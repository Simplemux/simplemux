/**************************************************************************
 * simplemux.c            version 1.6.2                                   *
 *                                                                        *
 * Simplemux compresses headers using ROHC (RFC 3095), and multiplexes    *
 * these header-compressed packets between a pair of machines (called     *
 * optimizers). The multiplexed bundle is sent in an IP/UDP packet.       *
 *                                                                        *
 * Simplemux can be seen as a naive implementation of TCM , a protocol    *
 * combining Tunneling, Compressing and Multiplexing for the optimization *
 * of small-packet flows. TCM may use of a number of different standard   *
 * algorithms for header compression, multiplexing and tunneling,         *
 * combined in a similar way to RFC 4170.                                 *
 *                                                                        *
 * In 2014 Jose Saldana wrote this program, published under GNU GENERAL   *
 * PUBLIC LICENSE, Version 3, 29 June 2007                                *
 * Copyright (C) 2007 Free Software Foundation, Inc.                      *
 *                                                                        *
 * Thanks to Davide Brini for his simpletun.c program. (2010)             *
 * http://backreference.org/wp-content/uploads/2010/03/simpletun.tar.bz2  *
 *                                                                        *
 * Simplemux uses an implementation of ROHC by Didier Barvaux             *
 * (https://rohc-lib.org/).                                               *
 *                                                                        *
 * Simplemux has been written for research purposes, so if you find it    *
 * useful, I would appreciate that you send a message sharing your        *
 * experiences, and your improvement suggestions.                         *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for research     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>			// for printing uint_64 numbers
#include <stdbool.h>			// for using the bool type
#include <rohc/rohc.h>			// for using header compression
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>



#define BUFSIZE 2000   			// buffer for reading from tun interface, must be >= MTU
#define MTU 1500				// it has to be equal or higher than the one in the network
#define PORT 55555				// default port
#define MAXPKTS 100				// maximum number of packets to store
#define MAXTHRESHOLD 1472		// default threshold of the maximum number of bytes to store. When it is reached, the sending is triggered. By default it is 1500 - 28 (IP/UDP tunneling header)
#define MAXTIMEOUT 100000000.0	// maximum value of the timeout (microseconds). (default 100 seconds)

#define SIZE_PROTOCOL_FIELD 1	// 1: protocol field of one byte
								// 2: protocol field of two bytes

#define PROTOCOL_FIRST 0		// 1: protocol field goes before the length byte(s) (as in draft-saldana-tsvwg-simplemux-01)
								// 0: protocol field goes after the length byte(s)  (as in draft-saldana-tsvwg-simplemux-02)

/* global variables */
int debug;						// 0:no debug; 1:minimum debug; 2:maximum debug 
char *progname;


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 * 			flags can be IFF_TUN (1) or IFF_TAP (2)                       *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

	struct ifreq ifr;
	int fd, err;
	char *clonedev = "/dev/net/tun";

	if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    	perror("Opening /dev/net/tun");
    	return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev) {
	 	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
	    perror("ioctl(TUNSETIFF)");
	    close(fd);
	    return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, unsigned char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, unsigned char *buf, int n){
  
  int nwritten;

  if((nwritten = write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwritten;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, unsigned char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(int level, char *msg, ...){
  
  va_list argp;
  
  if( debug >= level ) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <tunifacename> -e <ifacename> [-c <peerIP>] [-p <port>] [-d <debug_level>] [-r <ROHC_option>] [-n <num_mux_tun>] [-b <num_bytes_threshold>] [-t <timeout (microsec)>] [-P <period (microsec)>] [-l <log file name>] [-L]\n\n" , progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of tun interface to use (mandatory)\n");
  fprintf(stderr, "-e <ifacename>: Name of local interface which IP will be used for reception of muxed packets, i.e., the tunnel local end (mandatory)\n");
  fprintf(stderr, "-c <peerIP>: specify peer destination IP address, i.e. the tunnel remote end (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on, and to connect to (default 55555)\n");
  fprintf(stderr, "-d: outputs debug information while running. 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC)\n");
  fprintf(stderr, "-r: 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)\n");
  fprintf(stderr, "-n: number of packets received, to be sent to the network at the same time, default 1, max 100\n");
  fprintf(stderr, "-b: size threshold (bytes) to trigger the departure of packets, default 1472 (1500 - 28)\n");
  fprintf(stderr, "-t: timeout (in usec) to trigger the departure of packets\n");
  fprintf(stderr, "-P: period (in usec) to trigger the departure of packets. If ( timeout < period ) then the timeout has no effect\n");
  fprintf(stderr, "-l: log file name\n");
  fprintf(stderr, "-L: use default log file name (day and hour Y-m-d_H.M.S)\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * GetTimeStamp: Get a timestamp in microseconds from the OS              *
 **************************************************************************/
uint64_t GetTimeStamp() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec*(uint64_t)1000000+tv.tv_usec;
}

/**************************************************************************
 * ToByte: convert an array of booleans to a char                         *
 **************************************************************************/
// example:
/* char c;
// bits[0] is the less significant bit
bool bits[8]={false, true, false, true, false, true, false, false}; is character '*': 00101010
c = ToByte(bits);
do_debug(1, "%c\n",c );
// prints an asterisk*/
unsigned char ToByte(bool b[8]) 
{
	int i;
    unsigned char c = 0;
    for (i=0; i < 8; ++i)
        if (b[i])
            c |= 1 << i;
    return c;
}

/**************************************************************************
 * FromByte: return an array of booleans from a char                      *
 **************************************************************************/
// stores in 'b' the value 'true' or 'false' depending on each bite of the byte c
// b[0] is the less significant bit
// example: print the byte corresponding to an asterisk
/*bool bits2[8];
FromByte('*', bits2);
do_debug(1, "byte:%c%c%c%c%c%c%c%c\n", bits2[0], bits2[1], bits2[2], bits2[3], bits2[4], bits2[5], bits2[6], bits2[7]);
if (bits2[4]) {
	do_debug(1, "1\n");
} else {
	do_debug(1, "0\n");
}*/
void FromByte(unsigned char c, bool b[8])
{
	int i;
    for (i=0; i < 8; ++i)
        b[i] = (c & (1<<i)) != 0;
}


/**************************************************************************
 * PrintByte: prints the bits of a byte                                   *
 **************************************************************************/
void PrintByte(int debug_level, int num_bits, bool b[8])
{
	// num_bits is the number of bits to print
	// if 'num_bits' is smaller than 7, the function prints an 'x' instead of the value

	int i;
	for (i= 7 ; i>= num_bits ; i--) {
			do_debug(debug_level, "x");
	}
	for (i= num_bits -1 ; i>=0; i--) {
		if (b[i]) {
			do_debug(debug_level, "1");
		} else {
			do_debug(debug_level, "0");
		}
	}
}


/**************************************************************************
************ dump a packet ************************************************
**************************************************************************/
void dump_packet (int packet_size, unsigned char packet[MTU])
{
	int j;

	for(j = 0; j < packet_size; j++)
	{
		do_debug(2, "%02x ", packet[j]);
		if(j != 0 && ((j + 1) % 16) == 0)
		{
			do_debug(2, "\n");
			if ( j != (packet_size -1 )) do_debug(2,"   ");
		}
		// separate in groups of 8 bytes
		else if((j != 0 ) && ((j + 1) % 8 == 0 ) && (( j + 1 ) % 16 != 0))
		{
			do_debug(2, "  ");
		}
	}
	if(j != 0 && ((j ) % 16) != 0) /* be sure to go to the line */
	{
		do_debug(2, "\n");
	}
}


/**************************************************************************
 * return an string with the date and the time in format %Y-%m-%d_%H.%M.%S*
 **************************************************************************/
int date_and_time(char buffer[25])
{
	time_t timer;
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);
	strftime(buffer, 25, "%Y-%m-%d_%H.%M.%S", tm_info);
    return EXIT_SUCCESS;
}

/**************************************************************************
 *                   build the multiplexed packet                         *
 **************************************************************************/
// it takes all the variables where packets are stored, and builds a multiplexed packet
// the variables are:
//	- prot[MAXPKTS][SIZE_PROTOCOL_FIELD]	the protocol byte of each packet
//	- size_separators_to_mux[MAXPKTS]		the size of each separator (1 or 2 bytes). Protocol byte not included
//	- separators_to_mux[MAXPKTS][2]			the separators
//	- size_packets_to_mux[MAXPKTS]			the size of each packet to be multiplexed
//	- packets_to_mux[MAXPKTS][BUFSIZE]		the packet to be multiplexed

// the multiplexed packet is stored in mux_packet[BUFSIZE]
// the length of the multiplexed packet is returned by this function
uint16_t build_multiplexed_packet ( int num_packets, int single_prot, unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD], uint16_t size_separators_to_mux[MAXPKTS], unsigned char separators_to_mux[MAXPKTS][2], uint16_t size_packets_to_mux[MAXPKTS], unsigned char packets_to_mux[MAXPKTS][BUFSIZE], unsigned char mux_packet[BUFSIZE])
{
	int k, l;
	int length = 0;

	// for each packet, write the protocol field (if required), the separator and the packet itself
	for (k = 0; k < num_packets ; k++) {

		if ( PROTOCOL_FIRST ) {
			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
			}
	
			// add the separator
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}
		} else {
			// add the separator
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}
			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
			}
		}

		// add the bytes of the packet itself
		for (l = 0; l < size_packets_to_mux[k] ; l++) {
			mux_packet[length] = packets_to_mux[k][l];
			length ++;
		}
	}
	return length;
}


/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//	- prot[MAXPKTS][SIZE_PROTOCOL_FIELD]	the protocol byte of each packet
//	- size_separators_to_mux[MAXPKTS]		the size of each separator (1 or 2 bytes). Protocol byte not included
//	- separators_to_mux[MAXPKTS][2]			the separators
//	- size_packets_to_mux[MAXPKTS]			the size of each packet to be multiplexed
//	- packets_to_mux[MAXPKTS][BUFSIZE]		the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet ( int num_packets, int single_prot, unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD], uint16_t size_separators_to_mux[MAXPKTS], unsigned char separators_to_mux[MAXPKTS][2], uint16_t size_packets_to_mux[MAXPKTS], unsigned char packets_to_mux[MAXPKTS][BUFSIZE])
{
	int k, l;
	int length = 0;

	// for each packet, read the protocol field (if present), the separator and the packet itself
	for (k = 0; k < num_packets ; k++) {

		// count the 'Protocol' field if necessary
		if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					length ++;
				}
		}
	
		// count the separator
		for (l = 0; l < size_separators_to_mux[k] ; l++) {
			length ++;
		}

		// count the bytes of the packet itself
		for (l = 0; l < size_packets_to_mux[k] ; l++) {
			length ++;
		}
	}
	return length;
}


/************ Prototypes of functions used in the program ****************/

static int gen_random_num(const struct rohc_comp *const comp, void *const user_context);


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	// Only prints ROHC messages if debug level is > 2
	if ( debug > 2 ) {
        va_list args;
        va_start(args, format);
        vfprintf(stdout, format, args);
        va_end(args);
	}
}


/**************************************************************************
 ************************ main program ************************************
 **************************************************************************/
int main(int argc, char *argv[]) {

	// variables for managing the network interfaces
	int tun_fd;										// file descriptor of the tun interface
	int net_fd = 1;									// the file descriptor of the socket of the network interface
	int feedback_fd = 2;							// the file descriptor of the socket of the feedback received from the network interface
	int maxfd;										// maximum number of file descriptors
  	fd_set rd_set;									// rd_set is a set of file descriptors used to know which interface has received a packet
	char if_name[IFNAMSIZ] = "";					// name of the tun interface (e.g. "tun1")
	char interface[IFNAMSIZ]= "";					// name of the network interface (e.g. "eth0")
	struct sockaddr_in local, remote, feedback, feedback_remote;		// these are structs for storing sockets
	socklen_t slen = sizeof(remote);				// size of the socket. The type is like an int, but adequate for the size of the socket
	socklen_t slen_feedback = sizeof(feedback);		// size of the socket. The type is like an int, but adequate for the size of the socket
	char remote_ip[16] = "";            			// dotted quad IP string with the IP of the remote machine
	char local_ip[16] = "";                 		// dotted quad IP string with the IP of the local machine     
	unsigned short int port = PORT;					// UDP port to be used for sending the multiplexed packets
	unsigned short int port_feedback = PORT + 1;	// UDP port to be used for sending the ROHC feedback packets, when using ROHC bidirectional
	struct ifreq iface;								// network interface

	// variables for storing the packets to multiplex
	uint16_t total_length;									// total length of the built multiplexed packet
	unsigned char protocol_rec;								// protocol field of the received muxed packet
	unsigned char protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];	// protocol field of each packet
	uint16_t size_separators_to_multiplex[MAXPKTS];			// stores the size of the Simplemux separator. It does not include the "Protocol" field
	unsigned char separators_to_multiplex[MAXPKTS][2];		// stores the header ('protocol' not included) received from tun, before sending it to the network
	uint16_t size_packets_to_multiplex[MAXPKTS];			// stores the size of the received packet
	unsigned char packets_to_multiplex[MAXPKTS][BUFSIZE];	// stores the packets received from tun, before storing it or sending it to the network
	unsigned char muxed_packet[MTU];						// stores the multiplexed packet

	// variables for storing the packets to demultiplex
	uint16_t nread_from_net;								// number of bytes read from network which will be demultiplexed
	unsigned char buffer_from_net[BUFSIZE];					// stores the packet received from the network, before sending it to tun
	unsigned char demuxed_packet[MTU];						// stores each demultiplexed packet

	// variables for controlling the arrival and departure of packets
	unsigned long int tun2net = 0, net2tun = 0;		// number of packets read from tun and from net
	unsigned long int feedback_pkts = 0;			// number of ROHC feedback packets
	int limit_numpackets_tun = 0;					// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
	int size_threshold = MAXTHRESHOLD;				// if the number of bytes stored is higher than this, they are sent
	uint64_t timeout = MAXTIMEOUT;					// (microseconds) if a packet arrives and the timeout has expired (time from the  
													// previous sending), the sending is triggered. default 100 seconds
	uint64_t period= MAXTIMEOUT;					// period. If it expires, a packet is sent
	uint64_t microseconds_left = period;			// the time until the period expires	

	// very long unsigned integers for storing the system clock in microseconds
	uint64_t time_last_sent_in_microsec;			// moment when the last multiplexed packet was sent
	uint64_t time_in_microsec;						// current time
	uint64_t time_difference;						// difference between two timestamps

	int option;										// command line options
	int l,j,k;
	int num_pkts_stored_from_tun = 0;				// number of packets received and not sent from tun (stored)
	int size_muxed_packet = 0;						// acumulated size of the multiplexed packet
	int predicted_size_muxed_packet;				// size of the muxed packet if the arrived packet was added to it
	int position;									// for reading the arrived multiplexed packet
	int packet_length;								// the length of each packet inside the multiplexed bundle
	int network_mtu;								// the maximum transfer unit of the interface
	int num_demuxed_packets;						// a counter of the number of packets inside a muxed one
	int single_protocol;							// it is 1 when the Single-Protocol-Bit of the first header is 1
	int single_protocol_rec;						// it is the bit Single-Protocol-Bit received in a muxed packet
	int first_header_read;							// it is 0 when the first header has not been read
	int LXT_position;								// the position of the LXT bit. It may be 6 (non-first header) or 7 (first header)
	int maximum_packet_length;						// the maximum lentgh of a packet. It may be 64 (first header) or 128 (non-first header)
	int first_header_written = 0;					// it indicates if the first header has been written or not
    int ret;										// value returned by the "select" function

	struct timeval period_expires;					// it is used for the maximum time waiting for a new packet

	bool bits[8];									// it is used for printing the bits of a byte in debug mode

	// ROHC header compression variables
	int ROHC_mode = 0;								// it is 0 if ROHC is not used
													// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
													// it is 2 for ROHC Bidirectional Optimistic mode
													// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)

	struct rohc_comp *compressor;           		// the ROHC compressor
	unsigned char ip_buffer[BUFSIZE];				// the buffer that will contain the IPv4 packet to compress
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFSIZE);	
	unsigned char rohc_buffer[BUFSIZE];				// the buffer that will contain the resulting ROHC packet
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFSIZE);
	unsigned int seed;
	rohc_status_t status;

	struct rohc_decomp *decompressor;       		// the ROHC decompressor
	unsigned char ip_buffer_d[BUFSIZE];				// the buffer that will contain the resulting IP decompressed packet
	struct rohc_buf ip_packet_d = rohc_buf_init_empty(ip_buffer_d, BUFSIZE);
	unsigned char rohc_buffer_d[BUFSIZE];			// the buffer that will contain the ROHC packet to decompress
	struct rohc_buf rohc_packet_d = rohc_buf_init_empty(rohc_buffer_d, BUFSIZE);

    /* structures to handle ROHC feedback */
	unsigned char rcvd_feedback_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet received
    struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcvd_feedback_buffer_d, BUFSIZE);

	unsigned char feedback_send_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet to be sent
	struct rohc_buf feedback_send = rohc_buf_init_empty(feedback_send_buffer_d, BUFSIZE);


	/* variables for the log file */
	char log_file_name[100] = "";            		// name of the log file	
	FILE *log_file = NULL;							// file descriptor of the log file
	int file_logging = 0;							// it is set to 1 if logging into a file is enabled



	/************** Check command line options *********************/
	progname = argv[0];		// argument used when calling the program

	while((option = getopt(argc, argv, "i:e:c:p:n:b:t:P:l:d:r:hL")) > 0) {
	    switch(option) {
			case 'd':
				debug = atoi(optarg);		/* 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC) */
				break;
			case 'r':
				ROHC_mode = atoi(optarg);	/* 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)*/ 
				break;
			case 'h':						/* help */
				usage();
				break;
			case 'i':						/* put the name of the tun interface (e.g. "tun2") in "if_name" */
				strncpy(if_name, optarg, IFNAMSIZ-1);
				break;
			case 'e':						/* the name of the network interface (e.g. "eth0") in "interface" */
				strncpy(interface, optarg, IFNAMSIZ-1);
				break;
			case 'c':						/* destination address of the machine where the tunnel ends */
				strncpy(remote_ip, optarg, 15);
				break;
			case 'l':						/* name of the log file */
				strncpy(log_file_name, optarg, 100);
				file_logging = 1;
				break;
			case 'L':						/* name of the log file assigned automatically */
				date_and_time(log_file_name);
				file_logging = 1;
				break;
			case 'p':						/* port number */
				port = atoi(optarg);		/* atoi Parses a string interpreting its content as an int */
				port_feedback = port + 1;
				break;
			case 'n':						/* limit of the number of packets for triggering a muxed packet */
				limit_numpackets_tun = atoi(optarg);
				break;
			case 'b':						/* size threshold (in bytes) for triggering a muxed packet */
				size_threshold = atoi(optarg);
				break;
			case 't':						/* timeout for triggering a muxed packet */
				timeout = atof(optarg);
				break;
			case 'P':						/* Period for triggering a muxed packet */
				period = atof(optarg);
				break;
			default:
				my_err("Unknown option %c\n", option);
				usage();
    	}
	}	//end while option

	argv += optind;
	argc -= optind;

	if(argc > 0) {
		my_err("Too many options\n");
		usage();
	}

	/* check the rest of the options */
	if(*if_name == '\0') {
		my_err("Must specify tun interface name\n");
		usage();
	} else if(*remote_ip == '\0') {
		my_err("Must specify the address of the peer\n");
		usage();
	} else if(*interface == '\0') {
		my_err("Must specify local interface name\n");
		usage();
	}

	/* open the log file */
	if ( file_logging == 1 ) {
		log_file = fopen(log_file_name, "w");
		if (log_file == NULL) my_err("Error: cannot open the log file!\n");
	}


	// check debug option
	if ( debug < 0 ) debug = 0;
	else if ( debug > 3 ) debug = 3;
	do_debug ( 1 , "debug level set to %i\n", debug);


	// check ROHC option
	if ( ROHC_mode < 0 ) ROHC_mode = 0;
	else if ( ROHC_mode > 2 ) ROHC_mode = 2;
	switch(ROHC_mode) {
			case 0:
				do_debug ( 1 , "ROHC not activated\n", debug);
				break;
			case 1:
				do_debug ( 1 , "ROHC Unidirectional Mode\n", debug);
				break;
			case 2:
				do_debug ( 1 , "ROHC Bidirectional Optimistic Mode\n", debug);
				break;
			/*case 3:
				do_debug ( 1 , "ROHC Bidirectional Reliable Mode\n", debug);
				break;*/
	}

	/*** set the triggering parameters according to user selections (or default values) ***/
	
	// there are four possibilities for triggering the sending of the packets:
	// - a threshold of the acumulated packet size
	// - a number of packets
	// - a timeout. A packet arrives. If the timeout has been reached, a muxed packet is triggered
	// - a period. If the period has been reached, a muxed packet is triggered

	// if ( timeout < period ) then the timeout has no effect
	// as soon as one of the conditions is accomplished, all the accumulated packets are sent

	if (( (size_threshold < MAXTHRESHOLD) || (timeout < MAXTIMEOUT) || (period < MAXTIMEOUT) ) && (limit_numpackets_tun == 0)) limit_numpackets_tun = MAXPKTS;

	// if no option is set by the user, it is assumed that every packet will be sent immediately
	if (( (size_threshold == MAXTHRESHOLD) && (timeout == MAXTIMEOUT) && (period == MAXTIMEOUT)) && (limit_numpackets_tun == 0)) limit_numpackets_tun = 1;
	

	// I calculate 'now' as the moment of the last sending
	time_last_sent_in_microsec = GetTimeStamp() ; 

	do_debug(1, "threshold: %i. numpackets: %i.timeout: %.2lf\n", size_threshold, limit_numpackets_tun, timeout);


	/*** initialize tun interface ***/
	if ( (tun_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun interface %s\n", if_name);
		exit(1);
	}
	do_debug(1, "Successfully connected to interface %s\n", if_name);


	/*** Request a socket for multiplexed packets ***/
	// AF_INET (exactly the same as PF_INET)
	// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
	// net_fd is the file descriptor of the socket for managing arrived multiplexed packets	
  	if ( ( net_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
    	perror("socket()");
    	exit(1);
  	}

	/*** Request a socket for feedback packets ***/
	// AF_INET (exactly the same as PF_INET)
	// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
	// net_fd is the file descriptor of the socket for managing arrived feedback packets		
  	if ( ( feedback_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
    	perror("socket()");
    	exit(1);
  	}

    /*** assign the destination address for the multiplexed packets ***/
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);		// remote IP
    remote.sin_port = htons(port);						// remote port


    /*** assign the destination address for the feedback packets ***/
    memset(&feedback_remote, 0, sizeof(feedback_remote));
    feedback_remote.sin_family = AF_INET;
    feedback_remote.sin_addr.s_addr = inet_addr(remote_ip);	// remote feedback IP (the same IP as the remote one)
    feedback_remote.sin_port = htons(port_feedback);		// remote feedback port


	// Use ioctl() to look up interface index which we will use to
	// bind socket descriptor net_fd to specified interface with setsockopt() since
	// none of the other arguments of sendto() specify which interface to use.
	memset (&iface, 0, sizeof (iface));
	snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", interface);
	if (ioctl (net_fd, SIOCGIFINDEX, &iface) < 0) {
		perror ("ioctl() failed to find interface ");
		return (EXIT_FAILURE);
	}

	if (ioctl (feedback_fd, SIOCGIFINDEX, &iface) < 0) {
		perror ("ioctl() failed to find interface ");
		return (EXIT_FAILURE);
	}


	/*** get the IP address of the local interface ***/
	if (ioctl(net_fd, SIOCGIFADDR, &iface) < 0) {
		perror ("ioctl() failed to find the IP address for local interface ");
		return (EXIT_FAILURE);
	}


	/*** get the MTU of the local interface ***/
	if (ioctl(net_fd, SIOCGIFMTU, &iface) == -1) network_mtu = 0;
	else network_mtu = iface.ifr_mtu;
	do_debug(1, "MTU: %i\n", network_mtu);
	if (network_mtu > MTU) perror("predefined MTU is higher than the one in the network");


	// create the sockets for sending packets to the network
    // assign the local address. Source IPv4 address: it is the one of the interface
    strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
	do_debug(1, "Local IP %s\n", local_ip);

	// create the socket for sending multiplexed packets (with separator)
    memset(&local, 0, sizeof(local));

    local.sin_family = AF_INET;
    //local.sin_addr.s_addr = htonl(INADDR_ANY); // this would take any interface
   	local.sin_addr.s_addr = inet_addr(local_ip);		// local IP
    local.sin_port = htons(port);						// local port

 	if (bind(net_fd, (struct sockaddr *)&local, sizeof(local))==-1) perror("bind");

    do_debug(1, "Socket for multiplexing open: Remote IP  %s. Port %i\n", inet_ntoa(remote.sin_addr), port); 


	// create the socket for sending feedback packets
    memset(&feedback, 0, sizeof(feedback));

    feedback.sin_family = AF_INET;
   	feedback.sin_addr.s_addr = inet_addr(local_ip);		// local IP
    feedback.sin_port = htons(port_feedback);			// local port (feedback)

 	if (bind(feedback_fd, (struct sockaddr *)&feedback, sizeof(feedback))==-1) perror("bind");

    do_debug(1, "Socket for feedback open: Remote IP  %s. Port %i\n", inet_ntoa(feedback_remote.sin_addr), port_feedback); 

  

	// If ROHC has been selected, I have to initialize it
	if ( ROHC_mode > 0 ) {

		/* initialize the random generator */
		seed = time(NULL);
		srand(seed);

		/* Create a ROHC compressor with Large CIDs and the largest MAX_CID
		 * possible for large CIDs */
		compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, gen_random_num, NULL);
		if(compressor == NULL)
		{
			fprintf(stderr, "failed create the ROHC compressor\n");
			goto error;
		}

		do_debug(1, "ROHC compressor created\n");

		// set the function that will manage the ROHC compressing traces (it will be 'print_rohc_traces')
        if(!rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL))
        {
                fprintf(stderr, "failed to set the callback for traces on compressor\n");
                goto release_compressor;
        }

		/* Enable the ROHC compression profiles */
		if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED))
		{
			fprintf(stderr, "failed to enable the Uncompressed profile\n");
			goto release_compressor;
		}
		if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP))
		{
			fprintf(stderr, "failed to enable the IP-only profile\n");
			goto release_compressor;
		}
		if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP, ROHC_PROFILE_UDPLITE, -1))
		{
			fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite profiles\n");
			goto release_compressor;
		}
		if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP))
		{
			fprintf(stderr, "failed to enable the RTP profile\n");
			goto release_compressor;
		}
		if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP))
		{
			fprintf(stderr, "failed to enable the ESP profile\n");
			goto release_compressor;
		}
		if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP))
		{
			fprintf(stderr, "failed to enable the TCP profile\n");
			goto release_compressor;
		}
		do_debug(1, "several ROHC compression profiles enabled\n");


        /* Create a ROHC decompressor to operate:
         *  - with large CIDs use ROHC_LARGE_CID, ROHC_LARGE_CID_MAX
         *  - with small CIDs use ROHC_SMALL_CID, ROHC_SMALL_CID_MAX maximum of 5 streams (MAX_CID = 4),
         *  - ROHC_O_MODE: Bidirectional Optimistic mode (O-mode)
		 *  - ROHC_U_MODE: Unidirectional mode (U-mode).    */
		if ( ROHC_mode == 1 ) {
        	decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);	// Unidirectional mode
		} else if ( ROHC_mode == 2 ) {
        	decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);	// Bidirectional Optimistic mode
		} /*else if ( ROHC_mode == 3 ) {
        	decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);	// Bidirectional Reliable mode (not implemented yet)
		} */

        if(decompressor == NULL)
        {
                fprintf(stderr, "failed create the ROHC decompressor\n");
                goto release_decompressor;
        }

		do_debug(1, "ROHC decompressor created\n");

		// set the function that will manage the ROHC decompressing traces (it will be 'print_rohc_traces')
		if(!rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL))
        {
                fprintf(stderr, "failed to set the callback for traces on decompressor\n");
                goto release_decompressor;
        }

		// enable rohc decompression profiles
		status = rohc_decomp_enable_profiles(decompressor,
                                     ROHC_PROFILE_UNCOMPRESSED,
                                     ROHC_PROFILE_UDP,
                                     ROHC_PROFILE_IP,
                                     ROHC_PROFILE_UDPLITE,
                                     ROHC_PROFILE_RTP,
                                     ROHC_PROFILE_ESP,
                                     ROHC_PROFILE_TCP, -1);
		if(!status)
		{
    		fprintf(stderr, "failed to enable the decompression profiles\n");
            goto release_decompressor;
		}
		do_debug(1, "several ROHC decompression profiles enabled\n");
	}


  	/*** I need the value of the maximum file descriptor, in order to let select() handle three interface descriptors at once ***/
    if(tun_fd >= net_fd && tun_fd >= feedback_fd)		maxfd = tun_fd;
    if(net_fd >= tun_fd && net_fd >= feedback_fd)		maxfd = net_fd;
    if(feedback_fd >= tun_fd && feedback_fd >= net_fd)	maxfd = feedback_fd;

	do_debug(1, "tun_fd: %i; net_fd: %i; feedback_fd: %i; maxfd: %i\n",tun_fd, net_fd, feedback_fd, maxfd);


	/*****************************************/
	/************** Main loop ****************/
	/*****************************************/
  	while(1) {

   		FD_ZERO(&rd_set);				/* FD_ZERO() clears a set */
   		FD_SET(tun_fd, &rd_set);		/* FD_SET() adds a given file descriptor to a set */
		FD_SET(net_fd, &rd_set);
		FD_SET(feedback_fd, &rd_set);

		/* Initialize the timeout data structure. */
		time_in_microsec = GetTimeStamp();
		if ( period > (time_in_microsec - time_last_sent_in_microsec)) {
			microseconds_left = (period - (time_in_microsec - time_last_sent_in_microsec));			
		} else {
			microseconds_left = 0;
		}
		// do_debug (1, "microseconds_left: %i\n", microseconds_left);

		period_expires.tv_sec = 0;
		period_expires.tv_usec = microseconds_left;		// this is the moment when the period will expire


    	/* select () allows a program to monitor multiple file descriptors, */ 
		/* waiting until one or more of the file descriptors become "ready" */
		/* for some class of I/O operation*/
		ret = select(maxfd + 1, &rd_set, NULL, NULL, &period_expires); 	//this line stops the program until something
																		//happens or the period expires
		// if the program gets here, it means that a packet has arrived (from tun or from the network), or the period has expired
    	if (ret < 0 && errno == EINTR) continue;

    	if (ret < 0) {
      		perror("select()");
      		exit(1);
    	}



		/*****************************************************************************/
		/***************** NET to tun. demux and decompress **************************/
		/*****************************************************************************/

    	/*** data arrived at the network interface: read, demux, decompress and forward it ***/
    	if(FD_ISSET(net_fd, &rd_set)) {		/* FD_ISSET tests to see if a file descriptor is part of the set */

	  		// a packet has been received from the network, destinated to the multiplexing port. 'slen' is the length of the IP address
			nread_from_net = recvfrom ( net_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&remote, &slen );
			if (nread_from_net==-1) perror ("recvfrom()");

			// now buffer_from_net contains a full packet or frame.
			// check if the packet comes from the multiplexing port (default 55555). (Its destination IS the multiplexing port)

			if (port == ntohs(remote.sin_port)) {
	  		/* increase the counter of the number of packets read from the network */
      			net2tun++;
	  			do_debug(1, "NET2TUN %lu: Read muxed packet (%i bytes) from %s:%d\n", net2tun, nread_from_net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));				

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
				}

				// if the packet comes from the multiplexing port, I have to demux it and write each packet to the tun interface
				position = 0; //this is the index for reading the packet/frame
				num_demuxed_packets = 0;

				first_header_read = 0;

				while (position < nread_from_net) {

					if ( PROTOCOL_FIRST ) {
						/* read the separator */
						// - read 'protocol', the SPB and LXT bits

						// check if this is the first separator or not
						if (first_header_read == 0) {		// this is the first separator

							// the first thing I expect is a 'protocol' field
							if ( SIZE_PROTOCOL_FIELD == 1 ) {
								protocol_rec = buffer_from_net[position];
								position ++;
							} else {	// SIZE_PROTOCOL_FIELD == 2
								protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
								position = position + 2;
							}

							// after the first byte I will find a Mux separator, so I check the next byte
							// Since this is a first header:
							//	- SPB will be stored in 'bits[7]'
							//	- LXT will be stored in 'bits[6]'
							FromByte(buffer_from_net[position], bits);

							// check the Single Protocol Bit (SPB, one bit), which only appears in the first
	   						// Simplemux header.  It would is set to 0 if all the multiplexed
							// packets belong to the same protocol (in this case, the "protocol"
							// field will only appear in the first Simplemux header).  It is set to
							// 1 when each packet MAY belong to a different protocol.
							if (bits[7]) {
								single_protocol_rec = 1;
							} else {
								single_protocol_rec = 0;
							}

							// as this is a first header, the length extension bit is the second one, and the maximum
							// length of a packet is 64 bytes
							LXT_position = 6;
							maximum_packet_length = 64;			

							// if I am here, it means that I have read the first separator
							first_header_read = 1;
									
						} else {
							// Non-first header

							if (single_protocol_rec == 1) {
								// all the packets belong to the same protocol, so the first byte belongs to the Mux separator, so I check it
								FromByte(buffer_from_net[position], bits);
							} else {
								// each packet belongs to a different protocol, so the first thing I find is the 'Protocol' field
								// and the second one belongs to the Mux separator, so I check it
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									protocol_rec = buffer_from_net[position];
									position ++;
								} else {	// SIZE_PROTOCOL_FIELD == 2
									protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
									position = position + 2;
								}

								// get the value of the bits of the first byte
								// as this is a non-first header:
								//	- LXT will be stored in 'bits[7]'
								FromByte(buffer_from_net[position], bits);
							}

							// as this is a non-first header, the length extension bit is the first one (7), and the maximum
							// length of a packet is 128 bytes
							LXT_position = 7;
							maximum_packet_length = 128;
						}

						// I have demuxed another packet
						num_demuxed_packets ++;
						//do_debug(2, "\n");

						do_debug(1, " NET2TUN: packet #%i demuxed", num_demuxed_packets);
						if ((debug == 1) && (ROHC_mode == 0) ) do_debug (1,"\n");
						do_debug(2, ": ");

						// read the length
						// Check the LXT (length extension) bit.
						// if this is a first header, the length extension bit is the second one (6), and the maximum
						// length of a packet is 64 bytes

						if (bits[LXT_position]== false) {
							// if the LXT bit is 0, it means that the separator is one-byte
							// I have to convert the six less significant bits to an integer, which means the length of the packet
							// since the two most significant bits are 0, the length is the value of the char
							packet_length = buffer_from_net[position] % maximum_packet_length;
							do_debug(2, " Mux separator:(%02x) ", buffer_from_net[position]);
							PrintByte(2, 8, bits);

							position ++;

						} else {
							// if the second bit is 1, it means that the separator is two bytes
							// I get the six less significant bits by using modulo maximum_packet_length
							// I do de product by 256 and add the resulting number to the second byte
							packet_length = ((buffer_from_net[position] % maximum_packet_length) * 256 ) + buffer_from_net[position+1];

							if (debug ) {
								do_debug(2, " Mux separator:(%02x) ", buffer_from_net[position]);
								PrintByte(2, 8, bits);
								FromByte(buffer_from_net[position+1], bits);
								do_debug(2, " (%02x) ",buffer_from_net[position+1]);
								PrintByte(2, 8, bits);	
							}					
							position = position + 2;
						}
						do_debug(2, " (%i bytes)\n", packet_length);


					} else { 	// 'Protocol' field goes after the separator

						// read the SPB and LXT bits and 'protocol', 

						// check if this is the first separator or not
						if (first_header_read == 0) {

							// in the first byte I will find a Mux separator, so I check it
							// Since this is a first header:
							//	- SPB will be stored in 'bits[7]'
							//	- LXT will be stored in 'bits[6]'
							FromByte(buffer_from_net[position], bits);

							// check the Single Protocol Bit (SPB, one bit), which only appears in the first
	   						// Simplemux header.  It would is set to 0 if all the multiplexed
							// packets belong to the same protocol (in this case, the "protocol"
							// field will only appear in the first Simplemux header).  It is set to
							// 1 when each packet MAY belong to a different protocol.
							if (bits[7]) {
								single_protocol_rec = 1;
							} else {
								single_protocol_rec = 0;
							}

							// as this is a first header, the length extension bit is the second one (6), and the maximum
							// length of a packet is 64 bytes
							LXT_position = 6;
							maximum_packet_length = 64;			

						} else {	// Non-first header

							// get the value of the bits of the first byte
							// as this is a non-first header:
							//	- LXT will be stored in 'bits[7]'
							FromByte(buffer_from_net[position], bits);
							
							// as this is a non-first header, the length extension bit is the first one (7), and the maximum
							// length of a packet is 128 bytes
							LXT_position = 7;
							maximum_packet_length = 128;
						}

						// I have demuxed another packet
						num_demuxed_packets ++;
						//do_debug(2, "\n");

						do_debug(1, " NET2TUN: packet #%i demuxed", num_demuxed_packets);
						if ((debug == 1) && (ROHC_mode == 0) ) do_debug (1,"\n");
						do_debug(2, ": ");

						// read the length
						// Check the LXT (length extension) bit.
						if (bits[LXT_position]== false) {
							// if the LXT bit is 0, it means that the separator is one-byte
							// I have to convert the six less significant bits to an integer, which means the length of the packet
							// since the two most significant bits are 0, the length is the value of the char
							packet_length = buffer_from_net[position] % maximum_packet_length;
							do_debug(2, " Mux separator:(%02x) ", buffer_from_net[position]);
							PrintByte(2, 8, bits);

							position ++;

						} else {
							// if the second bit is 1, it means that the separator is two bytes
							// I get the six less significant bits by using modulo maximum_packet_length
							// I do de product by 256 and add the resulting number to the second byte
							packet_length = ((buffer_from_net[position] % maximum_packet_length) * 256 ) + buffer_from_net[position+1];

							if (debug ) {
								do_debug(2, " Mux separator:(%02x) ", buffer_from_net[position]);
								PrintByte(2, 8, bits);
								FromByte(buffer_from_net[position+1], bits);
								do_debug(2, " (%02x) ",buffer_from_net[position+1]);
								PrintByte(2, 8, bits);	
							}					
							position = position + 2;
						}
						do_debug(2, " (%i bytes)\n", packet_length);

						// check if this is the first separator or not
						if (first_header_read == 0) {		// this is the first separator. The protocol field will always be present
							// the next thing I expect is a 'protocol' field
							if ( SIZE_PROTOCOL_FIELD == 1 ) {
								protocol_rec = buffer_from_net[position];
								position ++;
							} else {	// SIZE_PROTOCOL_FIELD == 2
								protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
								position = position + 2;
							}

							// if I am here, it means that I have read the first separator
							first_header_read = 1;

						} else {			// non-first separator. The protocol field may or may not be present
							if ( single_protocol_rec == 0 ) {
								// each packet belongs to a different protocol, so the first thing is the 'Protocol' field
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									protocol_rec = buffer_from_net[position];
									position ++;
								} else {	// SIZE_PROTOCOL_FIELD == 2
									protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
									position = position + 2;
								}
							}
						}
					}

					// copy the packet to a new string
					for (l = 0; l < packet_length ; l++) {
						demuxed_packet[l] = buffer_from_net[l + position ];
					}
					position = position + packet_length;

					// Check if the position has gone beyond the size of the packet (wrong packet)
					if (position > nread_from_net) {
						// The last length read from the separator goes beyond the end of the packet
						do_debug (1, "  The length of the packet does not fit. Packet discarded\n");

						// write the log file
						if ( log_file != NULL ) {
							fprintf (log_file, "%"PRIu64"\terror\tdemux_bad_length\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun );	// the packet is bad so I add a line
							fflush(log_file);
						}
						
					} else {

						/************ decompress the packet ***************/

						// if the number of the protocol is NOT 142 (which means ROHC) I do not decompress the packet
						if ( protocol_rec != 142 ) {
							// non-compressed packet
							// dump the received packet on terminal
							if (debug) {
								do_debug(2, " ");
								do_debug(1, " Received ");
								do_debug(2, "packet\n   ");
								dump_packet ( packet_length, demuxed_packet );
							}

						} else {
							// ROHC-compressed packet

							// reset the buffers where the rohc packets, ip packets and feedback info are to be stored
							rohc_buf_reset (&ip_packet_d);
							rohc_buf_reset (&rohc_packet_d);
							rohc_buf_reset (&rcvd_feedback);
							rohc_buf_reset (&feedback_send);

							// Copy the compressed length and the compressed packet
							rohc_packet_d.len = packet_length;
						
							// Copy the packet itself
							for (l = 0; l < packet_length ; l++) {
								rohc_buf_byte_at(rohc_packet_d, l) = demuxed_packet[l];
							}

							// dump the ROHC packet on terminal
							if (debug) {
								do_debug(2, " ");
								do_debug(1, " ROHC ");
								do_debug(2, "packet\n   ");
								dump_packet (packet_length, demuxed_packet);
							}


							// decompress the packet
							status = rohc_decompress3 (decompressor, rohc_packet_d, &ip_packet_d, &rcvd_feedback, &feedback_send);

							// if bidirectional mode has been set, check the feedback
							if ( ROHC_mode > 1 ) {

								// check if the decompressor has received feedback, and it has to be delivered to the local compressor
								if ( !rohc_buf_is_empty( rcvd_feedback) ) { 
									do_debug(3, "Feedback received from the remote compressor by the decompressor (%i bytes), to be delivered to the local compressor\n", rcvd_feedback.len);
									// dump the feedback packet on terminal
									if (debug) {
										do_debug(2, "  ROHC feedback packet received\n   ");

										dump_packet (rcvd_feedback.len, rcvd_feedback.data );
									}


									// deliver the feedback received to the local compressor
									//https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
									if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
										do_debug(3, "Error delivering feedback received from the remote compressor to the compressor\n");
									} else {
										do_debug(3, "Feedback from the remote compressor delivered to the compressor (%i bytes)\n", rcvd_feedback.len);
									}
								} else {
									do_debug(3, "No feedback received by the decompressor from the remote compressor\n");
								}

								// check if the decompressor has generated feedback to be sent by the feedback channel to the other peer
								if ( !rohc_buf_is_empty( feedback_send ) ) { 
									do_debug(3, "Generated feedback (%i bytes) to be sent by the feedback channel to the peer\n", feedback_send.len);

									// dump the ROHC packet on terminal
									if (debug) {
										do_debug(2, "  ROHC feedback packet generated\n   ");
										dump_packet (feedback_send.len, feedback_send.data );
									}


									// send the feedback packet to the peer
									if (sendto(feedback_fd, feedback_send.data, feedback_send.len, 0, (struct sockaddr *)&feedback_remote, sizeof(feedback_remote))==-1) {
										perror("sendto()");
									} else {
										do_debug(3, "Feedback generated by the decompressor (%i bytes), sent to the compressor\n", feedback_send.len);
									}
								} else {
									do_debug(3, "No feedback generated by the decompressor\n");
								}
							}


							// check the result of the decompression

							// decompression is successful
							if ( status == ROHC_STATUS_OK) {

								if(!rohc_buf_is_empty(ip_packet_d))	{	// decompressed packet is not empty
								
									// ip_packet.len bytes of decompressed IP data available in ip_packet
									packet_length = ip_packet_d.len;

									// copy the packet
									memcpy(demuxed_packet, rohc_buf_data_at(ip_packet_d, 0), packet_length);

									//dump the IP packet on the standard output
									do_debug(2, "  ");
									do_debug(1, "IP packet resulting from the ROHC decompression (%i bytes) written to tun\n", packet_length);
									do_debug(2, "   ");

									if (debug) {
										// dump the decompressed IP packet on terminal
										dump_packet (ip_packet_d.len, ip_packet_d.data );
									}

								} else {
									/* no IP packet was decompressed because of ROHC segmentation or
									 * feedback-only packet:
									 *  - the ROHC packet was a non-final segment, so at least another
									 *    ROHC segment is required to be able to decompress the full
									 *    ROHC packet
									 *  - the ROHC packet was a feedback-only packet, it contained only
									 *    feedback information, so there was nothing to decompress */
									do_debug(1, "  no IP packet decompressed\n");

									// write the log file
									if ( log_file != NULL ) {
										fprintf (log_file, "%"PRIu64"\trec\tROHC_feedback\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));	// the packet is bad so I add a line
										fflush(log_file);
									}
								}
							}

							else if ( status == ROHC_STATUS_NO_CONTEXT ) {

								// failure: decompressor failed to decompress the ROHC packet 
								do_debug(2, "  decompression of ROHC packet failed. No context\n");
								fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

								// write the log file
								if ( log_file != NULL ) {
									// the packet is bad
									fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
									fflush(log_file);
								}
							}

							else if ( status == ROHC_STATUS_OUTPUT_TOO_SMALL ) {	// the output buffer is too small for the compressed packet

								// failure: decompressor failed to decompress the ROHC packet 
								do_debug(2, "  decompression of ROHC packet failed. Output buffer is too small\n");
								fprintf(stderr, "  decompression of ROHC packet failed. Output buffer is too small\n");

								// write the log file
								if ( log_file != NULL ) {
									// the packet is bad
									fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Output buffer is too small\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
									fflush(log_file);
								}
							}

							else if ( status == ROHC_STATUS_MALFORMED ) {			// the decompression failed because the ROHC packet is malformed 

								// failure: decompressor failed to decompress the ROHC packet 
								do_debug(2, "  decompression of ROHC packet failed. No context\n");
								fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

								// write the log file
								if ( log_file != NULL ) {
									// the packet is bad
									fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. No context\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
									fflush(log_file);
								}
							}

							else if ( status == ROHC_STATUS_BAD_CRC ) {			// the CRC detected a transmission or decompression problem

								// failure: decompressor failed to decompress the ROHC packet 
								do_debug(2, "  decompression of ROHC packet failed. Bad CRC\n");
								fprintf(stderr, "  decompression of ROHC packet failed. Bad CRC\n");

								// write the log file
								if ( log_file != NULL ) {
									// the packet is bad
									fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Bad CRC\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
									fflush(log_file);
								}
							}

							else if ( status == ROHC_STATUS_ERROR ) {				// another problem occurred

								// failure: decompressor failed to decompress the ROHC packet 
								do_debug(2, "  decompression of ROHC packet failed. Other error\n");
								fprintf(stderr, "  decompression of ROHC packet failed. Other error\n");

								// write the log file
								if ( log_file != NULL ) {
									// the packet is bad
									fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Other error\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
									fflush(log_file);
								}
							}

						} /*********** end decompression **************/

						// write the demuxed (and perhaps decompressed) packet to the tun interface
						// if compression is used, check that ROHC has decompressed correctly
						if ( ( protocol_rec != 142 ) || ((protocol_rec == 142) && ( status == ROHC_STATUS_OK))) {

							// print the debug information
							do_debug(2, "  Protocol: %i ",protocol_rec);

							switch(protocol_rec) {
								case 4:
									do_debug (2, "(IP)");
									break;
								case 142:
									do_debug (2, "(ROHC)");
									break;
							}
							do_debug(2, "\n\n");
							//do_debug(2, "packet length (without separator): %i\n", packet_length);

							// write the demuxed packet to the network
							cwrite ( tun_fd, demuxed_packet, packet_length );

							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tsent\tdemuxed\t%i\t%lu\n", GetTimeStamp(), packet_length, net2tun);	// the packet is good
								fflush(log_file);
							}
						}
					}
				}
			}

			else {
				// packet with destination port 55555, but a source port different from the multiplexing one
				// if the packet does not come from the multiplexing port, write it directly into the tun interface
				cwrite ( tun_fd, buffer_from_net, nread_from_net);
				do_debug(1, "NET2TUN %lu: Non-multiplexed packet. Written %i bytes to tun\n", net2tun, nread_from_net);

				// write the log file
				if ( log_file != NULL ) {
					// the packet is good
					fprintf (log_file, "%"PRIu64"\tforward\tnative\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
					fflush(log_file);
				}
			}
  		}



		/****************************************************************************************************************************/		
		/******* NET to tun. ROHC feedback packet from the remote decompressor to be delivered to the local compressor **************/
		/****************************************************************************************************************************/

    	/*** ROHC feedback data arrived at the network interface: read it in order to deliver it to the local compressor ***/

		// the ROHC mode only affects the decompressor. So if I receive a ROHC feedback packet, I will use it
		// this implies that if the origin is in ROHC Unidirectional mode and the destination in Bidirectional, feedback will still work

    	else if ( FD_ISSET ( feedback_fd, &rd_set )) {		/* FD_ISSET tests to see if a file descriptor is part of the set */

	  		// a packet has been received from the network, destinated to the feedbadk port. 'slen_feedback' is the length of the IP address
			nread_from_net = recvfrom ( feedback_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&feedback_remote, &slen_feedback );

			if (nread_from_net == -1) perror ("recvfrom()");

			// now buffer_from_net contains a full packet or frame.
			// check if the packet comes (source port) from the feedback port (default 55556).  (Its destination port IS the feedback port)

			if (port_feedback == ntohs(feedback_remote.sin_port)) {

				// the packet comes from the feedback port (default 55556)
	  			do_debug(1, "\nFEEDBACK %lu: Read ROHC feedback packet (%i bytes) from %s:%d\n", feedback_pkts, nread_from_net, inet_ntoa(feedback.sin_addr), ntohs(feedback.sin_port));

				feedback_pkts ++;

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\trec\tROHC feedback\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, feedback_pkts, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
				}


				// reset the buffers where the packets are to be stored
//rohc_buf_reset (&ip_packet_d);
					rohc_buf_reset (&rohc_packet_d);
//rohc_buf_reset (&rcvd_feedback);
//rohc_buf_reset (&feedback_send);

				// Copy the compressed length and the compressed packet
				rohc_packet_d.len = nread_from_net;
		
				// Copy the packet itself
				for (l = 0; l < nread_from_net ; l++) {
					rohc_buf_byte_at(rohc_packet_d, l) = buffer_from_net[l];
				}

				// dump the ROHC packet on terminal
				if (debug) {

					do_debug(2, " ROHC feedback packet received\n   ");
					dump_packet ( rohc_packet_d.len, rohc_packet_d.data );
				}


				// deliver the feedback received to the local compressor
				//https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html

				if ( rohc_comp_deliver_feedback2 ( compressor, rohc_packet_d ) == false ) {
					do_debug(3, "Error delivering feedback to the compressor");
				} else {
					do_debug(3, "Feedback delivered to the compressor (%i bytes)\n", rohc_packet_d.len);
				}

				// the information received does not have to be decompressed, because it has been generated as feedback on the other side

				// so I have commented the next lines:

/*				// decompress the packet
				status = rohc_decompress3 (decompressor, rohc_packet_d, &ip_packet_d, &rcvd_feedback, &feedback_send);

				// check if the feedback is ok, and it has to be delivered to the local compressor
				if (status == ROHC_FEEDBACK_ONLY) {
					if ( !rohc_buf_is_empty( rcvd_feedback) ) { 
						do_debug(3, "Feedback received by the decompressor (%i bytes), to be delivered to the local compressor\n",rcvd_feedback.len);

						// deliver the feedback received to the local compressor
						//https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
						//if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
						//if ( rohc_comp_deliver_feedback2 ( compressor, ip_packet_d ) == false ) {
						if ( rohc_comp_deliver_feedback2 ( compressor, rohc_packet_d ) == false ) {
							do_debug(3, "Error delivering feedback to the compressor");
						} else {
							do_debug(3, "Feedback delivered to the compressor (%i bytes)\n",rcvd_feedback.len);
						}

					} else {
						do_debug(3, "No feedback received by the decompressor\n");
					}
				}*/
			}

			else {

				// packet with destination port 55556, but a source port different from the feedback one
				// if the packet does not come from the feedback port, write it directly into the tun interface
				cwrite ( tun_fd, buffer_from_net, nread_from_net);
				do_debug(1, "NET2TUN %lu: Non-feedback packet. Written %i bytes to tun\n", net2tun, nread_from_net);

				// write the log file
				if ( log_file != NULL ) {
					// the packet is good
					fprintf (log_file, "%"PRIu64"\tforward\tnative\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
					fflush(log_file);
				}
			}
 		}



		/**************************************************************************************/	
		/***************** TUN to NET: compress and multiplex *********************************/
		/**************************************************************************************/
	
    	/*** data arrived at tun: read it, and check if the stored packets should be written to the network ***/

    	else if(FD_ISSET(tun_fd, &rd_set)) {		/* FD_ISSET tests if a file descriptor is part of the set */

	  		/* read the packet from tun, store it in the array, and store its size */
      		size_packets_to_multiplex[num_pkts_stored_from_tun] = cread (tun_fd, packets_to_multiplex[num_pkts_stored_from_tun], BUFSIZE);
		
	  		/* increase the counter of the number of packets read from tun*/
      		tun2net++;

			if (debug > 1 ) do_debug (2,"\n");
      		do_debug(1, "TUN2NET %lu: Read packet from tun (%i bytes). ", tun2net, size_packets_to_multiplex[num_pkts_stored_from_tun]);

			// write the log file
			if ( log_file != NULL ) {
				fprintf (log_file, "%"PRIu64"\trec\tnative\t%i\t%lu\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
				fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
			}

			// print the native packet received
			if (debug) {
				do_debug(2, "\n   ");
				// dump the newly-created IP packet on terminal
				dump_packet ( size_packets_to_multiplex[num_pkts_stored_from_tun], packets_to_multiplex[num_pkts_stored_from_tun] );
			}


			/******************** compress the headers if the option has been set ****************/
			if ( ROHC_mode > 0 ) {
				// header compression has been selected by the user

				// copy the length read from tun to the buffer where the packet to be compressed is stored
				ip_packet.len = size_packets_to_multiplex[num_pkts_stored_from_tun];

				// copy the packet
				memcpy(rohc_buf_data_at(ip_packet, 0), packets_to_multiplex[num_pkts_stored_from_tun], size_packets_to_multiplex[num_pkts_stored_from_tun]);

				// reset the buffer where the rohc packet is to be stored
				rohc_buf_reset (&rohc_packet);

				// compress the IP packet
				status = rohc_compress4(compressor, ip_packet, &rohc_packet);

				// check the result of the compression
				if(status == ROHC_STATUS_SEGMENT) {
					/* success: compression succeeded, but resulting ROHC packet was too
					 * large for the Maximum Reconstructed Reception Unit (MRRU) configured
					 * with \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
					 * first ROHC segment and \ref rohc_comp_get_segment can be used to
					 * retrieve the next ones. */
				}

				else if (status == ROHC_STATUS_OK) {
					/* success: compression succeeded, and resulting ROHC packet fits the
					* Maximum Reconstructed Reception Unit (MRRU) configured with
					* \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
					* rohc_packet_len bytes of the ROHC packet */

					// since this packet has been compressed with ROHC, its protocol number must be 142
					// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol[num_pkts_stored_from_tun][0] = 142;
					} else {	// SIZE_PROTOCOL_FIELD == 2 
						protocol[num_pkts_stored_from_tun][0] = 0;
						protocol[num_pkts_stored_from_tun][1] = 142;
					}

					// Copy the compressed length and the compressed packet over the packet read from tun
					size_packets_to_multiplex[num_pkts_stored_from_tun] = rohc_packet.len;
					for (l = 0; l < size_packets_to_multiplex[num_pkts_stored_from_tun] ; l++) {
						packets_to_multiplex[num_pkts_stored_from_tun][l] = rohc_buf_byte_at(rohc_packet, l);
					}

					/* dump the ROHC packet on terminal */
					if (debug) {
						do_debug(2, "  ROHC packet resulting from the ROHC compression (%i bytes):\n   ", rohc_packet.len);
						dump_packet ( rohc_packet.len, rohc_packet.data );
					}

				} else {
					/* compressor failed to compress the IP packet */
					/* Send it in its native form */

					// I don't have to copy the native length and the native packet, because they
					// have already been stored in 'size_packets_to_multiplex[num_pkts_stored_from_tun]' and 'packets_to_multiplex[num_pkts_stored_from_tun]'

					// since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP'
					// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
					if ( SIZE_PROTOCOL_FIELD == 1 ) {
						protocol[num_pkts_stored_from_tun][0] = 4;
					} else {	// SIZE_PROTOCOL_FIELD == 2 
						protocol[num_pkts_stored_from_tun][0] = 0;
						protocol[num_pkts_stored_from_tun][1] = 4;
					}
					fprintf(stderr, "compression of IP packet failed\n");

					// print in the log file
					if ( log_file != NULL ) {
						fprintf (log_file, "%"PRIu64"\terror\tcompr_failed. Native packet sent\t%i\t%lu\\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
						fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
					}

					do_debug(2, "  ROHC did not work. Native packet sent (%i bytes):\n   ", size_packets_to_multiplex[num_pkts_stored_from_tun]);
					//goto release_compressor;
				}

			} else {
				// header compression has not been selected by the user

				// since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP' 
				// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
				if ( SIZE_PROTOCOL_FIELD == 1 ) {
					protocol[num_pkts_stored_from_tun][0] = 4;
				} else {	// SIZE_PROTOCOL_FIELD == 2 
					protocol[num_pkts_stored_from_tun][0] = 0;
					protocol[num_pkts_stored_from_tun][1] = 4;
				}
			}



			/*** Calculate if the MTU will be reached when multiplexing the present packet ***/
			// if the addition of the present packet will imply a multiplexed packet bigger than MTU:
			// - I send the previously stored packets
			// - I store the present one

			// calculate the size without the present packet
			predicted_size_muxed_packet = predict_size_multiplexed_packet (num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex);

			// I add the length of the present packet:

			// separator and length of the present packet
			if (first_header_written == 0) {
				// this is the first header, so the maximum length is 64
				if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 64 ) {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				} else {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				}
			} else {
				// this is not the first header, so the maximum length is 128
				if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 128 ) {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				} else {
					predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
				}
			}

			// calculate if all the packets belong to the same protocol
			single_protocol = 1;
			for (k = 1; k < num_pkts_stored_from_tun ; k++) {
				for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
					if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
				}
			}

			// add the length of the 'protocol' fields of the present packet
			// if pkts belonging to different protocols are multiplexed, I have to add n-1 bytes, each one 
			//corresponding to the "Protocol" field of a muliplexed packet
			if (single_protocol == 0 ) predicted_size_muxed_packet = predicted_size_muxed_packet + num_pkts_stored_from_tun;	


			if (predicted_size_muxed_packet > MTU ) {
				// if the present packet is muxed, the MTU will be overriden. So I first empty the buffer
				//i.e. I build and send a multiplexed packet not including the current one

	      		do_debug(1, " MTU reached. Predicted size: %i bytes. Sending muxed packet without this one.", predicted_size_muxed_packet);

				// add the Single Protocol Bit in the first header (the most significant bit)
				// it is '1' if all the multiplexed packets belong to the same protocol
				if (single_protocol == 1) {
					separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
					size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
				} else {
					size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
				}

				// build the multiplexed packet without the current one
				total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);

				do_debug(1, "size_muxed_packet: %i. total_length: %i\n",size_muxed_packet,total_length);

				// send the multiplexed packet without the current one
				if (sendto(net_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) perror("sendto()");

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
				}

				// I have emptied the buffer, so I have to
				//move the current packet to the first position of the 'packets_to_multiplex' array
				for (l = 0; l < BUFSIZE; l++ ) {
					packets_to_multiplex[0][l]=packets_to_multiplex[num_pkts_stored_from_tun][l];
				}

				// move the current separator to the first position of the array
				for (l = 0; l < 2; l++ ) {
					separators_to_multiplex[0][l]=separators_to_multiplex[num_pkts_stored_from_tun][l];
				}

				// move the length to the first position of the array
				size_packets_to_multiplex[0] = size_packets_to_multiplex[num_pkts_stored_from_tun];
				size_separators_to_multiplex[0] = size_separators_to_multiplex[num_pkts_stored_from_tun];
				for (j=1; j < MAXPKTS; j++) size_packets_to_multiplex [j] = 0;

				// I have sent a packet, so I set to 0 the "first_header_written" bit
				first_header_written = 0;

				// reset the length and the number of packets
				size_muxed_packet = 0;
				num_pkts_stored_from_tun = 0;
			}	/*** end check if MTU would be reached ***/


			// update the size of the muxed packet, adding the size of the current one
			size_muxed_packet = size_muxed_packet + size_packets_to_multiplex[num_pkts_stored_from_tun];

			// I have to add the multiplexing separator. It is 1 byte if the length is smaller than 64 (or 128). 
			// it is 2 bytes if the lengh is 64 (or 128) or more
			if (first_header_written == 0) {
				// this is the first header
				maximum_packet_length = 64;
			} else {
				// this is a non-first header
				maximum_packet_length = 128;
			}

			// check if the length has to be one or two bytes
			if (size_packets_to_multiplex[num_pkts_stored_from_tun] < maximum_packet_length ) {

				// the length can be written in the first byte of the separator (expressed in 6 or 7 bits)
				size_separators_to_multiplex[num_pkts_stored_from_tun] = 1;

				// add the length to the string.
				// since the value is < maximum_packet_length, the most significant bits will always be 0
				separators_to_multiplex[num_pkts_stored_from_tun][0] = size_packets_to_multiplex[num_pkts_stored_from_tun];

				// increase the size of the multiplexed packet
				size_muxed_packet ++;


				// print the  Mux separator (only one byte)
				if(debug) {
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][0], bits);
					do_debug(2, " Mux separator:(%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
					if (first_header_written == 0) {
						PrintByte(2, 7, bits);			// first header
					} else {
						PrintByte(2, 8, bits);			// non-first header
					}
					do_debug(2, "\n");
				}

			} else {
				// the length requires a two-byte separator (length expressed in 14 or 15 bits)
				size_separators_to_multiplex[num_pkts_stored_from_tun] = 2;

				// first byte of the Mux separator
				// It can be:
				// - first-header: SPB bit, LXT=1 and 6 bits with the most significant bytes of the length
				// - non-first-header: LXT=1 and 7 bits with the most significant bytes of the length
				// get the most significant byte by dividing by 256
				// add 64 (or 128) in order to put a '1' in the second (or first) bit
				if (first_header_written == 0) {
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 256 ) + 64;	// first header
				} else {
					separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 256 ) + 128;	// non-first header
				}

				// second byte of the Mux separator
				// the 8 less significant bytes of the length. Use modulo
				separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 256;

				// increase the size of the multiplexed packet
				size_muxed_packet = size_muxed_packet + 2;

				// print the two bytes of the separator
				if(debug) {
					// first byte
					FromByte(separators_to_multiplex[0][num_pkts_stored_from_tun], bits);
					do_debug(2, " Mux separator:(%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
					if (first_header_written == 0) {
						PrintByte(2, 7, bits);			// first header
					} else {
						PrintByte(2, 8, bits);			// non-first header
					}

					// second byte
					FromByte(separators_to_multiplex[num_pkts_stored_from_tun][1], bits);
					do_debug(2, " (%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][1]);
					PrintByte(2, 8, bits);
					do_debug(2, "\n");
				}	
			}

			// I have finished storing the packet, so I increase the number of stored packets
			num_pkts_stored_from_tun ++;

			// I have written a header of the multiplexed bundle, so I have to set to 1 the "first header written bit"
			if (first_header_written == 0) first_header_written = 1;



			//do_debug (1,"\n");
			do_debug(1, " Packet stopped and multiplexed: accumulated %i pkts (%i bytes).", num_pkts_stored_from_tun , size_muxed_packet);
			time_in_microsec = GetTimeStamp();
			time_difference = time_in_microsec - time_last_sent_in_microsec;		
			do_debug(1, " time since last trigger: %" PRIu64 " usec\n", time_difference);//PRIu64 is used for printing uint64_t numbers



			// check if a multiplexed packet has to be sent

			// if the packet limit or the size threshold or the MTU are reached, send all the stored packets to the network
			// do not worry about the MTU. if it is reached, a number of packets will be sent
			if ((num_pkts_stored_from_tun == limit_numpackets_tun) || (size_muxed_packet > size_threshold) || (time_difference > timeout )) {

				// a multiplexed packet has to be sent

				// calculate if all the packets belong to the same protocol
				single_protocol = 1;
				for (k = 1; k < num_pkts_stored_from_tun ; k++) {
					for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
						if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
					}
				}





	      		do_debug(1, " Single Protocol Bit = %i\n", single_protocol);

				// Add the Single Protocol Bit in the first header (the most significant bit)
				// It is 1 if all the multiplexed packets belong to the same protocol
				if (single_protocol == 1) {
					separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
					size_muxed_packet = size_muxed_packet + 1;						// one byte corresponding to the 'protocol' field of the first header
				} else {
					size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;	// one byte per packet, corresponding to the 'protocol' field
				}

				// write the debug information
				if (debug) {
					do_debug(1, " TUN2NET**Sending triggered**. ");
					if (num_pkts_stored_from_tun == limit_numpackets_tun)
						do_debug(1, "num packet limit reached. ");
					if (size_muxed_packet > size_threshold)
						do_debug(1," size limit reached. ");
					if (time_difference > timeout)
						do_debug(1, "timeout reached. ");		
					do_debug(1, "Writing %i packets (%i bytes) to network\n", num_pkts_stored_from_tun, size_muxed_packet);						
				}

				// build the multiplexed packet including the current one
				total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);

				//do_debug(1, "size_muxed_packet: %i. total_length: %i\n",size_muxed_packet,total_length);


				// send the multiplexed packet
				if (sendto(net_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) perror("sendto()");

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i", GetTimeStamp(), size_muxed_packet, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
					if (num_pkts_stored_from_tun == limit_numpackets_tun)
						fprintf(log_file, "\tnumpacket_limit");
					if (size_muxed_packet > size_threshold)
						fprintf(log_file, "\tsize_limit");
					if (time_difference > timeout)
						fprintf(log_file, "\ttimeout");
					fprintf(log_file, "\n");
					fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
				}

				// I have sent a packet, so I set to 0 the "first_header_written" bit
				first_header_written = 0;

				// reset the length and the number of packets
				size_muxed_packet = 0 ;
				num_pkts_stored_from_tun = 0;

				// update the time of the last packet sent
				time_last_sent_in_microsec = time_in_microsec;
			}
    	} 


		/*************************************************************************************/	
		/******************** Period expired: multiplex **************************************/
		/*************************************************************************************/	

		// The period has expired
		// Check if there is something stored, and send it
		// since there is no new packet, here it is not necessary to compress anything

		else {
			time_in_microsec = GetTimeStamp();
			if ( num_pkts_stored_from_tun > 0 ) {

				// There are some packets stored

				// calculate the time difference
				time_difference = time_in_microsec - time_last_sent_in_microsec;		

				if (debug) {
					do_debug(1, "TUN2NET**Period expired. Sending triggered**. time since last trigger: %" PRIu64 " usec\n", time_difference);	
					do_debug(1, "Writing %i packets (%i bytes) to network\n", num_pkts_stored_from_tun, size_muxed_packet);						

				}

				// build the multiplexed packet

				// calculate if all the packets belong to the same protocol
				single_protocol = 1;
				for (k = 1; k < num_pkts_stored_from_tun ; k++) {
					for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
						if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
					}
				}

				// Add the Single Protocol Bit in the first header (the most significant bit)
				// It is 1 if all the multiplexed packets belong to the same protocol
				if (single_protocol == 1) {
					separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
					size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
				} else {
					size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
				}

	      		do_debug(1, " Single Protocol Bit = %i.", single_protocol);

				// build the multiplexed packet
				total_length = build_multiplexed_packet ( num_pkts_stored_from_tun, single_protocol, protocol, size_separators_to_multiplex, separators_to_multiplex, size_packets_to_multiplex, packets_to_multiplex, muxed_packet);

				do_debug(1, "size_muxed_packet: %i. total_length: %i\n",size_muxed_packet,total_length);

				// send the multiplexed packet
				if (sendto(net_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) perror("sendto()");

				// write the log file
				if ( log_file != NULL ) {
					fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);	
				}
			
				// I have sent a packet, so I set to 0 the "first_header_written" bit
				first_header_written = 0;

				// reset the length and the number of packets
				size_muxed_packet = 0 ;
				num_pkts_stored_from_tun = 0;

			} else {
				// No packet arrived
				//do_debug(2, "Period expired. Nothing to be sent\n");
			}

			// restart the period
			time_last_sent_in_microsec = time_in_microsec;
		}

  	}	// end while(1)
  
  	return(0);



/******* labels ************/
release_compressor:
	rohc_comp_free(compressor);

release_decompressor:
	rohc_decomp_free(decompressor);

error:
	fprintf(stderr, "an error occured during program execution, "
	        "abort program\n");
	if ( log_file_name != '\0' ) fclose (log_file);
	return 1;
}



static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
	return rand();
}


