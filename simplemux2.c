/**************************************************************************
 * simplemux2.c            version 2.0                                   *
 *                                                                        *
 * Simplemux multiplexes a number of packets between a pair of machines   *
 * (called ingress and egress). It also sends ethernet frames.            *
 *                                                                        *
 * Simplemux is described here:                                           *
 *  http://datatracker.ietf.org/doc/draft-saldana-tsvwg-simplemux/        *
 *                                                                        *
 * Multiplexing can be combined with Tunneling and Header Compression     *
 * for the optimization of small-packet flows. This is called TCM.        *
 * Different algorithms for header compression, multiplexing and          *
 * tunneling can be combined in a similar way to RFC 4170.                *
 *                                                                        *
 * This code runs a combination of three protocols:                       *
 *      - ROHC header compression (RFC 5225)                              *
 *      - Simplemux, which is used for multiplexing                       *
 *      - a tunneling protocol. In this implementation, the multiplexed   *
 *      bundle can be sent:                                               *
 *          - in an IPv4 packet belonging to protocol 253 (network mode)  *
 *          - in an IPv4/UDP packet (transport mode)                      *
 *                                                                        *
 * IPv6 is not supported in this implementation                           *
 *                                                                        *
 *                                                                        *
 * Jose Saldana wrote this program in 2015, published under GNU GENERAL   *
 * PUBLIC LICENSE, Version 3, 29 June 2007                                *
 * Copyright (C) 2007 Free Software Foundation, Inc.                      *
 *                                                                        *
 * Thanks to Davide Brini for his simpletun.c program. (2010)             *
 * http://backreference.org/wp-content/uploads/2010/03/simpletun.tar.bz2  *
 *                                                                        *
 * This program uses an implementation of ROHC by Didier Barvaux          *
 * (https://rohc-lib.org/).                                               *
 *                                                                        *
 * This program has been written for research purposes, so if you find it *
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
#include <netinet/ip.h>			// for using iphdr type
#include <ifaddrs.h>				// required for using getifaddrs()
#include <netdb.h>					// required for using getifaddrs()
#include <poll.h>


#define BUFSIZE 2304					// buffer for reading from tun interface, must be >= MTU of the network
#define IPv4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define TCP_HEADER_SIZE 20
#define SIZE_PROTOCOL_FIELD 1		// 1: protocol field of one byte
																// 2: protocol field of two bytes
#define NUMBER_OF_SOCKETS 3			// I am using 3 sockets in the program

#define PORT 55555							// default port
#define MAXPKTS 100							// maximum number of packets to store
#define MAXTIMEOUT 100000000.0	// maximum value of the timeout (microseconds). (default 100 seconds)

#define IPPROTO_IP_ON_IP 4			// IP on IP Protocol ID
#define IPPROTO_SIMPLEMUX	253		// Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_ROHC 142				// ROHC Protocol ID
#define IPPROTO_ETHERNET 143		// Ethernet Protocol ID (according to IANA)
																// see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

#define NETWORK_MODE		'N'			// N: network mode
#define UDP_MODE				'U'			// U: UDP mode
#define TCP_CLIENT_MODE	'T'			// T: TCP client mode
#define TCP_SERVER_MODE 'S'			// S: TCP server mode

#define TUN_MODE 'U'						// T: tun mode, i.e. IP packets will be tunneled inside Simplemux
#define TAP_MODE 'A'						// A: tap mode, i.e. Ethernet frames will be tunneled inside Simplemux

#define Linux_TTL 64			// the initial value of the TTL IP field in Linux

#define PROTOCOL_FIRST 0	// 1: protocol field goes before the length byte(s) (as in draft-saldana-tsvwg-simplemux-01)
													// 0: protocol field goes after the length byte(s)  (as in draft-saldana-tsvwg-simplemux-02 and subsequent versions)

/* global variables */
int debug;						// 0:no debug; 1:minimum debug; 2:maximum debug 
char *progname;



/**
 * @brief The RTP detection callback which does detect RTP stream.
 * it assumes that UDP packets belonging to certain ports are RTP packets
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rtp_detect(const unsigned char *const ip __attribute__((unused)),
                      const unsigned char *const udp,
                      const unsigned char *const payload __attribute__((unused)),
                      const unsigned int payload_size __attribute__((unused)),
                      void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if(udp == NULL)
	{
		return false;
	}

	/* get the UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	/* is the UDP destination port in the list of ports reserved for RTP
	 * traffic by default (for compatibility reasons) */
	for(i = 0; i < default_rtp_ports_nr; i++)
	{
		if(ntohs(udp_dport) == default_rtp_ports[i])
		{
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 *          flags can be IFF_TUN (1) or IFF_TAP (2)                       *
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
		perror("cwrite() Error writing data");
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
	fprintf(stderr, "%s -i <ifacename> -e <ifacename> -c <peerIP> -M <N or U or T> [-T <U or A>] [-p <port>] [-d <debug_level>] [-r <ROHC_option>] [-n <num_mux_tun>] [-m <MTU>] [-b <num_bytes_threshold>] [-t <timeout (microsec)>] [-P <period (microsec)>] [-l <log file name>] [-L]\n\n" , progname);
	fprintf(stderr, "%s -h\n", progname);
	fprintf(stderr, "\n");
	fprintf(stderr, "-i <ifacename>: Name of tun interface to use for capturing native packets (mandatory)\n");
	fprintf(stderr, "-e <ifacename>: Name of local interface which IP will be used for reception of muxed packets, i.e., the tunnel local end (mandatory)\n");
	fprintf(stderr, "-c <peerIP>: specify peer destination IP address, i.e. the tunnel remote end (mandatory)\n");
	fprintf(stderr, "-M <mode>: Network (N), UDP (U), TCP (T) mode (mandatory)\n");
	fprintf(stderr, "-T <tunnel mode>: TUN (U, default) or TAP (A) mode\n");
	fprintf(stderr, "-p <port>: port to listen on, and to connect to (default 55555)\n");
	fprintf(stderr, "-d: outputs debug information while running. 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC)\n");
	fprintf(stderr, "-r: 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)\n");
	fprintf(stderr, "-n: number of packets received, to be sent to the network at the same time, default 1, max 100\n");
	fprintf(stderr, "-m: Maximum Transmission Unit of the network path (by default the one of the local interface is taken)\n");
	fprintf(stderr, "-b: size threshold (bytes) to trigger the departure of packets (default MTU-28 in transport mode and MTU-20 in network mode)\n");
	fprintf(stderr, "-t: timeout (in usec) to trigger the departure of packets\n");
	fprintf(stderr, "-P: period (in usec) to trigger the departure of packets. If ( timeout < period ) then the timeout has no effect\n");
	fprintf(stderr, "-l: log file name. Use 'stdout' if you want the log data in standard output\n");
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
unsigned char ToByte(bool b[8]) {
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
void FromByte(unsigned char c, bool b[8]) {
	int i;
	for (i=0; i < 8; ++i)
		b[i] = (c & (1<<i)) != 0;
}

/**************************************************************************
 * PrintByte: prints the bits of a byte                                   *
 **************************************************************************/
void PrintByte(int debug_level, int num_bits, bool b[8]) {
	// num_bits is the number of bits to print
	// if 'num_bits' is smaller than 7, the function prints an 'x' instead of the value

	int i;
	for (i= 7 ; i>= num_bits ; i--) {
			do_debug(debug_level, "_");
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
void dump_packet (int packet_size, unsigned char packet[BUFSIZE]) {
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
int date_and_time(char buffer[25]) {
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
uint16_t build_multiplexed_packet ( int num_packets,
												int single_prot,
												unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD],
												uint16_t size_separators_to_mux[MAXPKTS],
												unsigned char separators_to_mux[MAXPKTS][3],
												uint16_t size_packets_to_mux[MAXPKTS],
												unsigned char packets_to_mux[MAXPKTS][BUFSIZE],
												unsigned char mux_packet[BUFSIZE]) {
	int k, l;
	int length = 0;

	// for each packet, write the protocol field (if required), the separator and the packet itself
	for (k = 0; k < num_packets ; k++) {

		if (k == 0)
			// add a tab before the first separator
			do_debug(2, "   Separators: ");
		else
			// add a semicolon before the 2nd and subsequent separators
			do_debug(2, "; ");
			
		do_debug(2, "#%d: ", k+1);
		
		if ( PROTOCOL_FIRST ) {
			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
				//do_debug(2, "Protocol field: %02x ", prot[k][0]);
				do_debug(2, "0x%02x", prot[k][0]);
			}
				
			// add the separator
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				do_debug(2, "%02x", separators_to_mux[k][l]);
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}
		}
		else {

			// add the separator
			do_debug(2, "0x");
			for (l = 0; l < size_separators_to_mux[k] ; l++) {
				do_debug(2, "%02x", separators_to_mux[k][l]);
				mux_packet[length] = separators_to_mux[k][l];
				length ++;
			}

			// add the 'Protocol' field if necessary
			if ( (k==0) || (single_prot == 0 ) ) {		// the protocol field is always present in the first separator (k=0), and maybe in the rest
				for (l = 0; l < SIZE_PROTOCOL_FIELD ; l++ ) {
					mux_packet[length] = prot[k][l];
					length ++;
				}
				//do_debug(2, "Protocol field: %02x ", prot[k][0]);
				do_debug(2, "%02x", prot[k][0]);
			}
		}
		
		// add the bytes of the packet itself
		for (l = 0; l < size_packets_to_mux[k] ; l++) {
			mux_packet[length] = packets_to_mux[k][l];
			length ++;
		}
	}
	do_debug(2,"\n");
	return length;
}


/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//	- prot[MAXPKTS][SIZE_PROTOCOL_FIELD]	the protocol byte of each packet
//	- size_separators_to_mux[MAXPKTS]			the size of each separator (1 or 2 bytes). Protocol byte not included
//	- separators_to_mux[MAXPKTS][2]				the separators
//	- size_packets_to_mux[MAXPKTS]				the size of each packet to be multiplexed
//	- packets_to_mux[MAXPKTS][BUFSIZE]		the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (int num_packets,
																					int single_prot,
																					unsigned char prot[MAXPKTS][SIZE_PROTOCOL_FIELD],
																					uint16_t size_separators_to_mux[MAXPKTS],
																					unsigned char separators_to_mux[MAXPKTS][3],
																					uint16_t size_packets_to_mux[MAXPKTS],
																					unsigned char packets_to_mux[MAXPKTS][BUFSIZE]) {
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
 * @param priv_ctxt	An optional private context, may be NULL
 * @param level		The priority level of the trace
 * @param entity	The entity that emitted the trace among:
 *					\li ROHC_TRACE_COMP
 *					\li ROHC_TRACE_DECOMP
 * @param profile	The ID of the ROHC compression/decompression profile
 *					the trace is related to
 * @param format	The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
								const rohc_trace_level_t level,
								const rohc_trace_entity_t entity,
								const int profile,
								const char *const format,
								...) {
	// Only prints ROHC messages if debug level is > 2
	if ( debug > 2 ) {
		va_list args;
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}


/**************************************************************************
 * Functions to work with IP Header *
 **************************************************************************/

// Calculate IPv4 checksum
unsigned short in_cksum(unsigned short *addr, int len) {
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *) (&answer) = *(u_char *) w;
		sum += answer;
	}
	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return (answer);
}



// Buid an IPv4 Header
void BuildIPHeader(struct iphdr *iph, uint16_t len_data,struct sockaddr_in local, struct sockaddr_in remote) {
	static uint16_t counter = 0;

	// clean the variable
	memset (iph, 0, sizeof(struct iphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + len_data);
	iph->id = htons(1234 + counter);
	iph->frag_off = 0;	// fragment is allowed
	iph->ttl = Linux_TTL;
	iph->protocol = IPPROTO_SIMPLEMUX;
	iph->saddr = inet_addr(inet_ntoa(local.sin_addr));
	//iph->saddr = inet_addr("192.168.137.1");
	iph->daddr = inet_addr(inet_ntoa(remote.sin_addr));

	iph->check = in_cksum((unsigned short *)iph, sizeof(struct iphdr));
	
	//do_debug(1, "Checksum: %i\n", iph->check);

	counter ++;
}


// Buid a Full IP Packet
void BuildFullIPPacket(struct iphdr iph, unsigned char *data_packet, uint16_t len_data, unsigned char *full_ip_packet) {
	memset(full_ip_packet, 0, BUFSIZE);
	memcpy((struct iphdr*)full_ip_packet, &iph, sizeof(struct iphdr));
	memcpy((struct iphdr*)(full_ip_packet + sizeof(struct iphdr)), data_packet, len_data);
}


//Get IP header from IP packet
void GetIpHeader(struct iphdr *iph, unsigned char *ip_packet) {	
	memcpy(iph,(struct iphdr*)ip_packet,sizeof(struct iphdr));
}

//Set IP header in IP Packet
void SetIpHeader(struct iphdr iph, unsigned char *ip_packet) {
	memcpy((struct iphdr*)ip_packet,&iph,sizeof(struct iphdr));
}



/**************************************************************************
 ************************ main program ************************************
 **************************************************************************/
int main(int argc, char *argv[]) {

	// variables for managing the network interfaces
	int tun_fd;													// file descriptor of the tun interface(no mux packet)
	int udp_mode_fd;								// file descriptor of the socket in UDP mode
	int network_mode_fd;						// file descriptor of the socket in Network mode
	int feedback_fd;								// file descriptor of the socket of the feedback received from the network interface
	int tcp_welcoming_fd;						// file descriptor of the TCP welcoming socket
	int tcp_client_fd;							// file descriptor of the TCP socket
	int tcp_server_fd;
	int maxfd;													// maximum number of file descriptors


	int fd2read;
	
	char tun_if_name[IFNAMSIZ] = "";		// name of the tun interface (e.g. "tun0")
	char mux_if_name[IFNAMSIZ] = "";		// name of the network interface (e.g. "eth0")

	char mode[2] = "";									// Network (N) or UDP (U) or TCP (T) mode

	char tunnel_mode[2]= "U";						// TUN (U, default) or TAP (T) tunnel mode
	
	const int on = 1;										// needed when creating a socket

	struct sockaddr_in local, remote, feedback, feedback_remote, received;	// these are structs for storing sockets
	struct sockaddr_in TCPpair;

	struct iphdr ipheader;							// IP header
	struct ifreq iface;									// network interface

	socklen_t slen = sizeof(remote);							// size of the socket. The type is like an int, but adequate for the size of the socket
	socklen_t slen_feedback = sizeof(feedback);		// size of the socket. The type is like an int, but adequate for the size of the socket

	char remote_ip[16] = "";											// dotted quad IP string with the IP of the remote machine
	char local_ip[16] = "";												// dotted quad IP string with the IP of the local machine     
	unsigned short int port = PORT;								// UDP port to be used for sending the multiplexed packets
	unsigned short int port_feedback = PORT + 1;	// UDP port to be used for sending the ROHC feedback packets, when using ROHC bidirectional

	// variables for storing the packets to multiplex
	uint16_t total_length;																	// total length of the built multiplexed packet
	unsigned char protocol_rec;															// protocol field of the received muxed packet
	unsigned char protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];		// protocol field of each packet
	uint16_t size_separators_to_multiplex[MAXPKTS];					// stores the size of the Simplemux separator. It does not include the "Protocol" field
	unsigned char separators_to_multiplex[MAXPKTS][3];			// stores the header ('protocol' not included) received from tun, before sending it to the network
	uint16_t size_packets_to_multiplex[MAXPKTS];						// stores the size of the received packet
	unsigned char packets_to_multiplex[MAXPKTS][BUFSIZE];		// stores the packets received from tun, before storing it or sending it to the network
	unsigned char muxed_packet[BUFSIZE];										// stores the multiplexed packet
	int is_multiplexed_packet;															// To determine if a received packet have been multiplexed
	unsigned char full_ip_packet[BUFSIZE];									// Full IP packet

	// variables for storing the packets to demultiplex
	uint16_t nread_from_net;												// number of bytes read from network which will be demultiplexed
	unsigned char buffer_from_net[BUFSIZE];					// stores the packet received from the network, before sending it to tun
	unsigned char buffer_from_net_aux[BUFSIZE];			// stores the packet received from the network, before sending it to tun
	unsigned char demuxed_packet[BUFSIZE];					// stores each demultiplexed packet

	// variables for controlling the arrival and departure of packets
	unsigned long int tun2net = 0, net2tun = 0;		// number of packets read from tun and from net
	unsigned long int feedback_pkts = 0;					// number of ROHC feedback packets
	int limit_numpackets_tun = 0;									// limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS

	int size_threshold = 0;												// if the number of bytes stored is higher than this, a muxed packet is sent
	int size_max;																	// maximum value of the packet size

	uint64_t timeout = MAXTIMEOUT;								// (microseconds) if a packet arrives and the 'timeout' has expired (time from the  
																								//previous sending), the sending is triggered. default 100 seconds
	uint64_t period= MAXTIMEOUT;									// (microseconds). If the 'period' expires, a packet is sent
	uint64_t microseconds_left = period;					// the time until the period expires	

	// very long unsigned integers for storing the system clock in microseconds
	uint64_t time_last_sent_in_microsec;					// moment when the last multiplexed packet was sent
	uint64_t time_in_microsec;										// current time
	uint64_t time_difference;											// difference between two timestamps

	int option;															// command line options
	int l,j,k;
	int num_pkts_stored_from_tun = 0;				// number of packets received and not sent from tun (stored)
	int size_muxed_packet = 0;							// accumulated size of the multiplexed packet
	int predicted_size_muxed_packet;				// size of the muxed packet if the arrived packet was added to it
	int position;														// for reading the arrived multiplexed packet
	int packet_length;											// the length of each packet inside the multiplexed bundle
	int interface_mtu;											// the maximum transfer unit of the interface
	int user_mtu = 0;												// the MTU specified by the user (it must be <= interface_mtu)
	int selected_mtu;												// the MTU that will be used in the program
	int num_demuxed_packets;								// a counter of the number of packets inside a muxed one
	int single_protocol;										// it is 1 when the Single-Protocol-Bit of the first header is 1
	int single_protocol_rec;								// it is the bit Single-Protocol-Bit received in a muxed packet
	int first_header_read;									// it is 0 when the first header has not been read
	int LXT_position;												// the position of the LXT bit. It may be 6 (non-first header) or 7 (first header)
	int maximum_packet_length;							// the maximum length of a packet. It may be 64 (first header) or 128 (non-first header)
	int limit_length_two_bytes;							// the maximum length of a packet in order to express it in 2 bytes. It may be 8192 or 16384 (non-first header)
	int first_header_written = 0;						// it indicates if the first header has been written or not
	int drop_packet = 0;
	bool accepting_tcp_connections;					// it is set to '1' if this is a TCP server and no connections have started

	bool bits[8];														// it is used for printing the bits of a byte in debug mode

	/* ROHC header compression variables */
	int ROHC_mode = 0;			// it is 0 if ROHC is not used
													// it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
													// it is 2 for ROHC Bidirectional Optimistic mode
													// it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)

	struct rohc_comp *compressor;           		// the ROHC compressor
	unsigned char ip_buffer[BUFSIZE];						// the buffer that will contain the IPv4 packet to compress
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFSIZE);	
	unsigned char rohc_buffer[BUFSIZE];					// the buffer that will contain the resulting ROHC packet
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFSIZE);
	unsigned int seed;
	rohc_status_t status;

	struct rohc_decomp *decompressor;       		// the ROHC decompressor
	unsigned char ip_buffer_d[BUFSIZE];					// the buffer that will contain the resulting IP decompressed packet
	struct rohc_buf ip_packet_d = rohc_buf_init_empty(ip_buffer_d, BUFSIZE);
	unsigned char rohc_buffer_d[BUFSIZE];				// the buffer that will contain the ROHC packet to decompress
	struct rohc_buf rohc_packet_d = rohc_buf_init_empty(rohc_buffer_d, BUFSIZE);

	/* structures to handle ROHC feedback */
	unsigned char rcvd_feedback_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet received
	struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcvd_feedback_buffer_d, BUFSIZE);

	unsigned char feedback_send_buffer_d[BUFSIZE];	// the buffer that will contain the ROHC feedback packet to be sent
	struct rohc_buf feedback_send = rohc_buf_init_empty(feedback_send_buffer_d, BUFSIZE);


	/* variables for the log file */
	char log_file_name[100] = "";       // name of the log file	
	FILE *log_file = NULL;							// file descriptor of the log file
	int file_logging = 0;								// it is set to 1 if logging into a file is enabled



	/************** Check command line options *********************/
	progname = argv[0];		// argument used when calling the program

	// no arguments specified by the user. Print usage and finish
	if (argc == 1 ) {
		usage ();
	}
	else {
		while((option = getopt(argc, argv, "i:e:M:T:c:p:n:b:t:P:l:d:r:m:hL")) > 0) {

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
				case 'i':						/* put the name of the tun interface (e.g. "tun0") in "tun_if_name" */
					strncpy(tun_if_name, optarg, IFNAMSIZ-1);
					break;
				case 'M':						/* Network (N) or UDP (U) or TCP client (T) or TCP server (S) mode */
					strncpy(mode, optarg, 1);
					break;
				case 'T':						/* TUN (U) or TAP (A) tunnel mode */
					strncpy(tunnel_mode, optarg, 1);
					break;
				case 'e':						/* the name of the network interface (e.g. "eth0") in "mux_if_name" */
					strncpy(mux_if_name, optarg, IFNAMSIZ-1);
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
				case 'm':						/* MTU forced by the user */
					user_mtu = atoi(optarg);
					break;
				case 'b':						/* size threshold (in bytes) for triggering a muxed packet */
					size_threshold = atoi(optarg);
					break;
				case 't':						/* timeout for triggering a muxed packet */
					timeout = atoll(optarg);
					break;
				case 'P':						/* Period for triggering a muxed packet */
					period = atoll(optarg);
					break;
				default:
					my_err("Unknown option %c\n", option);
					usage();
					break;
			}
		}

		argv += optind;
		argc -= optind;

		if(argc > 0) {
			my_err("Too many options\n");
			usage();
		}


		// check interface options
		if(*tun_if_name == '\0') {
			my_err("Must specify a tun interface name for native packets ('-i' option)\n");
			usage();
		} else if(*remote_ip == '\0') {
			my_err("Must specify the address of the peer\n");
			usage();
		} else if(*mux_if_name == '\0') {
			my_err("Must specify local interface name for multiplexed packets\n");
			usage();
		} 


		// check if NETWORK or TRANSPORT mode have been selected (mandatory)
		else if((*mode != NETWORK_MODE) && (*mode != UDP_MODE) && (*mode != TCP_CLIENT_MODE) && (*mode != TCP_SERVER_MODE)) {
			my_err("Must specify a valid mode ('-M' option MUST be 'N' (network), 'U' (UDP) or 'T'(TCP))\n");
			usage();
		} 
	
		// check if TUN or TAP mode have been selected (mandatory)
		else if((*tunnel_mode != TUN_MODE) && (*tunnel_mode != TAP_MODE)) {
			my_err("Must specify a valid tunnel mode ('-T' option MUST be 'U' (tun) or 'A' (tap))\n");
			usage();
		} 

		/* open the log file */
		if ( file_logging == 1 ) {
			if (strcmp(log_file_name, "stdout") == 0) {
				log_file = stdout;
			} else {
				log_file = fopen(log_file_name, "w");
				if (log_file == NULL) my_err("Error: cannot open the log file!\n");
			}
		}

		// check debug option
		if ( debug < 0 ) debug = 0;
		else if ( debug > 3 ) debug = 3;
		do_debug ( 1 , "debug level set to %i\n", debug);

		// check ROHC option
		if ( ROHC_mode < 0 ) {
			ROHC_mode = 0;
		}
		else if ( ROHC_mode > 2 ) { 
			ROHC_mode = 2;
		}

		if (*tunnel_mode == TUN_MODE) {
			// tun tunnel mode (i.e. send IP packets)
			/*** initialize tun interface for native packets ***/
			if ( (tun_fd = tun_alloc(tun_if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
				my_err("Error connecting to tun interface for capturing native packets %s\n", tun_if_name);
				exit(1);
			}
			do_debug(1, "Successfully connected to interface for native packets %s\n", tun_if_name);		
		}
		else if (*tunnel_mode == TAP_MODE) {
			// tap tunnel mode (i.e. send Ethernet frames)
			
			// ROHC mode cannot be used in tunnel mode TAP, because Ethernet headers cannot be compressed
			if (ROHC_mode != 0) {
				my_err("Error ROHC cannot be used in TAP mode (Ethernet headers cannot be compressed)\n");
				exit(1);					
			}				

			/*** initialize tap interface for native packets ***/
			if ( (tun_fd = tun_alloc(tun_if_name, IFF_TAP | IFF_NO_PI)) < 0 ) {
				my_err("Error connecting to tap interface for capturing native Ethernet frames %s\n", tun_if_name);
				exit(1);
			}
			do_debug(1, "Successfully connected to interface for Ethernet frames %s\n", tun_if_name);		
		}
		else exit(1); // this would be a failure
		
		// I will only set this to '1' if this is a TCP server
		accepting_tcp_connections = 0;
		
		/*** Request a socket for writing and receiving muxed packets in Network mode ***/
		if ( *mode == NETWORK_MODE ) {
			// initialize header IP to be used when receiving a packet in NETWORK mode
			memset(&ipheader, 0, sizeof(struct iphdr));			
			memset (&iface, 0, sizeof (iface));
			snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);

			// get the local IP address of the network interface 'mux_if_name'
			// using 'getifaddrs()' 	
		  struct ifaddrs *ifaddr, *ifa;
	    int /*family,*/ s;
	    char host[NI_MAXHOST];	// this will be the IP address
	
	    if (getifaddrs(&ifaddr) == -1) {
	        perror("getifaddrs");
	        exit(EXIT_FAILURE);
	    }
	    
	    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr == NULL)
					continue;  
				
				s=getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				
				if((strcmp(ifa->ifa_name,mux_if_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
			    if (s != 0) {
			        printf("getnameinfo() failed: %s\n", gai_strerror(s));
			        exit(EXIT_FAILURE);
			    }
			    //printf("\tInterface : <%s>\n",ifa->ifa_name );
			    //printf("\t  Address : <%s>\n", host);
			    do_debug(1,"Raw socket for multiplexing over IP open. Interface %s\nLocal IP %s. Protocol number %i\n", ifa->ifa_name, host, IPPROTO_SIMPLEMUX);
			    break;
				}
	    }
 
			// assign the local address for the multiplexed packets
			memset(&local, 0, sizeof(local));
			local.sin_family = AF_INET;
			local.sin_addr.s_addr = inet_addr(host);	// convert the string 'host' to an IP address

	    freeifaddrs(ifaddr);
	    
 			// assign the destination address for the multiplexed packets
			memset(&remote, 0, sizeof(remote));
			remote.sin_family = AF_INET;
			remote.sin_addr.s_addr = inet_addr(remote_ip);		// remote IP. There are no ports in Network Mode
	
			// AF_INET (exactly the same as PF_INET)
			// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
			// network_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets
			// create a raw socket for reading and writing multiplexed packets belonging to protocol Simplemux (protocol ID 253)
			// Submit request for a raw socket descriptor
			if ((network_mode_fd = socket (AF_INET, SOCK_RAW, IPPROTO_SIMPLEMUX)) < 0) {
				perror ("Raw socket for sending muxed packets failed ");
				exit (EXIT_FAILURE);
			}
			else {
				do_debug(1,"Remote IP %s\n", inet_ntoa(remote.sin_addr));
			}

			// Set flag so socket expects us to provide IPv4 header
			if (setsockopt (network_mode_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
				perror ("setsockopt() failed to set IP_HDRINCL ");
				exit (EXIT_FAILURE);
			}

			// Bind the socket "network_mode_fd" to interface index
			// bind socket descriptor "network_mode_fd" to specified interface with setsockopt() since
			// none of the other arguments of sendto() specify which interface to use.
			if (setsockopt (network_mode_fd, SOL_SOCKET, SO_BINDTODEVICE, &iface, sizeof (iface)) < 0) {
				perror ("setsockopt() failed to bind to interface (network mode) ");
				exit (EXIT_FAILURE);
			}	
		}
		
		// UDP mode
		else if ( *mode == UDP_MODE ) {
			/*** Request a socket for writing and receiving muxed packets in UDP mode ***/
			// AF_INET (exactly the same as PF_INET)
			// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
			// udp_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets

			/* creates an UN-named socket inside the kernel and returns
			 * an integer known as socket descriptor
			 * This function takes domain/family as its first argument.
			 * For Internet family of IPv4 addresses we use AF_INET
			 */
			if ( ( udp_mode_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
				perror("socket() UDP mode");
				exit(1);
			}

			// Use ioctl() to look up interface index which we will use to bind socket descriptor "udp_mode_fd" to
			memset (&iface, 0, sizeof (iface));
			snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
			if (ioctl (udp_mode_fd, SIOCGIFINDEX, &iface) < 0) {
				perror ("ioctl() failed to find interface (transport mode) ");
				return (EXIT_FAILURE);
			}

			/*** get the IP address of the local interface ***/
			if (ioctl(udp_mode_fd, SIOCGIFADDR, &iface) < 0) {
				perror ("ioctl() failed to find the IP address for local interface ");
				return (EXIT_FAILURE);
			}
			else {
				// source IPv4 address: it is the one of the interface
				strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
				do_debug(1, "Local IP for multiplexing %s\n", local_ip);
			}
	
			// assign the destination address and port for the multiplexed packets
			memset(&remote, 0, sizeof(remote));
			remote.sin_family = AF_INET;
			remote.sin_addr.s_addr = inet_addr(remote_ip);		// remote IP
			remote.sin_port = htons(port);						// remote port
	
			// assign the local address and port for the multiplexed packets
			memset(&local, 0, sizeof(local));
			local.sin_family = AF_INET;
			local.sin_addr.s_addr = inet_addr(local_ip);		// local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
			local.sin_port = htons(port);						// local port
	
			// bind the socket "udp_mode_fd" to the local address and port
		 	if (bind(udp_mode_fd, (struct sockaddr *)&local, sizeof(local))==-1) {
				perror("bind");
			}
			else {
				do_debug(1, "Socket for multiplexing over UDP open. Remote IP %s. Port %i\n", inet_ntoa(remote.sin_addr), htons(remote.sin_port)); 
			}
		}

		// TCP server mode
		else if (*mode == TCP_SERVER_MODE ) {
			/*** Request a socket for writing and receiving muxed packets in TCP mode ***/
			// AF_INET (exactly the same as PF_INET)
			// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
			// tcp_welcoming_fd is the file descriptor of the socket for managing arrived multiplexed packets

			/* creates an UN-named socket inside the kernel and returns
			 * an integer known as socket descriptor
			 * This function takes domain/family as its first argument.
			 * For Internet family of IPv4 addresses we use AF_INET
			 */
			if ( ( tcp_welcoming_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
				perror("socket() TCP server mode");
				exit(1);
			}			

			// Use ioctl() to look up interface index which we will use to bind socket descriptor "udp_mode_fd" to
			memset (&iface, 0, sizeof (iface));
			snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
								
			/*** get the IP address of the local interface ***/
			if (ioctl(tcp_welcoming_fd, SIOCGIFADDR, &iface) < 0) {
				perror ("ioctl() failed to find the IP address for local interface ");
				return (EXIT_FAILURE);
			}
			else {
				// source IPv4 address: it is the one of the interface
				strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
				do_debug(1, "Local IP for multiplexing %s\n", local_ip);
			}

			// assign the destination address and port for the multiplexed packets
			memset(&remote, 0, sizeof(remote));
			remote.sin_family = AF_INET;
			remote.sin_addr.s_addr = inet_addr(remote_ip);		// remote IP
			remote.sin_port = htons(port);						// remote port
	
			// assign the local address and port for the multiplexed packets
			memset(&local, 0, sizeof(local));
			local.sin_family = AF_INET;
			local.sin_addr.s_addr = inet_addr(local_ip);		// local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
			local.sin_port = htons(port);						// local port

			/* The call to the function "bind()" assigns the details specified
			 * in the structure 'sockaddr' to the socket created above
			 */	
			if (bind(tcp_welcoming_fd, (struct sockaddr *)&local, sizeof(local))==-1) {
				perror("bind");
			}
			else {
				do_debug(1, "Welcoming TCP socket open. Remote IP %s. Port %i\n", inet_ntoa(remote.sin_addr), htons(remote.sin_port)); 
			}

			/* The call to the function "listen()" with second argument as 1 specifies
			 * maximum number of client connections that the server will queue for this listening
			 * socket.
			 */
			listen(tcp_welcoming_fd, 1);
			
			// from now on, I will accept a TCP connection
			accepting_tcp_connections = 1;
		}

		// TCP client mode
		else if (*mode == TCP_CLIENT_MODE ) {
			/*** Request a socket for writing and receiving muxed packets in TCP mode ***/
			// AF_INET (exactly the same as PF_INET)
			// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
			// tcp_welcoming_fd is the file descriptor of the socket for managing arrived multiplexed packets

			/* creates an UN-named socket inside the kernel and returns
			 * an integer known as socket descriptor
			 * This function takes domain/family as its first argument.
			 * For Internet family of IPv4 addresses we use AF_INET
			 */
			if ( ( tcp_client_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
				perror("socket() TCP mode");
				exit(1);
			}
			
			// Use ioctl() to look up interface index which we will use to bind socket descriptor "udp_mode_fd" to
			memset (&iface, 0, sizeof (iface));
			snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
			
			/*** get the IP address of the local interface ***/
			if (ioctl(tcp_client_fd, SIOCGIFADDR, &iface) < 0) {
				perror ("ioctl() failed to find the IP address for local interface ");
				return (EXIT_FAILURE);
			}
			else {
				// source IPv4 address: it is the one of the interface
				strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
				do_debug(1, "Local IP for multiplexing %s\n", local_ip);
			}

			// assign the local address and port for the multiplexed packets
			memset(&local, 0, sizeof(local));
			local.sin_family = AF_INET;
			local.sin_addr.s_addr = inet_addr(local_ip);		// local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
			local.sin_port = htons(port);						// local port
			
			// assign the destination address and port for the multiplexed packets
			memset(&remote, 0, sizeof(remote));
			remote.sin_family = AF_INET;
			remote.sin_addr.s_addr = inet_addr(remote_ip);		// remote IP
			remote.sin_port = htons(port);						// remote port


			/* Information like IP address of the remote host and its port is
			 * bundled up in a structure and a call to function connect() is made
			 * which tries to connect this socket with the socket (IP address and port)
			 * of the remote host
			 */
			if( connect(tcp_client_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
				perror("connect() error: TCP connect Failed. The TCP server did not accept the connection");
				return 1;
			}
			else {
				do_debug(1, "Successfully connected to the TCP server at %s:%i\n", inet_ntoa(remote.sin_addr), htons(remote.sin_port)); 
			}
		}

		/*** get the MTU of the local interface ***/
		if (*mode == UDP_MODE)	{
			if (ioctl(udp_mode_fd, SIOCGIFMTU, &iface) == -1)
				interface_mtu = 0;
			else interface_mtu = iface.ifr_mtu;
		}
		else if (*mode == NETWORK_MODE) {
			if (ioctl(network_mode_fd, SIOCGIFMTU, &iface) == -1)
				interface_mtu = 0;
			else interface_mtu = iface.ifr_mtu;
		}
		else if (*mode == TCP_SERVER_MODE ) {
			if (ioctl(tcp_welcoming_fd, SIOCGIFMTU, &iface) == -1)
				interface_mtu = 0;
			else interface_mtu = iface.ifr_mtu;
		}
		else if (*mode == TCP_CLIENT_MODE ) {
			if (ioctl(tcp_client_fd, SIOCGIFMTU, &iface) == -1)
				interface_mtu = 0;
			else interface_mtu = iface.ifr_mtu;
		}
		/*** check if the user has specified a bad MTU ***/
		do_debug (1, "Local interface MTU: %i\t ", interface_mtu);
		if ( user_mtu > 0 ) {
			do_debug (1, "User-selected MTU: %i\n", user_mtu);
		}
		else {
			do_debug (1, "\n");
		}

		if (user_mtu > interface_mtu) {
			perror ("Error: The MTU specified by the user is higher than the MTU of the interface\n");
			exit (1);
		}
		else {

			// if the user has specified a MTU, I use it instead of network MTU
			if (user_mtu > 0) {
				selected_mtu = user_mtu;

			// otherwise, use the MTU of the local interface
			}
			else {
				selected_mtu = interface_mtu;
			}
		}

		if (selected_mtu > BUFSIZE ) {
			do_debug (1, "Selected MTU: %i\t Size of the buffer for packet storage: %i\n", selected_mtu, BUFSIZE);
			perror ("Error: The MTU selected is higher than the size of the buffer defined.\nCheck #define BUFSIZE at the beginning of this application\n");
			exit (1);
		}

		// define the maximum size threshold
		switch (*mode) {
			case NETWORK_MODE:
				size_max = selected_mtu - IPv4_HEADER_SIZE ;
			break;
			
			case UDP_MODE:
				size_max = selected_mtu - IPv4_HEADER_SIZE - UDP_HEADER_SIZE ;
			break;
			
			case TCP_CLIENT_MODE:
				size_max = selected_mtu - IPv4_HEADER_SIZE - TCP_HEADER_SIZE;
			break;
			
			case TCP_SERVER_MODE:
				size_max = selected_mtu - IPv4_HEADER_SIZE - TCP_HEADER_SIZE;
			break;
		}

		// the size threshold has not been established by the user 
		if (size_threshold == 0 ) {
			size_threshold = size_max;
			//do_debug (1, "Size threshold established to the maximum: %i.", size_max);
		}

		// the user has specified a too big size threshold
		if (size_threshold > size_max ) {
			do_debug (1, "Warning: Size threshold too big: %i. Automatically set to the maximum: %i\n", size_threshold, size_max);
			size_threshold = size_max;
		}

		/*** set the triggering parameters according to user selections (or default values) ***/
	
		// there are four possibilities for triggering the sending of the packets:
		// - a threshold of the accumulated packet size. Two different options apply:
		// 		-	the size of the multiplexed packet has exceeded the size threshold specified by the user,
		//			but not the MTU. In this case, a packet is sent and a new period is started with the
		//			buffer empty.
		//		-	the size of the multiplexed packet has exceeded the MTU (and the size threshold consequently).
		//			In this case, a packet is sent without the last one. A new period is started, and the last 
		//			packet is stored as the first packet to be sent at the end of the next period.
		// - a number of packets
		// - a timeout. A packet arrives. If the timeout has been reached, a muxed packet is triggered
		// - a period. If the period has been reached, a muxed packet is triggered

		// if ( timeout < period ) then the timeout has no effect
		// as soon as one of the conditions is accomplished, all the accumulated packets are sent

		// if no limit of the number of packets is set, then it is set to the maximum
		if (( (size_threshold < size_max) || (timeout < MAXTIMEOUT) || (period < MAXTIMEOUT) ) && (limit_numpackets_tun == 0))
			limit_numpackets_tun = MAXPKTS;

		// if no option is set by the user, it is assumed that every packet will be sent immediately
		if (( (size_threshold == size_max) && (timeout == MAXTIMEOUT) && (period == MAXTIMEOUT)) && (limit_numpackets_tun == 0))
			limit_numpackets_tun = 1;
	

		// I calculate 'now' as the moment of the last sending
		time_last_sent_in_microsec = GetTimeStamp() ; 

		do_debug (1, "Multiplexing policies: size threshold: %i. numpackets: %i. timeout: %"PRIu64"us. period: %"PRIu64"us\n",
							size_threshold, limit_numpackets_tun, timeout, period);
		
		
		// I only need the feedback socket if ROHC is activated
		//but I create it in case the other extreme sends ROHC packets
		if(1) {
			/*** Request a socket for feedback packets ***/
			// AF_INET (exactly the same as PF_INET)
			// transport_protocol: 	SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)	
			// feedback_fd is the file descriptor of the socket for managing arrived feedback packets
			if ( ( feedback_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
				perror("socket()");
				exit(1);
			}
	
			if (ioctl (feedback_fd, SIOCGIFINDEX, &iface) < 0) {
				perror ("ioctl() failed to find interface (feedback)");
				return (EXIT_FAILURE);
			}
			
			// assign the destination address and port for the feedback packets
			memset(&feedback_remote, 0, sizeof(feedback_remote));
			feedback_remote.sin_family = AF_INET;
			feedback_remote.sin_addr.s_addr = inet_addr(remote_ip);	// remote feedback IP (the same IP as the remote one)
			feedback_remote.sin_port = htons(port_feedback);		// remote feedback port
	
			// assign the source address and port to the feedback packets
			memset(&feedback, 0, sizeof(feedback));
			feedback.sin_family = AF_INET;
			feedback.sin_addr.s_addr = inet_addr(local_ip);		// local IP
			feedback.sin_port = htons(port_feedback);			// local port (feedback)
	
			// bind the socket "feedback_fd" to the local feedback address (the same used for multiplexing) and port
		 	if (bind(feedback_fd, (struct sockaddr *)&feedback, sizeof(feedback))==-1) {
				perror("bind");
			}
			else {
				do_debug(1, "Socket for ROHC feedback over UDP open. Remote IP %s. Port %i\n", inet_ntoa(feedback_remote.sin_addr), htons(feedback_remote.sin_port)); 
			}
		}

		//do_debug(1,"tun_fd: %d; network_mode_fd: %d; udp_mode_fd: %d; feedback_fd: %d; tcp_welcoming_fd: %d; tcp_client_fd: %d\n", tun_fd, network_mode_fd, udp_mode_fd, feedback_fd, tcp_welcoming_fd, tcp_client_fd);
		
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
				do_debug ( 1 , "ROHC Bidirectional Reliable Mode\n", debug);	// Bidirectional Reliable mode (not implemented yet)
				break;*/
		}

		// If ROHC has been selected, I have to initialize it
		// see the API here: https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/
		if ( ROHC_mode > 0 ) {

			/* initialize the random generator */
			seed = time(NULL);
			srand(seed);
			
			/* Create a ROHC compressor with Large CIDs and the largest MAX_CID
			 * possible for large CIDs */
			compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, gen_random_num, NULL);
			if(compressor == NULL) {
				fprintf(stderr, "failed create the ROHC compressor\n");
				goto error;
			}
			
			do_debug(1, "ROHC compressor created. Profiles: ");
			
			// Set the callback function to be used for detecting RTP.
			// RTP is not detected automatically. So you have to create a callback function "rtp_detect" where you specify the conditions.
			// In our case we will consider as RTP the UDP packets belonging to certain ports
			if(!rohc_comp_set_rtp_detection_cb(compressor, rtp_detect, NULL)) {
			 	fprintf(stderr, "failed to set RTP detection callback\n");
				goto error;
			}

			// set the function that will manage the ROHC compressing traces (it will be 'print_rohc_traces')
			if(!rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL)) {
				fprintf(stderr, "failed to set the callback for traces on compressor\n");
				goto release_compressor;
			}

			/* Enable the ROHC compression profiles */
			if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED)) {
				fprintf(stderr, "failed to enable the Uncompressed compression profile\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "Uncompressed. ");
			}

			if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP)) {
				fprintf(stderr, "failed to enable the IP-only compression profile\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "IP-only. ");
			}

			if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP, ROHC_PROFILE_UDPLITE, -1)) {
				fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite compression profiles\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "IP/UDP. IP/UDP-Lite. ");
			}

			if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP)) {
				fprintf(stderr, "failed to enable the RTP compression profile\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "RTP (UDP ports 1234, 36780, 33238, 5020, 5002). ");
			}

			if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP)) {
				fprintf(stderr, "failed to enable the ESP compression profile\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "ESP. ");
			}

			if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP)) {
				fprintf(stderr, "failed to enable the TCP compression profile\n");
				goto release_compressor;
			}
			else {
				do_debug(1, "TCP. ");
			}
			do_debug(1, "\n");


			/* Create a ROHC decompressor to operate:
			*  - with large CIDs use ROHC_LARGE_CID, ROHC_LARGE_CID_MAX
			*  - with small CIDs use ROHC_SMALL_CID, ROHC_SMALL_CID_MAX maximum of 5 streams (MAX_CID = 4),
			*  - ROHC_O_MODE: Bidirectional Optimistic mode (O-mode)
			*  - ROHC_U_MODE: Unidirectional mode (U-mode).    */
			if ( ROHC_mode == 1 ) {
				decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);	// Unidirectional mode
			}
			else if ( ROHC_mode == 2 ) {
				decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);	// Bidirectional Optimistic mode
			}
			/*else if ( ROHC_mode == 3 ) {
				decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);	// Bidirectional Reliable mode (not implemented yet)
			}*/

			if(decompressor == NULL)
			{
				fprintf(stderr, "failed create the ROHC decompressor\n");
				goto release_decompressor;
			}

			do_debug(1, "ROHC decompressor created. Profiles: ");

			// set the function that will manage the ROHC decompressing traces (it will be 'print_rohc_traces')
			if(!rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL)) {
				fprintf(stderr, "failed to set the callback for traces on decompressor\n");
				goto release_decompressor;
			}

			// enable rohc decompression profiles
			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, -1);
			if(!status)	{
				fprintf(stderr, "failed to enable the Uncompressed decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "Uncompressed. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_IP, -1);
			if(!status)	{
				fprintf(stderr, "failed to enable the IP-only decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "IP-only. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP, -1);
			if(!status)	{
				fprintf(stderr, "failed to enable the IP/UDP decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "IP/UDP. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDPLITE, -1);
			if(!status)
			{
				fprintf(stderr, "failed to enable the IP/UDP-Lite decompression profile\n");
				goto release_decompressor;
			} else {
				do_debug(1, "IP/UDP-Lite. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_RTP, -1);
			if(!status)	{
				fprintf(stderr, "failed to enable the RTP decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "RTP. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_ESP,-1);
			if(!status)	{
			fprintf(stderr, "failed to enable the ESP decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "ESP. ");
			}

			status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_TCP, -1);
			if(!status) {
				fprintf(stderr, "failed to enable the TCP decompression profile\n");
				goto release_decompressor;
			}
			else {
				do_debug(1, "TCP. ");
			}

			do_debug(1, "\n");
		}
		do_debug(1, "\n");
		

		/** prepare POLL structure **/
		// it has size 3 (NUMBER_OF_SOCKETS), because it handles 3 sockets
		// - tun/tap socket where demuxed packets are sent/received
		// - feedback socket
		// - socket where muxed packets are sent/received. It can be:
		//			- Network mode: IP raw socket
		//			- UDP mode: UDP socket
		//			- TCP server mode
		//			- TCP client mode
	  struct pollfd* fds_poll = malloc(NUMBER_OF_SOCKETS * sizeof(struct pollfd));
	  memset(fds_poll, 0, NUMBER_OF_SOCKETS * sizeof(struct pollfd));
	
	  fds_poll[0].fd = tun_fd;
	  fds_poll[1].fd = feedback_fd;
	  if (*mode == NETWORK_MODE)
		  fds_poll[2].fd = network_mode_fd;
		else if (*mode == UDP_MODE)
			fds_poll[2].fd = udp_mode_fd;
	  else if (*mode==TCP_SERVER_MODE)
		  fds_poll[2].fd = tcp_welcoming_fd;
	  else
	  	fds_poll[2].fd = tcp_client_fd;
	  
	  fds_poll[0].events = POLLIN;
	  fds_poll[1].events = POLLIN;
	  fds_poll[2].events = POLLIN;
		/** END prepare POLL structure **/	
			
		
		/*****************************************/
		/************** Main loop ****************/
		/*****************************************/
		while(1) {
		
			/* Initialize the timeout data structure. */
			time_in_microsec = GetTimeStamp();
			if ( period > (time_in_microsec - time_last_sent_in_microsec)) {
				microseconds_left = (period - (time_in_microsec - time_last_sent_in_microsec));			
			}
			else {
				microseconds_left = 0;
			}
			//do_debug (1, "microseconds_left: %i\n", microseconds_left);

			//if (microseconds_left > 0) do_debug(0,"%"PRIu64"\n", microseconds_left);
			int milliseconds_left = (int)(microseconds_left / 1000.0);
			
			/** POLL **/
	    // check if a frame has arrived to any of the file descriptors
			// - the first argument is the pollfd struct
			// - the second argument is '3', i.e. the number of sockets NUMBER_OF_SOCKETS
			// - third argument: the timeout specifies the number of milliseconds that
      //   poll() should block waiting for a file descriptor to become ready.
	    fd2read = poll(fds_poll, NUMBER_OF_SOCKETS, milliseconds_left);


	    /********************************/
	    /**** Error in poll function ****/
	    /********************************/
	    if(fd2read < 0) {
	      if(fd2read == -1 || errno != EINTR ) {
	
	      }
	      else {
	        perror("Error in poll function");
	        return -1;
	      }
	    }
	
	    /*******************************************/
	    /**** A frame has arrived to one socket ****/
	    /*******************************************/
	    // a frame has arrived to one of the sockets in 'fds_poll'
	    else if (fd2read > 0) {
				//do_debug(0,"fd2read: %d; mode: %c; accepting_tcp_connections: %i\n", fd2read, *mode, accepting_tcp_connections);

				/******************************************************************/
				/********************* TCP connection from a client ***************/
				/******************************************************************/
				// a connection request has arrived to the welcoming socket
				if ((fds_poll[2].revents & POLLIN) && (*mode==TCP_SERVER_MODE) && (accepting_tcp_connections == 1) ) {

					// accept the connection
					unsigned int len = sizeof(struct sockaddr);
					tcp_server_fd = accept(tcp_welcoming_fd, (struct sockaddr*)&TCPpair, &len);
					
					// from now on, the TCP welcoming socket will NOT accept any other connection
					accepting_tcp_connections = 0;
	
	        if(tcp_server_fd <= 0) {
	          perror("Error in 'accept()': TCP welcoming Socket");
	        }
	
					// change the descriptor to that of tcp_server_fd
					// from now on, tcp_server_fd will be used
					fds_poll[2].fd = tcp_server_fd;
					if(tcp_server_fd > maxfd)
	          maxfd = tcp_server_fd;
					
					do_debug(1,"TCP connection started by the client. Socket for connecting to the client: %d\n", tcp_server_fd);				
	
				}
				
				/*****************************************************************************/
				/***************** NET to tun. demux and decompress **************************/
				/*****************************************************************************/
	
				// data arrived at the network interface: read, demux, decompress and forward it
				// in TCP_SERVER_MODE, I will only enter here if the TCP connection is already started
				// in the rest of modes, I will enter here if a muxed packet has arrived				
				else if ( (fds_poll[2].revents & POLLIN) && 
									(((*mode == TCP_SERVER_MODE) && (accepting_tcp_connections == 0))  ||
									(*mode == NETWORK_MODE) || 
									(*mode == UDP_MODE) ||
									(*mode == TCP_CLIENT_MODE) ) )
				{
					is_multiplexed_packet = -1;
	
					if (*mode == UDP_MODE) {
						// a packet has been received from the network, destined to the multiplexing port
						// 'slen' is the length of the IP address
						// I cannot use 'remote' because it would replace the IP address and port. I use 'received'
						nread_from_net = recvfrom ( udp_mode_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&received, &slen );
						if (nread_from_net==-1) {
							perror ("recvfrom() UDP error");
						}
						// now buffer_from_net contains the payload (simplemux headers and multiplexled packets/frames) of a full packet or frame.
						// I don't have the IP and UDP headers
	
						// check if the packet comes from the multiplexing port (default 55555). (Its destination IS the multiplexing port)
						if (port == ntohs(received.sin_port)) 
							 is_multiplexed_packet = 1;
						else
							is_multiplexed_packet = 0;
					}
	
					else if (*mode == NETWORK_MODE) {
						// a packet has been received from the network, destined to the local interface for muxed packets
						nread_from_net = cread ( network_mode_fd, buffer_from_net_aux, BUFSIZE);
	
						if (nread_from_net==-1) perror ("cread demux()");
						// now buffer_from_net contains the headers (IP and Simplemux) and the payload of a full packet or frame.
	
						// copy from "buffer_from_net_aux" everything except the IP header (usually the first 20 bytes)
						memcpy ( buffer_from_net, buffer_from_net_aux + sizeof(struct iphdr), nread_from_net - sizeof(struct iphdr));
						// correct the size of "nread from net"
						nread_from_net = nread_from_net - sizeof(struct iphdr);
	
						// Get IP Header of received packet
						GetIpHeader(&ipheader,buffer_from_net_aux);
						if (ipheader.protocol == IPPROTO_SIMPLEMUX )
							is_multiplexed_packet = 1;
						else
							is_multiplexed_packet = 0;
					}
	
					else if (*mode == TCP_CLIENT_MODE) {
						// a packet has been received from the network, destined to the TCP socket
	
						/* Once the sockets are connected, client can read it
						 * through normal read call on the its socket descriptor.
						 */
						nread_from_net = read(tcp_client_fd, buffer_from_net, sizeof(buffer_from_net));
					
						if(nread_from_net < 0)	{
							perror("read() error TCP mode");
						}
						else if(nread_from_net == 0) {
							is_multiplexed_packet = -1;
						}
						else {
							do_debug(0,"Read %d bytes from the TCP socket\n", nread_from_net);					 //FIXME: this should say '3'					
						
							// as I am reading from the TCP socket, this is a multiplexed packet
							is_multiplexed_packet = 1;
						}
						
						// now buffer_from_net contains the payload (simplemux headers and multiplexled packets/frames) of a full packet or frame.
						// I don't have the TCP headers
					}
	
					else if (*mode == TCP_SERVER_MODE) {		
						// a packet has been received from the network, destined to the TCP socket
						
						/* Once the sockets are connected, client can read it
						 * through normal read call on the its socket descriptor.
						 */
						nread_from_net = read(tcp_server_fd, buffer_from_net, sizeof(buffer_from_net));
					
						if(nread_from_net < 0)	{
							perror("read() error TCP server mode");
						}
						else if(nread_from_net == 0) {
							is_multiplexed_packet = -1;
						}
						else {
							do_debug(0,"Read %d bytes from the TCP socket\n", nread_from_net);			 //FIXME: this should say '3'			
							// as I am reading from the TCP socket, this is a multiplexed packet
							is_multiplexed_packet = 1;
						}
						
						// now buffer_from_net contains the payload (simplemux headers and multiplexled packets/frames) of a full packet or frame.
						// I don't have the TCP headers
					}
			
					else {
						// error: unknown mode				
					}
	
					// now buffer_from_net contains a full packet or frame.
					// check if the packet is a multiplexed one
					if (is_multiplexed_packet == -1) {
						// I have read nothing
					}
					
					else if (is_multiplexed_packet == 1) {
	
						/* increase the counter of the number of packets read from the network */
						net2tun++;
						switch (*mode) {
							case UDP_MODE:
								do_debug(1, "MUXED PACKET #%lu: Read UDP muxed packet from %s:%d: %i bytes\n", net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );				
	
								// write the log file
								if ( log_file != NULL ) {
									fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
									fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
								}
							break;
	
							case TCP_CLIENT_MODE:
								do_debug(1, "MUXED PACKET #%lu: Read TCP muxed packet from %s:%d: %i bytes\n", net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), nread_from_net + IPv4_HEADER_SIZE + TCP_HEADER_SIZE );				
	
								// write the log file
								if ( log_file != NULL ) {
									fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
									fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
								}
							break;
	
							case TCP_SERVER_MODE:
								do_debug(1, "MUXED PACKET #%lu: Read TCP muxed packet from %s:%d: %i bytes\n", net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), nread_from_net + IPv4_HEADER_SIZE + TCP_HEADER_SIZE );				
	
								// write the log file
								if ( log_file != NULL ) {
									fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, net2tun, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
									fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
								}
							break;
	
							case NETWORK_MODE:
								do_debug(1, "MUXED PACKET #%lu: Read IP muxed packet from %s: %i bytes\n", net2tun, inet_ntoa(remote.sin_addr), nread_from_net + IPv4_HEADER_SIZE );				
	
								// write the log file
								if ( log_file != NULL ) {
									fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%lu\tfrom\t%s\t\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE, net2tun, inet_ntoa(remote.sin_addr));
									fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
								}
							break;
						}
	
						// if the packet comes from the multiplexing port, I have to demux it and write each packet to the tun / tap interface
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
										do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
										position ++;
									}
									else {	// SIZE_PROTOCOL_FIELD == 2
										protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
										do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
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
									}
									else {
										single_protocol_rec = 0;
									}
	
									// as this is a first header, the length extension bit is the second one, and the 
									// maximum length of a single-byte packet is 64 bytes
									LXT_position = 6;
									maximum_packet_length = 64;
	
									// if I am here, it means that I have read the first separator
									first_header_read = 1;
								}
	
								else {
									// Non-first header
	
									if (single_protocol_rec == 1) {
										// all the packets belong to the same protocol, so the first byte belongs to the Mux separator, so I check it
										FromByte(buffer_from_net[position], bits);
									}
									else {
										// each packet belongs to a different protocol, so the first thing I find is the 'Protocol' field
										// and the second one belongs to the Mux separator, so I check it
										if ( SIZE_PROTOCOL_FIELD == 1 ) {
											protocol_rec = buffer_from_net[position];
											if(single_protocol_rec == 0)
												do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
											position ++;
										}
										else {	// SIZE_PROTOCOL_FIELD == 2
											protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
											if(single_protocol_rec == 0)
												do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
											position = position + 2;
										}
	
										// get the value of the bits of the first byte
										// as this is a non-first header:
										//	- LXT will be stored in 'bits[7]'
										FromByte(buffer_from_net[position], bits);
									}
	
									// as this is a non-first header, the length extension bit is the first one (7), and the
									// maximum length of a single-byte packet is 128 bytes
									LXT_position = 7;
									maximum_packet_length = 128;
								}
	
								// I have demuxed another packet
								num_demuxed_packets ++;
								//do_debug(2, "\n");
	
								do_debug(1, " DEMUXED PACKET #%i", num_demuxed_packets);
								//if ((debug == 1) && (ROHC_mode == 0) ) do_debug (1,"\n");
								do_debug(2, ": ");
	
								// read the length
								// Check the LXT (length extension) bit.
								// if this is a first header, the length extension bit is the second one (6), and the maximum
								// length of a single-byte packet is 64 bytes
	
								if (bits[LXT_position]== false) {
									// if the LXT bit is 0, it means that the separator is one-byte
									// I have to convert the six less significant bits to an integer, which means the length of the packet
									// since the two most significant bits are 0, the length is the value of the char
									packet_length = buffer_from_net[position] % maximum_packet_length;
									do_debug(2, " Mux separator of 1 byte: 0x%02x ", buffer_from_net[position]);
									PrintByte(2, 8, bits);
	
									position ++;
								}
	
								else {
									// if the second bit (LXT) of the first byte is 1, it means that the separator is not one-byte
	
									// check the bit 7 of the second byte
									FromByte(buffer_from_net[position+1], bits);
	
									// If the LXT bit is 0, this is a two-byte length
									if (bits[7] == 0) {
	
										// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
										// I do the product by 128, because the next byte includes 7 bits of the length
										packet_length = ((buffer_from_net[position] % maximum_packet_length) * 128 );
	
										// I add the value of the 7 less significant bits of the second byte
										packet_length = packet_length + (buffer_from_net[position+1] % 128);
	
										if (debug ) {
											do_debug(2, " Mux separator of 2 bytes: 0x%02x ", buffer_from_net[position]);
											PrintByte(2, 8, bits);
											FromByte(buffer_from_net[position+1], bits);
											do_debug(2, " 0x%02x ",buffer_from_net[position+1]);
											PrintByte(2, 8, bits);	
										}					
										position = position + 2;
									}
	
									// If the LXT bit is 1, this is a three-byte length
									else {
										// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
										// I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
										packet_length = ((buffer_from_net[position] % maximum_packet_length) * 16384 );
	
										// I get the 6 (or 7) less significant bits of the second byte by using modulo 128
										// I do the product by 128, because the next byte includes 7 bits of the length
										packet_length = packet_length + ((buffer_from_net[position+1] % 128) * 128 );
	
										// I add the value of the 7 less significant bits of the second byte
										packet_length = packet_length + (buffer_from_net[position+2] % 128);
	
										if (debug ) {
											do_debug(2, " Mux separator of 2 bytes: 0x%02x (", buffer_from_net[position]);
											PrintByte(2, 8, bits);
											FromByte(buffer_from_net[position+1], bits);
											do_debug(2, ") 0x%02x (",buffer_from_net[position+1]);
											PrintByte(2, 8, bits);	
											FromByte(buffer_from_net[position+2], bits);
											do_debug(2, ") %02x (",buffer_from_net[position+2]);
											PrintByte(2, 8, bits);
											do_debug(2, ")");
										}					
										position = position + 3;
									}
								}
	
								do_debug(1, ". Demuxed %i bytes\n", packet_length);
							}
							else { 	// 'Protocol' field goes after the separator
	
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
									}
									else {
										single_protocol_rec = 0;
									}
	
									// as this is a first header, the length extension bit is the second one, and the 
									// maximum length of a single-byte packet is 64 bytes
									LXT_position = 6;
									maximum_packet_length = 64;
								}
	
								else {	// Non-first header
									// get the value of the bits of the first byte
									// as this is a non-first header:
									//	- LXT will be stored in 'bits[7]'
									FromByte(buffer_from_net[position], bits);
								
									// as this is a non-first header, the length extension bit is the first one (7), and the
									// maximum length of a single-byte packet is 128 bytes
									LXT_position = 7;
									maximum_packet_length = 128;
								}
	
								// I have demuxed another packet
								num_demuxed_packets ++;
								//do_debug(2, "\n");
	
								do_debug(1, " DEMUXED PACKET #%i", num_demuxed_packets);
								do_debug(2, ": ");
	
								// read the length
								// Check the LXT (length extension) bit.
								if (bits[LXT_position]== false) {
									// if the LXT bit is 0, it means that the separator is one-byte
	
									// I have to convert the 6 (or 7) less significant bits to an integer, which means the length of the packet
									// since the two most significant bits are 0, the length is the value of the char
									packet_length = buffer_from_net[position] % maximum_packet_length;
									do_debug(2, " Mux separator of 1 byte: 0x%02x (", buffer_from_net[position]);
									PrintByte(2, 8, bits);
									do_debug(2, ")");
									position ++;
								}
	
								else {
									// if the second bit (LXT) of the first byte is 1, it means that the separator is not one-byte
	
									// check the bit 7 of the second byte
									FromByte(buffer_from_net[position+1], bits);
	
									// If the LXT bit is 0, this is a two-byte length
									if (bits[7] == 0) {
										// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
										// I do the product by 128, because the next byte includes 7 bits of the length
										packet_length = ((buffer_from_net[position] % maximum_packet_length) * 128 );
	
										// I add the value of the 7 less significant bits of the second byte
										packet_length = packet_length + (buffer_from_net[position+1] % 128);
	
										if (debug ) {
											do_debug(2, " Mux separator of 2 bytes: 0x%02x (", buffer_from_net[position]);
											PrintByte(2, 8, bits);
											FromByte(buffer_from_net[position+1], bits);
											do_debug(2, ") 0x%02x (",buffer_from_net[position+1]);
											PrintByte(2, 8, bits);
											do_debug(2,")");
										}					
										position = position + 2;
									}
	
									// If the LXT bit of the second byte is 1, this is a three-byte length
									else {
										// I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
										// I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
										packet_length = ((buffer_from_net[position] % maximum_packet_length) * 16384 );
	
										// I get the 6 (or 7) less significant bits of the second byte by using modulo 128
										// I do the product by 128, because the next byte includes 7 bits of the length
										packet_length = packet_length + ((buffer_from_net[position+1] % 128) * 128 );
	
										// I add the value of the 7 less significant bits of the second byte
										packet_length = packet_length + (buffer_from_net[position+2] % 128);
	
										if (debug ) {
											do_debug(2, " Mux separator of 2 bytes: 0x%02x ", buffer_from_net[position]);
											PrintByte(2, 8, bits);
											FromByte(buffer_from_net[position+1], bits);
											do_debug(2, " %02x ",buffer_from_net[position+1]);
											PrintByte(2, 8, bits);	
											FromByte(buffer_from_net[position+2], bits);
											do_debug(2, " %02x ",buffer_from_net[position+2]);
											PrintByte(2, 8, bits);
										}					
										position = position + 3;
									}
								}
	
								// check if this is the first separator or not
								if (first_header_read == 0) {		// this is the first separator. The protocol field will always be present
									// the next thing I expect is a 'protocol' field
									if ( SIZE_PROTOCOL_FIELD == 1 ) {
										protocol_rec = buffer_from_net[position];
										do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
										position ++;
									}
									else {	// SIZE_PROTOCOL_FIELD == 2
										protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
										do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
										position = position + 2;
									}
	
									// if I am here, it means that I have read the first separator
									first_header_read = 1;
	
								}
								else {			// non-first separator. The protocol field may or may not be present
									if ( single_protocol_rec == 0 ) {
										// each packet belongs to a different protocol, so the first thing is the 'Protocol' field
										if ( SIZE_PROTOCOL_FIELD == 1 ) {
											protocol_rec = buffer_from_net[position];
											if(single_protocol_rec == 0)
												do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
											position ++;
										}
										else {	// SIZE_PROTOCOL_FIELD == 2
											protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
											if(single_protocol_rec == 0)
												do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
											position = position + 2;
										}
									}
								}
								do_debug(1, ". Demuxed %i bytes\n", packet_length);
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
									// the packet is bad so I add a line
									fprintf (log_file, "%"PRIu64"\terror\tdemux_bad_length\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun );	
									fflush(log_file);
								}						
							}
							
							else {
	
								/************ decompress the packet ***************/
	
								// if the number of the protocol is NOT 142 (ROHC) I do not decompress the packet
								if ( protocol_rec != IPPROTO_ROHC ) {
									// non-compressed packet
									// dump the received packet on terminal
									if (debug) {
										//do_debug(1, " Received ");
										do_debug(2, "   ");
										dump_packet ( packet_length, demuxed_packet );
									}
								}
								else {
									// ROHC-compressed packet
	
									// I cannot decompress the packet if I am in no-ROHC mode
									if ( ROHC_mode == 0 ) {
										do_debug(1," ROHC packet received, but not in ROHC mode. Packet dropped\n");
	
										// write the log file
										if ( log_file != NULL ) {
											fprintf (log_file, "%"PRIu64"\tdrop\tno_ROHC_mode\t%i\t%lu\n", GetTimeStamp(), packet_length, net2tun);	// the packet may be good, but the decompressor is not in ROHC mode
											fflush(log_file);
										}
									}
									else {
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
										if (debug == 1) {
											do_debug(1, " ROHC. ");
										}
										if (debug == 2) {
											do_debug(2, " ");
											do_debug(2, " ROHC packet\n   ");
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
												}
												else {
													do_debug(3, "Feedback from the remote compressor delivered to the compressor: %i bytes\n", rcvd_feedback.len);
												}
											}
											else {
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
													perror("sendto() failed when sending a ROHC packet");
												}
												else {
													do_debug(3, "Feedback generated by the decompressor (%i bytes), sent to the compressor\n", feedback_send.len);
												}
											}
											else {
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
												do_debug(1, "IP packet resulting from the ROHC decompression: %i bytes\n", packet_length);
												do_debug(2, "   ");
	
												if (debug) {
													// dump the decompressed IP packet on terminal
													dump_packet (ip_packet_d.len, ip_packet_d.data );
												}
											}
											else {
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
											do_debug(1, "  decompression of ROHC packet failed. No context\n");
											//fprintf(stderr, "  decompression of ROHC packet failed. No context\n");
	
											// write the log file
											if ( log_file != NULL ) {
												// the packet is bad
												fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
												fflush(log_file);
											}
										}
	
										else if ( status == ROHC_STATUS_OUTPUT_TOO_SMALL ) {	// the output buffer is too small for the compressed packet
	
											// failure: decompressor failed to decompress the ROHC packet 
											do_debug(1, "  decompression of ROHC packet failed. Output buffer is too small\n");
											//fprintf(stderr, "  decompression of ROHC packet failed. Output buffer is too small\n");
	
											// write the log file
											if ( log_file != NULL ) {
												// the packet is bad
												fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Output buffer is too small\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
												fflush(log_file);
											}
										}
	
										else if ( status == ROHC_STATUS_MALFORMED ) {			// the decompression failed because the ROHC packet is malformed 
	
											// failure: decompressor failed to decompress the ROHC packet 
											do_debug(1, "  decompression of ROHC packet failed. No context\n");
											//fprintf(stderr, "  decompression of ROHC packet failed. No context\n");
	
											// write the log file
											if ( log_file != NULL ) {
												// the packet is bad
												fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. No context\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
												fflush(log_file);
											}
										}
	
										else if ( status == ROHC_STATUS_BAD_CRC ) {			// the CRC detected a transmission or decompression problem
	
											// failure: decompressor failed to decompress the ROHC packet 
											do_debug(1, "  decompression of ROHC packet failed. Bad CRC\n");
											//fprintf(stderr, "  decompression of ROHC packet failed. Bad CRC\n");
	
											// write the log file
											if ( log_file != NULL ) {
												// the packet is bad
												fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Bad CRC\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
												fflush(log_file);
											}
										}
	
										else if ( status == ROHC_STATUS_ERROR ) {				// another problem occurred
	
											// failure: decompressor failed to decompress the ROHC packet 
											do_debug(1, "  decompression of ROHC packet failed. Other error\n");
											//fprintf(stderr, "  decompression of ROHC packet failed. Other error\n");
	
											// write the log file
											if ( log_file != NULL ) {
												// the packet is bad
												fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Other error\t%i\t%lu\n", GetTimeStamp(), nread_from_net, net2tun);	
												fflush(log_file);
											}
										}
									}
								}
								/*********** end decompression **************/
	
								// write the demuxed (and perhaps decompressed) packet to the tun interface
								// if compression is used, check that ROHC has decompressed correctly
								if ( ( protocol_rec != IPPROTO_ROHC ) || ((protocol_rec == IPPROTO_ROHC) && ( status == ROHC_STATUS_OK))) {
	
									// print the debug information
									//do_debug(2, "  Protocol: %i ",protocol_rec);
	
									/*switch(protocol_rec) {
										case IPPROTO_IP_ON_IP:
											do_debug (2, "(IP)");
											break;
										case IPPROTO_ROHC:
											do_debug (2, "(ROHC)");
											break;
									}*/
	
									// tun mode
									if(*tunnel_mode == TUN_MODE) {
		 								// write the demuxed packet to the tun interface
										do_debug (2, " Sending packet of %i bytes to the tun interface\n", packet_length);
										cwrite ( tun_fd, demuxed_packet, packet_length );
									}
									// tap mode
									else if(*tunnel_mode == TAP_MODE) {
										if (protocol_rec!= IPPROTO_ETHERNET) {
											do_debug (2, "wrong value of 'Protocol' field received. It should be 143, but it is %i", protocol_rec);							
										}
										else {
			 								// write the demuxed packet to the tap interface
											do_debug (2, " Sending frame of %i bytes to the tap interface\n", packet_length);
											cwrite ( tun_fd, demuxed_packet, packet_length );
										}
									}
									else {
										perror ("wrong value of 'tunnel_mode'");
										exit (EXIT_FAILURE);
									}
									
									do_debug(2, "\n");
									//do_debug(2, "packet length (without separator): %i\n", packet_length);
	
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
						do_debug(1, "NON-MUXED PACKET #%lu: Non-multiplexed packet. Writing %i bytes to tun\n", net2tun, nread_from_net);
						cwrite ( tun_fd, buffer_from_net, nread_from_net);
	
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
	
				//else if ( FD_ISSET ( feedback_fd, &rd_set )) {		/* FD_ISSET tests to see if a file descriptor is part of the set */
				else if(fds_poll[1].revents & POLLIN) {
				
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
	
						// reset the buffer where the packet is to be stored
						rohc_buf_reset (&rohc_packet_d);
	
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
						}
						else {
							do_debug(3, "Feedback delivered to the compressor: %i bytes\n", rohc_packet_d.len);
						}
	
						// the information received does not have to be decompressed, because it has been 
						// generated as feedback on the other side.
						// So I don't have to decompress the packet
					}
					else {
	
						// packet with destination port 55556, but a source port different from the feedback one
						// if the packet does not come from the feedback port, write it directly into the tun interface
						do_debug(1, "NON-FEEDBACK PACKET %lu: Non-feedback packet. Writing %i bytes to tun\n", net2tun, nread_from_net);
						cwrite ( tun_fd, buffer_from_net, nread_from_net);
	
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
	
				/* FD_ISSET tests if a file descriptor is part of the set */
				//else if(FD_ISSET(tun_fd, &rd_set)) {
				else if(fds_poll[0].revents & POLLIN) {
					/* read the packet from tun, store it in the array, and store its size */
					size_packets_to_multiplex[num_pkts_stored_from_tun] = cread (tun_fd, packets_to_multiplex[num_pkts_stored_from_tun], BUFSIZE);
			
					/* increase the counter of the number of packets read from tun*/
					tun2net++;
	
					//if (debug > 1 ) do_debug (2,"\n");
					if (*tunnel_mode == TUN_MODE)
						do_debug(1, "NATIVE PACKET #%lu: Read packet from tun: %i bytes\n", tun2net, size_packets_to_multiplex[num_pkts_stored_from_tun]);
					else if (*tunnel_mode == TAP_MODE)
						do_debug(1, "NATIVE PACKET #%lu: Read packet from tap: %i bytes\n", tun2net, size_packets_to_multiplex[num_pkts_stored_from_tun]);
						
					// print the native packet/frame received
					if (debug) {
						do_debug(2, "   ");
						// dump the newly-created IP packet on terminal
						dump_packet ( size_packets_to_multiplex[num_pkts_stored_from_tun], packets_to_multiplex[num_pkts_stored_from_tun] );
					}
	
					// write in the log file
					if ( log_file != NULL ) {
						fprintf (log_file, "%"PRIu64"\trec\tnative\t%i\t%lu\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
						fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
					}
	
	
					// check if this packet (plus the tunnel and simplemux headers ) is bigger than the MTU. Drop it in that case
					drop_packet = 0;
					if (*mode == UDP_MODE) {
						
						if ( size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3 > selected_mtu ) {
							drop_packet = 1;
	
							do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, selected_mtu);
	
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%lu\tto\t%s\t%d\t%i\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
								fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
							}
						}
					}
					
					// TCP client mode or TCP server mode
					else if ((*mode == TCP_CLIENT_MODE) || (*mode == TCP_SERVER_MODE)) {
						
						if ( size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + TCP_HEADER_SIZE + 3 > selected_mtu ) {
							drop_packet = 1;
	
							do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, selected_mtu);
	
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%lu\tto\t%s\t%d\t%i\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
								fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
							}
						}
					}
					
					// network mode
	 				else {
						if ( size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + 3 > selected_mtu ) {
							drop_packet = 1;
	
							do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + 3, selected_mtu);
	
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%lu\tto\t%s\t%d\t%i\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun] + IPv4_HEADER_SIZE + 3, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
								fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
							}
						}
					}
	
					// the length of the packet is adequate
					if ( drop_packet == 0 ) {
	
	
						/******************** compress the headers if the ROHC option has been set ****************/
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
									protocol[num_pkts_stored_from_tun][0] = IPPROTO_ROHC;
								}
								else {	// SIZE_PROTOCOL_FIELD == 2 
									protocol[num_pkts_stored_from_tun][0] = 0;
									protocol[num_pkts_stored_from_tun][1] = IPPROTO_ROHC;
								}
	
								// Copy the compressed length and the compressed packet over the packet read from tun
								size_packets_to_multiplex[num_pkts_stored_from_tun] = rohc_packet.len;
								for (l = 0; l < size_packets_to_multiplex[num_pkts_stored_from_tun] ; l++) {
									packets_to_multiplex[num_pkts_stored_from_tun][l] = rohc_buf_byte_at(rohc_packet, l);
								}
	
								/* dump the ROHC packet on terminal */
								if (debug >= 1 ) {
									do_debug(1, " ROHC-compressed to %i bytes\n", rohc_packet.len);
								}
								if (debug == 2) {
									do_debug(2, "   ");
									dump_packet ( rohc_packet.len, rohc_packet.data );
								}
	
							}
							else {
								/* compressor failed to compress the IP packet */
								/* Send it in its native form */
	
								// I don't have to copy the native length and the native packet, because they
								// have already been stored in 'size_packets_to_multiplex[num_pkts_stored_from_tun]' and 'packets_to_multiplex[num_pkts_stored_from_tun]'
	
								// since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP'
								// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									protocol[num_pkts_stored_from_tun][0] = IPPROTO_IP_ON_IP;
								}
								else {	// SIZE_PROTOCOL_FIELD == 2 
									protocol[num_pkts_stored_from_tun][0] = 0;
									protocol[num_pkts_stored_from_tun][1] = IPPROTO_IP_ON_IP;
								}
								fprintf(stderr, "compression of IP packet failed\n");
	
								// print in the log file
								if ( log_file != NULL ) {
									fprintf (log_file, "%"PRIu64"\terror\tcompr_failed. Native packet sent\t%i\t%lu\\n", GetTimeStamp(), size_packets_to_multiplex[num_pkts_stored_from_tun], tun2net);
									fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
								}
	
								do_debug(2, "  ROHC did not work. Native packet sent: %i bytes:\n   ", size_packets_to_multiplex[num_pkts_stored_from_tun]);
								//goto release_compressor;
							}
						}
						else {
							// header compression has not been selected by the user
	
							if (*tunnel_mode == TAP_MODE) {
								// tap mode
								
								// since this frame CANNOT be compressed, its protocol number has to be 143: 'Ethernet on IP' 
								// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									protocol[num_pkts_stored_from_tun][0] = IPPROTO_ETHERNET;
								}
								else {	// SIZE_PROTOCOL_FIELD == 2 
									protocol[num_pkts_stored_from_tun][0] = 0;
									protocol[num_pkts_stored_from_tun][1] = IPPROTO_ETHERNET;
								}
							}
							else if (*tunnel_mode == TUN_MODE) {
								// tun mode
								
								// since this IP packet is NOT compressed, its protocol number has to be 4: 'IP on IP' 
								// (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									protocol[num_pkts_stored_from_tun][0] = IPPROTO_IP_ON_IP;
								}
								else {	// SIZE_PROTOCOL_FIELD == 2 
									protocol[num_pkts_stored_from_tun][0] = 0;
									protocol[num_pkts_stored_from_tun][1] = IPPROTO_IP_ON_IP;
								}
							}
							else {
								perror ("wrong value of 'tunnel_mode'");
								exit (EXIT_FAILURE);
							}
						}
	
	
						/*** Calculate if the size limit will be reached when multiplexing the present packet ***/
						// if the addition of the present packet will imply a multiplexed packet bigger than the size limit:
						// - I send the previously stored packets
						// - I store the present one
						// - I reset the period
	
						// calculate if all the packets belong to the same protocol (single_protocol = 1) 
						//or they belong to different protocols (single_protocol = 0)
						single_protocol = 1;
						for (k = 1; k < num_pkts_stored_from_tun ; k++) {
							for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
								if (protocol[k][l] != protocol[k-1][l]) single_protocol = 0;
							}
						}
	
						// calculate the size without the present packet
						predicted_size_muxed_packet = predict_size_multiplexed_packet (num_pkts_stored_from_tun,
																											single_protocol,
																											protocol,
																											size_separators_to_multiplex,
																											separators_to_multiplex,
																											size_packets_to_multiplex,
																											packets_to_multiplex);
	
						// I add the length of the present packet:
	
						// separator and length of the present packet
						if (first_header_written == 0) {
							// this is the first header, so the maximum length is 64
							if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 64 ) {
								predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
							}
							else {
								predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
							}
						}
						else {
							// this is not the first header, so the maximum length is 128
							if (size_packets_to_multiplex[num_pkts_stored_from_tun] < 128 ) {
								predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + size_packets_to_multiplex[num_pkts_stored_from_tun];
							}
							else {
								predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + size_packets_to_multiplex[num_pkts_stored_from_tun];
							}
						}
	
						if (predicted_size_muxed_packet > size_max ) {
							// if the present packet is muxed, the max size of the packet will be overriden. So I first empty the buffer
							//i.e. I build and send a multiplexed packet not including the current one
	
							do_debug(2, "\n");
	
							switch (*mode) {
								case UDP_MODE:
									do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );
								case TCP_CLIENT_MODE:
									do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE );
								case NETWORK_MODE:
									do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE );
								break;
							}
	
							// add the Single Protocol Bit in the first header (the most significant bit)
							// it is '1' if all the multiplexed packets belong to the same protocol
							if (single_protocol == 1) {
								separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
								size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
							}
							else {
								size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
							}
	
							// build the multiplexed packet without the current one
							total_length = build_multiplexed_packet ( num_pkts_stored_from_tun,
																					single_protocol,
																					protocol,
																					size_separators_to_multiplex,
																					separators_to_multiplex,
																					size_packets_to_multiplex,
																					packets_to_multiplex,
																					muxed_packet);
	
							if (single_protocol) {
								do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
							}
							else {
								do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
							}
							
							switch(*tunnel_mode) {
								case TUN_MODE:
									switch (*mode) {
										case UDP_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
											do_debug(1, " Sending to the network a UDP muxed packet without this one: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
										break;
										case TCP_CLIENT_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
										break;
										case TCP_SERVER_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
										break;
										case NETWORK_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
											do_debug(1, " Sending to the network an IP muxed packet without this one: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE );
										break;
									}
								break;
	
								case TAP_MODE:
									switch (*mode) {
										case UDP_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
											do_debug(1, " Sending to the network a UDP packet without this Eth frame: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
										break;
										case TCP_CLIENT_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											do_debug(1, " Sending to the network a TCP packet without this Eth frame: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
										break;
										case TCP_SERVER_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											do_debug(1, " Sending to the network a TCP packet without this Eth frame: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
										break;
										case NETWORK_MODE:
											do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
											do_debug(1, " Sending to the network an IP packet without this Eth frame: %i bytes\n", size_muxed_packet + IPv4_HEADER_SIZE );
										break;
									}
								break;
							}	
	
	
							// send the multiplexed packet without the current one
							switch (*mode) {
								case UDP_MODE:
									// printf ("length: %i", total_length);
	
									// send the packet
									if (sendto(udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) {
										perror("sendto() in UDP mode failed");
										exit (EXIT_FAILURE);
									}
									
									// write in the log file
									if ( log_file != NULL ) {
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
										fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
									}
								break;
	
								case TCP_CLIENT_MODE:
									// printf ("length: %i", total_length);
	
									// send the packet
									if (write(tcp_client_fd, muxed_packet, total_length)==-1) {
										perror("write() in TCP client mode failed");
										exit (EXIT_FAILURE);
									}
									
									// write in the log file
									if ( log_file != NULL ) {
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
										fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
									}
								break;
	
								case TCP_SERVER_MODE:
									// printf ("length: %i", total_length);
	
									if(accepting_tcp_connections == 1) {
										do_debug(1," The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
									}
									else {
										// send the packet
										//if (sendto(tcp_welcoming_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) {
										if (write(tcp_server_fd, muxed_packet, total_length)==-1) {
											perror("write() in TCP server mode failed");
											exit (EXIT_FAILURE);
										}
										// write in the log file
										if ( log_file != NULL ) {
											fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
											fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
										}							
									}
								break;
								
								case NETWORK_MODE:
	
									// build the header
									BuildIPHeader(&ipheader, total_length, local, remote);
	
									// build the full IP multiplexed packet
									BuildFullIPPacket(ipheader, muxed_packet, total_length, full_ip_packet);
	
									// send the packet
									if (sendto (network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&remote, sizeof (struct sockaddr)) < 0)  {
										perror ("sendto() in Network mode failed");
										exit (EXIT_FAILURE);
									}
									// write in the log file
									if ( log_file != NULL ) {
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);
										fflush(log_file);	// If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
									}
								break;
							}
	
	
							// I have sent a packet, so I restart the period: update the time of the last packet sent
							time_in_microsec = GetTimeStamp();
							time_last_sent_in_microsec = time_in_microsec;
	
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
						}
						/*** end check if size limit would be reached ***/
	
	
						// update the size of the muxed packet, adding the size of the current one
						size_muxed_packet = size_muxed_packet + size_packets_to_multiplex[num_pkts_stored_from_tun];
	
						// I have to add the multiplexing separator.
						//   - It is 1 byte if the length is smaller than 64 (or 128 for non-first separators) 
						//   - It is 2 bytes if the length is 64 (or 128 for non-first separators) or more
						//   - It is 3 bytes if the length is 8192 (or 16384 for non-first separators) or more
						if (first_header_written == 0) {
							// this is the first header
							maximum_packet_length = 64;
							limit_length_two_bytes = 8192;
						}
						else {
							// this is a non-first header
							maximum_packet_length = 128;
							limit_length_two_bytes = 16384;
						}
	
						// check if the length has to be one, two or three bytes
						// I am assuming that a packet will never be bigger than 1048576 (2^20) bytes for a first header,
						// or 2097152 (2^21) bytes for a non-first one)
	
						// one-byte separator
						if (size_packets_to_multiplex[num_pkts_stored_from_tun] < maximum_packet_length ) {
	
							// the length can be written in the first byte of the separator
							// it can be expressed in 
							//	- 6 bits for the first separator
							// - 7 bits for non-first separators
							size_separators_to_multiplex[num_pkts_stored_from_tun] = 1;
	
							// add the 'length' field to the packet
							// since the value is < maximum_packet_length, the most significant bits will always be 0:
							// - first separator: the value will be expressed in 6 bits
							// - non-first separator: the value will be expressed in 7 bits
							separators_to_multiplex[num_pkts_stored_from_tun][0] = size_packets_to_multiplex[num_pkts_stored_from_tun];
	
							// increase the size of the multiplexed packet
							size_muxed_packet ++;
	
							// print the Mux separator (only one byte)
							if(debug) {
								FromByte(separators_to_multiplex[num_pkts_stored_from_tun][0], bits);
								//do_debug(2, " Mux separator of 1 byte: (0x%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
								
								do_debug(2, " Mux separator of 1 byte (plus Protocol): ");
								if (first_header_written == 0) {
									PrintByte(2, 7, bits);			// first header
									do_debug(2, "(SPB field not included)\n");
								}
								else {
									PrintByte(2, 8, bits);			// non-first header
									do_debug(2, "\n");
								}
							}
						}
						
						// two-byte separator
						else if (size_packets_to_multiplex[num_pkts_stored_from_tun] < limit_length_two_bytes ) {
	
							// the length requires a two-byte separator (length expressed in 13 or 14 bits)
							size_separators_to_multiplex[num_pkts_stored_from_tun] = 2;
	
							// first byte of the Mux separator
							// It can be:
							// - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
							// - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
							// get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
							// add 64 (or 128) in order to put a '1' in the second (or first) bit
							
							// fill the LXT field of the first byte
							// first header
							if (first_header_written == 0) {
								// add 64 (0100 0000) to the header, i.e., set the value of LXT to '1' (7th bit)
								separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 128 ) + 64;	// first header
							}
							// non-first header
							else {
								// add 128 (1000 0000) to the header, i.e., set the value of LXT to '1' (8th bit)
								separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 128 ) + 128;	// non-first header
							}
	
	
							// second byte of the Mux separator
	
							// Length: the 7 less significant bytes of the length. Use modulo 128
							separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 128;
	
							// fill the LXT field of the second byte
							// LXT bit has to be set to 0, because this is the last byte of the length
							// if I do nothing, it will be 0, since I have used modulo 128
	
							// SPB field will be filled later
							
							// increase the size of the multiplexed packet
							size_muxed_packet = size_muxed_packet + 2;
	
							// print the two bytes of the separator
							if(debug) {
								// first byte
								FromByte(separators_to_multiplex[0][num_pkts_stored_from_tun], bits);
								//do_debug(2, " Mux separator of 2 bytes: (0x%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
								do_debug(2, " Mux separator of 2 bytes (plus Protocol). First byte: ");
								if (first_header_written == 0) {
									PrintByte(2, 7, bits);			// first header
									do_debug(2, " (SPB field not included). ");
								}
								else {
									PrintByte(2, 8, bits);			// non-first header
									do_debug(2, "");
								}
	
								// second byte
								FromByte(separators_to_multiplex[num_pkts_stored_from_tun][1], bits);
								//do_debug(2, " (0x%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][1]);
								do_debug(2, "second byte: ");
								PrintByte(2, 8, bits);
								do_debug(2, "\n");
							}	
						}
	
						// three-byte separator
						else {
	
							// the length requires a three-byte separator (length expressed in 20 or 21 bits)
							size_separators_to_multiplex[num_pkts_stored_from_tun] = 3;
	
							//FIXME. I have just copied the case of two-byte separator
							// first byte of the Mux separator
							// It can be:
							// - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
							// - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
							// get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
							// add 64 (or 128) in order to put a '1' in the second (or first) bit
	
							if (first_header_written == 0) {
								// first header
								separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 16384 ) + 64;
	
							}
							else {
								// non-first header
								separators_to_multiplex[num_pkts_stored_from_tun][0] = (size_packets_to_multiplex[num_pkts_stored_from_tun] / 16384 ) + 128;	
							}
	
	
							// second byte of the Mux separator
							// Length: the 7 second significant bytes of the length. Use modulo 16384
							separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 16384;
	
							// LXT bit has to be set to 1, because this is not the last byte of the length
							separators_to_multiplex[num_pkts_stored_from_tun][0] = separators_to_multiplex[num_pkts_stored_from_tun][0] + 128;
	
	
							// third byte of the Mux separator
							// Length: the 7 less significant bytes of the length. Use modulo 128
							separators_to_multiplex[num_pkts_stored_from_tun][1] = size_packets_to_multiplex[num_pkts_stored_from_tun] % 128;
	
							// LXT bit has to be set to 0, because this is the last byte of the length
							// if I do nothing, it will be 0, since I have used modulo 128
	
	
							// increase the size of the multiplexed packet
							size_muxed_packet = size_muxed_packet + 3;
	
							// print the three bytes of the separator
							if(debug) {
								// first byte
								FromByte(separators_to_multiplex[0][num_pkts_stored_from_tun], bits);
								do_debug(2, " Mux separator of 2 bytes: (0x%02x) ", separators_to_multiplex[0][num_pkts_stored_from_tun]);
								if (first_header_written == 0) {
									PrintByte(2, 7, bits);			// first header
								}
								else {
									PrintByte(2, 8, bits);			// non-first header
								}
	
								// second byte
								FromByte(separators_to_multiplex[num_pkts_stored_from_tun][1], bits);
								do_debug(2, " (0x%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][1]);
								PrintByte(2, 8, bits);
								do_debug(2, "\n");
	
								// third byte
								FromByte(separators_to_multiplex[num_pkts_stored_from_tun][2], bits);
								do_debug(2, " (0x%02x) ", separators_to_multiplex[num_pkts_stored_from_tun][2]);
								PrintByte(2, 8, bits);
								do_debug(2, "\n");
							}
						}
	
	
						// I have finished storing the packet, so I increase the number of stored packets
						num_pkts_stored_from_tun ++;
	
						// I have written a header of the multiplexed bundle, so I have to set to 1 the "first header written bit"
						if (first_header_written == 0) first_header_written = 1;
	
						//do_debug (1,"\n");
						do_debug(1, " Packet stopped and multiplexed: accumulated %i pkts: %i bytes.", num_pkts_stored_from_tun , size_muxed_packet);
						time_in_microsec = GetTimeStamp();
						time_difference = time_in_microsec - time_last_sent_in_microsec;		
						do_debug(1, " Time since last trigger: %" PRIu64 " usec\n", time_difference);//PRIu64 is used for printing uint64_t numbers
	
	
						// check if a multiplexed packet has to be sent
	
						// if the packet limit or the size threshold are reached, send all the stored packets to the network
						// do not worry about the MTU. if it is reached, a number of packets will be sent
						if ((num_pkts_stored_from_tun == limit_numpackets_tun) || (size_muxed_packet > size_threshold) || (time_difference > timeout )) {
	
							// a multiplexed packet has to be sent
	
							// fill the SPB field (Single Protocol Bit)
							
							// calculate if all the packets belong to the same protocol
							single_protocol = 1;
							for (k = 1; k < num_pkts_stored_from_tun ; k++) {
								for ( l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
									if (protocol[k][l] != protocol[k-1][l])
										single_protocol = 0;
								}
							}
	
							// Add the Single Protocol Bit in the first header (the most significant bit)
							// It is 1 if all the multiplexed packets belong to the same protocol
							if (single_protocol == 1) {
								separators_to_multiplex[0][0] = separators_to_multiplex[0][0] + 128;	// this puts a 1 in the most significant bit position
								size_muxed_packet = size_muxed_packet + 1;								// one byte corresponding to the 'protocol' field of the first header
							}
							else {
								size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;	// one byte per packet, corresponding to the 'protocol' field
							}
	
							// write the debug information
							if (debug) {
								do_debug(2, "\n");
								do_debug(1, "SENDING TRIGGERED: ");
								if (num_pkts_stored_from_tun == limit_numpackets_tun)
									do_debug(1, "num packet limit reached\n");
								if (size_muxed_packet > size_threshold)
									do_debug(1," size threshold reached\n");
								if (time_difference > timeout)
									do_debug(1, "timeout reached\n");
	
								if ( SIZE_PROTOCOL_FIELD == 1 ) {
									if (single_protocol) {
										do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte (0x%02x) in the first separator\n", protocol[0][0]);
									}
									else {
										do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
									}
								}
								else {	// SIZE_PROTOCOL_FIELD == 2
									if (single_protocol) {
										do_debug(2, "   All packets belong to the same protocol. Added 2 Protocol bytes (0x%02x%02x) in the first separator\n", protocol[0][0], protocol[0][1]);
									}
									else {
										do_debug(2, "   Not all packets belong to the same protocol. Added 2 Protocol bytes in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
									}
								}
								
								switch(*tunnel_mode) {
									case TUN_MODE:
										switch (*mode) {
											case UDP_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
												do_debug(1, " Sending to the network a UDP packet containing %i native one(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
											break;
											case TCP_CLIENT_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
												do_debug(1, " Sending to the network a TCP packet containing %i native one(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											break;
											case TCP_SERVER_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
												do_debug(1, " Sending to the network a TCP packet containing %i native one(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											break;
											case NETWORK_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
												do_debug(1, " Sending to the network an IP packet containing %i native one(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE );
											break;
										}
									break;
									
									case TAP_MODE:
										switch (*mode) {
											case UDP_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
												do_debug(1, " Sending to the network a UDP packet containing %i native Eth frame(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
											break;
											case TCP_CLIENT_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
												do_debug(1, " Sending to the network a TCP packet containing %i native Eth frame(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											break;
											case TCP_SERVER_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
												do_debug(1, " Sending to the network a TCP packet containing %i native Eth frame(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
											break;
											case NETWORK_MODE:
												do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
												do_debug(1, " Sending to the network an IP packet containing %i native Eth frame(s): %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE );
											break;
										}
									break;
								}			
							}
	
							// build the multiplexed packet including the current one
							total_length = build_multiplexed_packet ( num_pkts_stored_from_tun,
																					single_protocol,
																					protocol,
																					size_separators_to_multiplex,
																					separators_to_multiplex,
																					size_packets_to_multiplex,
																					packets_to_multiplex,
																					muxed_packet);
	
							// send the multiplexed packet
							switch (*mode) {
								case UDP_MODE:
									// send the packet. I don't need to build the header, because I have a UDP socket
									if (sendto(udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) {
										perror("sendto() in UDP mode failed");
										exit (EXIT_FAILURE);								
									}
									else {
										if(*tunnel_mode == TUN_MODE) {
											do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", num_pkts_stored_from_tun);
										}
										else if(*tunnel_mode == TAP_MODE) {
											do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", num_pkts_stored_from_tun);										
										}
										else {
											perror ("wrong value of 'tunnel_mode'");
											exit (EXIT_FAILURE);
										}
									}
								break;
								
								case NETWORK_MODE:
									// build the header
									BuildIPHeader(&ipheader, total_length, local,remote);
	
									// build full IP multiplexed packet
									BuildFullIPPacket(ipheader, muxed_packet, total_length, full_ip_packet);
	
									// send the multiplexed packet
									if (sendto (network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&remote, sizeof (struct sockaddr)) < 0)  {
										perror ("sendto() in Network mode failed ");
										exit (EXIT_FAILURE);
									}
									else {
										if(*tunnel_mode == TUN_MODE) {
											do_debug(2, "Packet sent (includes %d muxed packet(s))\n\n", num_pkts_stored_from_tun);
										}
										else if(*tunnel_mode == TAP_MODE) {
											do_debug(2, "Packet sent (includes %d muxed frame(s))\n\n", num_pkts_stored_from_tun);
										}
										else {
											perror ("wrong value of 'tunnel_mode'");
											exit (EXIT_FAILURE);
										}
									}
								break;
									
								case TCP_CLIENT_MODE:
									// send the packet. I don't need to build the header, because I have a TCP socket
									
									if (write(tcp_client_fd, muxed_packet, total_length)==-1) {
										perror("write() in TCP client mode failed");
										exit (EXIT_FAILURE);
									}
									else {
										if(*tunnel_mode == TUN_MODE) {
											do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", num_pkts_stored_from_tun);
										}
										else if(*tunnel_mode == TAP_MODE) {
											do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", num_pkts_stored_from_tun);										
										}
										else {
											perror ("wrong value of 'tunnel_mode'");
											exit (EXIT_FAILURE);
										}
									}
								break;
	
								case TCP_SERVER_MODE:
									// send the packet. I don't need to build the header, because I have a TCP socket
									
									// check if the connection has already been established by the client
									if(accepting_tcp_connections == 1) {
										do_debug(1," The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
									}
									else {
										if (write(tcp_server_fd, muxed_packet, total_length)==-1) {
											perror("write() in TCP server mode failed");
											exit (EXIT_FAILURE);
										}
										else {
											if(*tunnel_mode == TUN_MODE) {
												do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", num_pkts_stored_from_tun);
											}
											else if(*tunnel_mode == TAP_MODE) {
												do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", num_pkts_stored_from_tun);										
											}
											else {
												perror ("wrong value of 'tunnel_mode'");
												exit (EXIT_FAILURE);
											}
										}
									}
								break;
							}
	
							// write the log file
							if ( log_file != NULL ) {
								switch (*mode) {
									case UDP_MODE:
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
									break;
									case TCP_CLIENT_MODE:
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t%d\t%i", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
									break;
									case NETWORK_MODE:
										fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);
									break;
								}
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
	
							// restart the period: update the time of the last packet sent
							time_last_sent_in_microsec = time_in_microsec;
						}
					}
				}
	

				}	
			/*************************************************************************************/	
			/******************** Period expired: multiplex **************************************/
			/*************************************************************************************/	

			// The period has expired
			// Check if there is something stored, and send it
			// since there is no new packet, here it is not necessary to compress anything

			else {  // fd2read == 0
				//do_debug(2, "Period expired\n");
				time_in_microsec = GetTimeStamp();
				if ( num_pkts_stored_from_tun > 0 ) {

					// There are some packets stored

					// calculate the time difference
					time_difference = time_in_microsec - time_last_sent_in_microsec;		

					if (debug) {
						do_debug(2, "\n");
						do_debug(1, "SENDING TRIGGERED. Period expired. Time since last trigger: %" PRIu64 " usec\n", time_difference);
						if (single_protocol) {
							do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
						}
						else {
							do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",num_pkts_stored_from_tun);
						}
						switch (*mode) {
							case UDP_MODE:
								do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
								do_debug(1, " Writing %i packets to network: %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);	
							break;
							case TCP_CLIENT_MODE:
								do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
								do_debug(1, " Writing %i packets to network: %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);	
							break;
							case NETWORK_MODE:
								do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
								do_debug(1, " Writing %i packets to network: %i bytes\n", num_pkts_stored_from_tun, size_muxed_packet + IPv4_HEADER_SIZE );
							break;
						}
					}

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
					}
					else {
						size_muxed_packet = size_muxed_packet + num_pkts_stored_from_tun;		// one byte per packet, corresponding to the 'protocol' field
					}

					// build the multiplexed packet
					total_length = build_multiplexed_packet ( num_pkts_stored_from_tun,
																			single_protocol,
																			protocol,
																			size_separators_to_multiplex,
																			separators_to_multiplex,
																			size_packets_to_multiplex,
																			packets_to_multiplex,
																			muxed_packet);

					// send the multiplexed packet
					switch (*mode) {
						
						case NETWORK_MODE:
							// build the header
							BuildIPHeader(&ipheader, total_length, local,remote);

							// build the full IP multiplexed packet
							BuildFullIPPacket(ipheader,muxed_packet,total_length, full_ip_packet);

							// send the packet
							if (sendto (network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *) &remote, sizeof (struct sockaddr)) < 0)  {
								perror ("sendto() failed ");
								exit (EXIT_FAILURE);
							}
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);	
							}
						break;
						
						case UDP_MODE:
							// send the packet. I don't need to build the header, because I have a UDP socket	
							if (sendto(udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&remote, sizeof(remote))==-1) {
								perror("sendto()");
								exit (EXIT_FAILURE);
							}
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);	
							}
						break;

						case TCP_SERVER_MODE:
							// send the packet. I don't need to build the header, because I have a TCP socket							
							if (write(tcp_welcoming_fd, muxed_packet, total_length)==-1) {
								perror("write() in TCP server mode failed");
								exit (EXIT_FAILURE);	
							}
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);	
							}
						break;

						case TCP_CLIENT_MODE:
							// send the packet. I don't need to build the header, because I have a TCP socket	
							if (write(tcp_client_fd, muxed_packet, total_length)==-1) {
								perror("write() in TCP client mode failed");
								exit (EXIT_FAILURE);	
							}
							// write the log file
							if ( log_file != NULL ) {
								fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%lu\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);	
							}
						break;
					}
			
					// I have sent a packet, so I set to 0 the "first_header_written" bit
					first_header_written = 0;

					// reset the length and the number of packets
					size_muxed_packet = 0 ;
					num_pkts_stored_from_tun = 0;

				}
				else {
					// No packet arrived
					//do_debug(2, "Period expired. Nothing to be sent\n");
				}

				// restart the period
				time_last_sent_in_microsec = time_in_microsec;

			}
		}	// end while(1)

		/** POLL **/
	  // free the variables
	  free(fds_poll);
	  /** END POLL **/

		return(0);
	}


/******* labels ************/
release_compressor:
	rohc_comp_free(compressor);

release_decompressor:
	rohc_decomp_free(decompressor);

error:
	fprintf(stderr, "an error occurred during program execution, "
		"abort program\n");
	if ( log_file != NULL ) fclose (log_file);
	return 1;
}


static int gen_random_num(const struct rohc_comp *const comp,
							void *const user_context)
{
	return rand();
}
