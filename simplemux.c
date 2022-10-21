/**************************************************************************
 * simplemux.c            version 2.1                                   *
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
 *          - in an IPv4 packet with protocol 253 or 254 (network mode)   *
 *          - in an IPv4/UDP packet (transport mode). Port 55555 or 55557 *
 *          - in an IPv4/TCP packet (transport mode). Port 55555 or 55557 *
 *                                                                        *
 * IPv6 is not supported in this implementation                           *
 *                                                                        *
 * Jose Saldana (working at CIRCE Foundation), improved it in 2021-2022   *
 *                                                                        *
 * Jose Saldana (working at University of Zaragoza) wrote this program    *
 * in 2015, published under GNU GENERAL                                   *
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

#include "simplemux.h"

/* global variable */
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
static bool rtp_detect(const uint8_t *const ip __attribute__((unused)),
                      const uint8_t *const udp,
                      const uint8_t *const payload __attribute__((unused)),
                      const unsigned int payload_size __attribute__((unused)),
                      void *const rtp_private __attribute__((unused)))
{
  const size_t default_rtp_ports_nr = 5;
  unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
  uint16_t udp_dport;
  bool is_rtp = false;
  size_t i;

  if (udp == NULL) {
    return false;
  }

  /* get the UDP destination port */
  memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

  /* is the UDP destination port in the list of ports reserved for RTP
   * traffic by default (for compatibility reasons) */
  for(i = 0; i < default_rtp_ports_nr; i++) {
    if(ntohs(udp_dport) == default_rtp_ports[i]) {
      is_rtp = true;
      break;
    }
  }

  return is_rtp;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> -e <ifacename> -c <peerIP> -M <'network' or 'udp' or 'tcpclient' or 'tcpserver'> [-T 'tun' or 'tap'] [-p <port>] [-d <debug_level>] [-r <ROHC_option>] [-n <num_mux_tun>] [-m <MTU>] [-B <num_bytes_threshold>] [-t <timeout (microsec)>] [-P <period (microsec)>] [-l <log file name>] [-L] [-f] [-b]\n\n" , progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of tun/tap interface to be used for capturing native packets (mandatory)\n");
  fprintf(stderr, "-e <ifacename>: Name of local interface which IP will be used for reception of muxed packets, i.e., the tunnel local end (mandatory)\n");
  fprintf(stderr, "-c <peerIP>: specify peer destination IP address, i.e. the tunnel remote end (mandatory)\n");
  fprintf(stderr, "-M <mode>: 'network' or 'udp' or 'tcpclient' or 'tcpserver' mode (mandatory)\n");
  fprintf(stderr, "-T <tunnel mode>: 'tun' (default) or 'tap' mode\n");
  fprintf(stderr, "-f: Fast mode (compression rate is lower, but it is faster). Compulsory for TCP mode\n");
  fprintf(stderr, "-b: Blast mode (packets are sent until an application-level ACK is received from the other side). A period (-P) is needed in this case\n");
  fprintf(stderr, "-p <port>: port to listen on, and to connect to (default 55555)\n");
  fprintf(stderr, "-d <debug_level>: Debug level. 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC)\n");
  fprintf(stderr, "-r <ROHC_option>: 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)\n");
  fprintf(stderr, "-n <num_mux_tun>: number of packets received, to be sent to the network at the same time, default 1, max 100\n");
  fprintf(stderr, "-m <MTU>: Maximum Transmission Unit of the network path (by default the one of the local interface is taken)\n");
  fprintf(stderr, "-B <num_bytes_threshold>: size threshold (bytes) to trigger the departure of packets (default MTU-28 in transport mode and MTU-20 in network mode)\n");
  fprintf(stderr, "-t <timeout (microsec)>: timeout (in usec) to trigger the departure of packets\n");
  fprintf(stderr, "-P <period (microsec)>: period (in usec) to trigger the departure of packets. If ( timeout < period ) then the timeout has no effect\n");
  fprintf(stderr, "-l <log file name>: log file name. Use 'stdout' if you want the log data in standard output\n");
  fprintf(stderr, "-L: use default log file name (day and hour Y-m-d_H.M.S)\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 *          flags can be IFF_TUN (1) or IFF_TAP (2)                       *
 **************************************************************************/
// explained here https://www.fatalerrors.org/a/tun-tap-interface-usage-guidance.html
int tun_alloc(char *dev,    // the name of an interface (or '\0')
              int flags)
{
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  // open the clone device
  // it is used as a starting point for creating any tun/tap virtual interface
  if( (fd = open(clonedev , O_RDWR)) < 0 ) { // Open with Read-Write
    do_debug(0, "[tun_alloc] Could not open the Clone device ");
    perror("Opening /dev/net/tun");
    return fd;
  }
  // if I am here, then the clone device has been opened for read/write
  do_debug(3, "[tun_alloc] Clone device open correctly\n");

  // preparation of the struct ifr, of type "struct ifreq"
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    // if a device name was specified, put it in the structure; otherwise,
    //the kernel will try to allocate the "next" device of the
    //specified type
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  // try to create the device
  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  // return the file descriptor of the created device
  return fd;
}


/************ Prototypes of functions used in the program ****************/

static int gen_random_num(const struct rohc_comp *const comp, void *const user_context);

/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level    The priority level of the trace
 * @param entity  The entity that emitted the trace among:
 *          \li ROHC_TRACE_COMP
 *          \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *          the trace is related to
 * @param format  The format string of the trace
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

  struct context contextSimplemux;

  contextSimplemux.fastMode = false; // fast mode is disabled by default
  contextSimplemux.blastMode = false; // blast mode is disabled by default

  contextSimplemux.rohcMode = 0;  // by default it is 0: ROHC is not used

  int fd2read;
  
  char tun_if_name[IFNAMSIZ] = "";    // name of the tun interface (e.g. "tun0")
  char mux_if_name[IFNAMSIZ] = "";    // name of the network interface (e.g. "eth0")

  char mode_string[10];
  char tunnel_mode_string[4];

  const int on = 1;                   // needed when creating a socket


  struct sockaddr_in TCPpair;

  struct iphdr ipheader;              // IP header
  struct ifreq iface;                 // network interface

  socklen_t slen = sizeof(contextSimplemux.remote);              // size of the socket. The type is like an int, but adequate for the size of the socket
  socklen_t slen_feedback = sizeof(contextSimplemux.feedback);   // size of the socket. The type is like an int, but adequate for the size of the socket

  char remote_ip[16] = "";                  // dotted quad IP string with the IP of the remote machine
  char local_ip[16] = "";                   // dotted quad IP string with the IP of the local machine
  uint16_t port = PORT;                     // UDP/TCP port to be used for sending the multiplexed packets
  uint16_t port_feedback = PORT_FEEDBACK;   // UDP port to be used for sending the ROHC feedback packets, when using ROHC bidirectional
  uint8_t ipprotocol = IPPROTO_SIMPLEMUX;


  // variables for storing the packets to multiplex
  uint8_t protocol_rec;                             // protocol field of the received muxed packet
  uint8_t protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];   // protocol field of each packet
  uint16_t size_separators_to_multiplex[MAXPKTS];   // stores the size of the Simplemux separator. It does not include the "Protocol" field
  uint8_t separators_to_multiplex[MAXPKTS][3];      // stores the header ('protocol' not included) received from tun, before sending it to the network
  uint16_t size_packets_to_multiplex[MAXPKTS];      // stores the size of the received packet


  struct packet *packetsToSend = NULL;              // to be used in blast mode

  uint8_t packets_to_multiplex[MAXPKTS][BUFSIZE];   // stores the packets received from tun, before storing it or sending it to the network

  //uint16_t length_muxed_packet;               // length of the next TCP packet
  uint16_t pending_bytes_muxed_packet = 0;           // number of bytes that still have to be read (TCP, fast mode)
  uint16_t read_tcp_bytes = 0;              // number of bytes of the content that have been read (TCP, fast mode)
  uint8_t read_tcp_bytes_separator = 0;     // number of bytes of the fast separator that have been read (TCP, fast mode)

  uint64_t blastModeTimestamps[0xFFFF+1];   // I will store 65536 different timestamps: one for each possible identifier

  // variables for controlling the arrival and departure of packets
  uint32_t tun2net = 0, net2tun = 0;     // number of packets read from tun and from net
  uint32_t feedback_pkts = 0;            // number of ROHC feedback packets
  int limit_numpackets_tun = 0;                   // limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS

  int size_threshold = 0;                         // if the number of bytes stored is higher than this, a muxed packet is sent
  int size_max;                                   // maximum value of the packet size

  uint64_t timeout = MAXTIMEOUT;                  // (microseconds) if a packet arrives and the 'timeout' has expired (time from the  
                                                  //previous sending), the sending is triggered. default 100 seconds
  uint64_t period= MAXTIMEOUT;                    // (microseconds). If the 'period' expires, a packet is sent
  uint64_t microseconds_left = period;            // the time until the period expires  

  // very long unsigned integers for storing the system clock in microseconds
  uint64_t time_last_sent_in_microsec;            // moment when the last multiplexed packet was sent
  uint64_t now_microsec;                          // current time
  uint64_t lastHeartBeatSent;                     // timestamp of the last heartbeat sent
  uint64_t lastHeartBeatReceived;                 // timestamp of the last heartbeat received

  int option;                             // command line options
  int l;
  int num_pkts_stored_from_tun = 0;       // number of packets received and not sent from tun (stored)
  int size_muxed_packet = 0;              // accumulated size of the multiplexed packet

  int interface_mtu;                      // the maximum transfer unit of the interface
  int user_mtu = 0;                       // the MTU specified by the user (it must be <= interface_mtu)
  int selected_mtu;                       // the MTU that will be used in the program

  int first_header_written = 0;           // it indicates if the first header has been written or not

  bool accepting_tcp_connections = 0;     // it is set to '1' if this is a TCP server and no connections have started

  // fixed size of the separator in fast mode
  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;

  // variables for the log file
  char log_file_name[100] = "";       // name of the log file  
  FILE *log_file = NULL;              // file descriptor of the log file
  int file_logging = 0;               // it is set to 1 if logging into a file is enabled


  /************** read command line options *********************/
  progname = argv[0];    // argument used when calling the program

  // no arguments specified by the user. Print usage and finish
  if (argc == 1 ) {
    usage ();
  }
  else {
    while((option = getopt(argc, argv, "i:e:M:T:c:p:n:B:t:P:l:d:r:m:fbhL")) > 0) {

      switch(option) {
        case 'd':
          debug = atoi(optarg);    /* 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC) */
          break;
        case 'r':
          contextSimplemux.rohcMode = atoi(optarg);  /* 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)*/ 
          break;
        case 'h':            /* help */
          usage();
          break;
        case 'i':            /* put the name of the tun interface (e.g. "tun0") in "tun_if_name" */
          strncpy(tun_if_name, optarg, IFNAMSIZ-1);
          break;
        case 'M':            /* network (N) or udp (U) or tcpclient (T) or tcpserver (S) mode */
          strcpy(mode_string, optarg);

          // check the 'mode' string and fill 'mode'
          if (strcmp(mode_string, "network") == 0) {
            do_debug(3, "the mode string is network\n");
            contextSimplemux.mode = 'N';
          }
          else if (strcmp(mode_string, "udp") == 0){
            do_debug(3, "the mode string is udp\n");
            contextSimplemux.mode= 'U';
          }
          else if (strcmp(mode_string, "tcpserver") == 0){
            do_debug(3, "the mode string is tcpserver\n");
            contextSimplemux.mode= 'S';
          }
          else if (strcmp(mode_string, "tcpclient") == 0){
            do_debug(3, "the mode string is tcpclient\n");
            contextSimplemux.mode= 'T';
          }
          else {
            do_debug(3, "the mode string is not valid\n");
          }
          do_debug(3, "mode_string: %s\n", mode_string);

          break;
        case 'T':            /* TUN (U) or TAP (A) tunnel mode */
          strcpy(tunnel_mode_string, optarg);

          // check the 'tunnel_mode' string and fill 'tunnelMode'
          if (strcmp(tunnel_mode_string, "tun") == 0) {
            do_debug(3, "the tunnel mode string is tun\n");
            contextSimplemux.tunnelMode = 'U';
          }
          else if (strcmp(tunnel_mode_string, "tap") == 0){
            do_debug(3, "the tunnel mode string is tap\n");
            contextSimplemux.tunnelMode = 'A';
          }
          else {
            do_debug(3, "the tunnel mode string is not valid\n");
          }
          do_debug(3, "tunnel_mode_string: %s\n", tunnel_mode_string);

          break;
        case 'f':            /* fast mode */
          contextSimplemux.fastMode = true;
          port = PORT_FAST;   // by default, port = PORT. In fast mode, it is PORT_FAST
          ipprotocol = IPPROTO_SIMPLEMUX_FAST; // by default, the protocol in network mode is 253. In fast mode, use 254
          do_debug(1, "Fast mode engaged\n");
          break;
        case 'b':            /* blast mode */
          contextSimplemux.blastMode = true;
          port = PORT_BLAST;   // by default, port = PORT. In blast mode, it is PORT_BLAST
          ipprotocol = IPPROTO_SIMPLEMUX_BLAST; // by default, the protocol in network mode is 253. In blast mode, use 252
          do_debug(1, "Blast mode engaged\n");
          break;
        case 'e':            /* the name of the network interface (e.g. "eth0") in "mux_if_name" */
          strncpy(mux_if_name, optarg, IFNAMSIZ-1);
          break;
        case 'c':            /* destination address of the machine where the tunnel ends */
          strncpy(remote_ip, optarg, 15);
          break;
        case 'l':            /* name of the log file */
          strncpy(log_file_name, optarg, 100);
          file_logging = 1;
          break;
        case 'L':            /* name of the log file assigned automatically */
          date_and_time(log_file_name);
          file_logging = 1;
          break;
        case 'p':            /* port number */
          port = atoi(optarg);    /* atoi Parses a string interpreting its content as an int */
          port_feedback = port + 1;
          break;
        case 'n':            /* limit of the number of packets for triggering a muxed packet */
          limit_numpackets_tun = atoi(optarg);
          break;
        case 'm':            /* MTU forced by the user */
          user_mtu = atoi(optarg);
          break;
        case 'B':            /* size threshold (in bytes) for triggering a muxed packet */
          size_threshold = atoi(optarg);
          break;
        case 't':            /* timeout for triggering a muxed packet */
          timeout = atoll(optarg);
          break;
        case 'P':            /* Period for triggering a muxed packet */
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


    /************* check command line options **************/
    if(argc > 0) {
      my_err("Too many options\n");
      usage();
    }


    // check interface options
    if(*tun_if_name == '\0') {
      my_err("Must specify a tun/tap interface name for native packets ('-i' option)\n");
      usage();
    } else if(*remote_ip == '\0') {
      my_err("Must specify the IP address of the peer\n");
      usage();
    } else if(*mux_if_name == '\0') {
      my_err("Must specify local interface name for multiplexed packets\n");
      usage();
    } 


    // check if NETWORK or TRANSPORT mode have been selected (mandatory)
    else if((contextSimplemux.mode!= NETWORK_MODE) && (contextSimplemux.mode!= UDP_MODE) && (contextSimplemux.mode!= TCP_CLIENT_MODE) && (contextSimplemux.mode!= TCP_SERVER_MODE)) {
      my_err("Must specify a valid mode ('-M' option MUST be 'network', 'udp', 'tcpserver' or 'tcpclient')\n");
      usage();
    } 
  
    // check if TUN or TAP mode have been selected (mandatory)
    else if((contextSimplemux.tunnelMode != TUN_MODE) && (contextSimplemux.tunnelMode != TAP_MODE)) {
      my_err("Must specify a valid tunnel mode ('-T' option MUST be 'tun' or 'tap')\n");
      usage();
    } 

    // TAP mode requires fast mode
    else if(((contextSimplemux.mode== TCP_SERVER_MODE) || (contextSimplemux.mode== TCP_CLIENT_MODE)) && (contextSimplemux.fastMode == false)) {
      my_err("TCP server ('-M tcpserver') and TCP client mode ('-M tcpclient') require fast mode (option '-f')\n");
      usage();
    }

    else if(contextSimplemux.fastMode == true) {
      if(SIZE_PROTOCOL_FIELD!=1) {
        my_err("Fast mode (-f) only allows a protocol field of size 1. Please review 'SIZE_PROTOCOL_FIELD'\n");        
      }
    }

    // Blast mode is restricted
    else if(contextSimplemux.blastMode == true) {
      if(SIZE_PROTOCOL_FIELD!=1) {
        my_err("Blast mode (-f) only allows a protocol field of size 1. Please review 'SIZE_PROTOCOL_FIELD'\n");        
      }
      if((contextSimplemux.mode== TCP_SERVER_MODE) || (contextSimplemux.mode== TCP_CLIENT_MODE)){
        my_err("Blast mode (-b) not allowed in TCP server ('-M tcpserver') and TCP client mode ('-M tcpclient')\n");
        usage();
      }
      if(contextSimplemux.fastMode== true) {
        my_err("Blast mode (-b) and fast mode (-f) are not compatible\n");
        usage();        
      }
      if(contextSimplemux.rohcMode!=0) {
        my_err("Blast mode (-b) is not compatible with ROHC (-r)\n");
        usage();          
      }
      if(size_threshold!=0) {
        my_err("Blast mode (-b) is not compatible with size threshold (-B)\n");
        usage();
      }
      if(timeout!=MAXTIMEOUT) {
        my_err("Blast mode (-b) is not compatible with timeout (-t)\n");
        usage();
      }
      if(limit_numpackets_tun!=0) {
        my_err("Blast mode (-b) is not compatible with a limit of the number of packets. Only a packet is sent (-n)\n");
        usage();
      }
      if(period==MAXTIMEOUT) {
        my_err("In blast mode (-b) you must specify a Period (-P)\n");
        usage();        
      }
    }


    // open the log file
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
    if ( contextSimplemux.rohcMode < 0 ) {
      contextSimplemux.rohcMode = 0;
    }
    else if ( contextSimplemux.rohcMode > 2 ) { 
      contextSimplemux.rohcMode = 2;
    }
    /************* end - check command line options **************/


    /************* initialize the tun/tap **************/
    if (contextSimplemux.tunnelMode == TUN_MODE) {
      // tun tunnel mode (i.e. send IP packets)
      // initialize tun interface for native packets
      if ( (contextSimplemux.tun_fd = tun_alloc(tun_if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tun interface for capturing native packets %s\n", tun_if_name);
        exit(1);
      }
      do_debug(1, "Successfully connected to interface for native packets %s\n", tun_if_name);    
    }
    else if (contextSimplemux.tunnelMode == TAP_MODE) {
      // tap tunnel mode (i.e. send Ethernet frames)
      
      // ROHC mode cannot be used in tunnel mode TAP, because Ethernet headers cannot be compressed
      if (contextSimplemux.rohcMode != 0) {
        my_err("Error ROHC cannot be used in 'tap' mode (Ethernet headers cannot be compressed)\n");
        exit(1);          
      }        

      // initialize tap interface for native packets
      if ( (contextSimplemux.tun_fd = tun_alloc(tun_if_name, IFF_TAP | IFF_NO_PI)) < 0 ) {
        my_err("Error connecting to tap interface for capturing native Ethernet frames %s\n", tun_if_name);
        exit(1);
      }
      do_debug(1, "Successfully connected to interface for Ethernet frames %s\n", tun_if_name);    
    }
    else exit(1); // this would be a failure
    /************* end - initialize the tun/tap **************/


    /*** Request a socket for writing and receiving muxed packets in Network mode ***/
    if ( contextSimplemux.mode== NETWORK_MODE ) {
      // initialize header IP to be used when receiving a packet in NETWORK mode
      memset(&ipheader, 0, sizeof(struct iphdr));      
      memset (&iface, 0, sizeof (iface));
      snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);

      // get the local IP address of the network interface 'mux_if_name'
      // using 'getifaddrs()'   
      struct ifaddrs *ifaddr, *ifa;
      int /*family,*/ s;
      char host[NI_MAXHOST];  // this will be the IP address
  
      if (getifaddrs(&ifaddr) == -1) {
          perror("getifaddrs");
          exit(EXIT_FAILURE);
      }
      
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
          continue;  
        
        s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        
        if((strcmp(ifa->ifa_name,mux_if_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
          if (s != 0) {
              printf("getnameinfo() failed: %s\n", gai_strerror(s));
              exit(EXIT_FAILURE);
          }
          do_debug(1,"Raw socket for multiplexing over IP open. Interface %s\nLocal IP %s. Protocol number %i\n", ifa->ifa_name, host, ipprotocol);
          break;
        }
      }
 
      // assign the local address for the multiplexed packets
      memset(&(contextSimplemux.local), 0, sizeof(contextSimplemux.local));
      contextSimplemux.local.sin_family = AF_INET;
      contextSimplemux.local.sin_addr.s_addr = inet_addr(host);  // convert the string 'host' to an IP address

      freeifaddrs(ifaddr);
      
       // assign the destination address for the multiplexed packets
      memset(&(contextSimplemux.remote), 0, sizeof(contextSimplemux.remote));
      contextSimplemux.remote.sin_family = AF_INET;
      contextSimplemux.remote.sin_addr.s_addr = inet_addr(remote_ip);    // remote IP. There are no ports in Network Mode
  
      // AF_INET (exactly the same as PF_INET)
      // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
      // contextSimplemux.network_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets
      // create a raw socket for reading and writing multiplexed packets belonging to protocol Simplemux (protocol ID 253)
      // Submit request for a raw socket descriptor
      if ((contextSimplemux.network_mode_fd = socket (AF_INET, SOCK_RAW, ipprotocol)) < 0) {
        perror ("Raw socket for sending muxed packets failed ");
        exit (EXIT_FAILURE);
      }
      else {
        do_debug(1,"Remote IP %s\n", inet_ntoa(contextSimplemux.remote.sin_addr));
      }

      // Set flag so socket expects us to provide IPv4 header
      if (setsockopt (contextSimplemux.network_mode_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
        perror ("setsockopt() failed to set IP_HDRINCL ");
        exit (EXIT_FAILURE);
      }

      // Bind the socket "contextSimplemux.network_mode_fd" to interface index
      // bind socket descriptor "contextSimplemux.network_mode_fd" to specified interface with setsockopt() since
      // none of the other arguments of sendto() specify which interface to use.
      if (setsockopt (contextSimplemux.network_mode_fd, SOL_SOCKET, SO_BINDTODEVICE, &iface, sizeof (iface)) < 0) {
        perror ("setsockopt() failed to bind to interface (network mode) ");
        exit (EXIT_FAILURE);
      }  
    }
    
    // UDP mode
    // I use the same origin and destination port. The reason is that I am using the same socket for sending
    //and receiving UDP simplemux packets
    // The local port for Simplemux is PORT
    // The remote port for Simplemux must also be PORT, because the packets go there
    // Packets arriving to the local computer have dstPort = PORT, srcPort = PORT
    // Packets sent from the local computer have srcPort = PORT, dstPort = PORT
    else if ( contextSimplemux.mode== UDP_MODE ) {
      /*** Request a socket for writing and receiving muxed packets in UDP mode ***/
      // AF_INET (exactly the same as PF_INET)
      // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
      // contextSimplemux.udp_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets

      /* creates an UN-named socket inside the kernel and returns
       * an integer known as socket descriptor
       * This function takes domain/family as its first argument.
       * For Internet family of IPv4 addresses we use AF_INET
       */
      if ( ( contextSimplemux.udp_mode_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
        perror("socket() UDP mode");
        exit(1);
      }

      // Use ioctl() to look up interface index which we will use to bind socket descriptor "contextSimplemux.udp_mode_fd" to
      memset (&iface, 0, sizeof (iface));
      snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
      if (ioctl (contextSimplemux.udp_mode_fd, SIOCGIFINDEX, &iface) < 0) {
        perror ("ioctl() failed to find interface (transport mode) ");
        return (EXIT_FAILURE);
      }

      /*** get the IP address of the local interface ***/
      if (ioctl(contextSimplemux.udp_mode_fd, SIOCGIFADDR, &iface) < 0) {
        perror ("ioctl() failed to find the IP address for local interface ");
        return (EXIT_FAILURE);
      }
      else {
        // source IPv4 address: it is the one of the interface
        strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
        do_debug(1, "Local IP for multiplexing %s\n", local_ip);
      }
  
      // assign the destination address and port for the multiplexed packets
      memset(&(contextSimplemux.remote), 0, sizeof(contextSimplemux.remote));
      contextSimplemux.remote.sin_family = AF_INET;
      contextSimplemux.remote.sin_addr.s_addr = inet_addr(remote_ip);    // remote IP
      contextSimplemux.remote.sin_port = htons(port);            // remote port
  
      // assign the local address and port for the multiplexed packets
      memset(&(contextSimplemux.local), 0, sizeof(contextSimplemux.local));
      contextSimplemux.local.sin_family = AF_INET;
      contextSimplemux.local.sin_addr.s_addr = inet_addr(local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
      contextSimplemux.local.sin_port = htons(port);            // local port
  
      // bind the socket "contextSimplemux.udp_mode_fd" to the local address and port
      if (bind(contextSimplemux.udp_mode_fd, (struct sockaddr *)&(contextSimplemux.local), sizeof(contextSimplemux.local))==-1) {
        perror("bind");
      }
      else {
        do_debug(1, "Socket for multiplexing over UDP open. Remote IP %s. Port %i\n", inet_ntoa(contextSimplemux.remote.sin_addr), htons(contextSimplemux.remote.sin_port)); 
      }
    }

    // TCP server mode
    else if (contextSimplemux.mode== TCP_SERVER_MODE ) {
      /*** Request a socket for writing and receiving muxed packets in TCP mode ***/
      // AF_INET (exactly the same as PF_INET)
      // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
      // contextSimplemux.tcp_welcoming_fd is the file descriptor of the socket for managing arrived multiplexed packets

      /* creates an UN-named socket inside the kernel and returns
       * an integer known as socket descriptor
       * This function takes domain/family as its first argument.
       * For Internet family of IPv4 addresses we use AF_INET
       */
      if ( ( contextSimplemux.tcp_welcoming_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
        perror("socket() TCP server mode");
        exit(1);
      }      

      // Use ioctl() to look up interface index which we will use to bind socket descriptor "contextSimplemux.udp_mode_fd" to
      memset (&iface, 0, sizeof (iface));
      snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
                
      /*** get the IP address of the local interface ***/
      if (ioctl(contextSimplemux.tcp_welcoming_fd, SIOCGIFADDR, &iface) < 0) {
        perror ("ioctl() failed to find the IP address for local interface ");
        return (EXIT_FAILURE);
      }
      else {
        // source IPv4 address: it is the one of the interface
        strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
        do_debug(1, "Local IP for multiplexing %s\n", local_ip);
      }

      // assign the destination address and port for the multiplexed packets
      memset(&(contextSimplemux.remote), 0, sizeof(contextSimplemux.remote));
      contextSimplemux.remote.sin_family = AF_INET;
      contextSimplemux.remote.sin_addr.s_addr = inet_addr(remote_ip);    // remote IP
      contextSimplemux.remote.sin_port = htons(port);            // remote port
  
      // assign the local address and port for the multiplexed packets
      memset(&(contextSimplemux.local), 0, sizeof(contextSimplemux.local));
      contextSimplemux.local.sin_family = AF_INET;
      contextSimplemux.local.sin_addr.s_addr = inet_addr(local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
      contextSimplemux.local.sin_port = htons(port);            // local port

      /* The call to the function "bind()" assigns the details specified
       * in the structure 'sockaddr' to the socket created above
       */  
      if (bind(contextSimplemux.tcp_welcoming_fd, (struct sockaddr *)&(contextSimplemux.local), sizeof(contextSimplemux.local))==-1) {
        perror("bind");
      }
      else {
        do_debug(1, "Welcoming TCP socket open. Remote IP %s. Port %i\n", inet_ntoa(contextSimplemux.remote.sin_addr), htons(contextSimplemux.remote.sin_port)); 
      }

      /* The call to the function "listen()" with second argument as 1 specifies
       * maximum number of client connections that the server will queue for this listening
       * socket.
       */
      listen(contextSimplemux.tcp_welcoming_fd, 1);
      
      // from now on, I will accept a TCP connection
      accepting_tcp_connections = 1;
    }

    // TCP client mode
    else if ( contextSimplemux.mode== TCP_CLIENT_MODE ) {
      /*** Request a socket for writing and receiving muxed packets in TCP mode ***/
      // AF_INET (exactly the same as PF_INET)
      // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
      // contextSimplemux.tcp_client_fd is the file descriptor of the socket for managing arrived multiplexed packets

      /* creates an UN-named socket inside the kernel and returns
       * an integer known as socket descriptor
       * This function takes domain/family as its first argument.
       * For Internet family of IPv4 addresses we use AF_INET
       */
      if ( ( contextSimplemux.tcp_client_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
        perror("socket() TCP mode");
        exit(1);
      }
      
      // Use ioctl() to look up interface index which we will use to bind socket descriptor "contextSimplemux.udp_mode_fd" to
      memset (&iface, 0, sizeof (iface));
      snprintf (iface.ifr_name, sizeof (iface.ifr_name), "%s", mux_if_name);
      
      /*** get the IP address of the local interface ***/
      if (ioctl(contextSimplemux.tcp_client_fd, SIOCGIFADDR, &iface) < 0) {
        perror ("ioctl() failed to find the IP address for local interface ");
        return (EXIT_FAILURE);
      }
      else {
        // source IPv4 address: it is the one of the interface
        strcpy (local_ip, inet_ntoa(((struct sockaddr_in *)&iface.ifr_addr)->sin_addr));
        do_debug(1, "Local IP for multiplexing %s\n", local_ip);
      }

      // assign the local address and port for the multiplexed packets
      memset(&(contextSimplemux.local), 0, sizeof(contextSimplemux.local));
      contextSimplemux.local.sin_family = AF_INET;
      contextSimplemux.local.sin_addr.s_addr = inet_addr(local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
      contextSimplemux.local.sin_port = htons(port);            // local port
      
      // assign the destination address and port for the multiplexed packets
      memset(&(contextSimplemux.remote), 0, sizeof(contextSimplemux.remote));
      contextSimplemux.remote.sin_family = AF_INET;
      contextSimplemux.remote.sin_addr.s_addr = inet_addr(remote_ip);    // remote IP
      contextSimplemux.remote.sin_port = htons(port);            // remote port


      /* Information like IP address of the remote host and its port is
       * bundled up in a structure and a call to function connect() is made
       * which tries to connect this socket with the socket (IP address and port)
       * of the remote host
       */
      if( connect(contextSimplemux.tcp_client_fd, (struct sockaddr *)&(contextSimplemux.remote), sizeof(contextSimplemux.remote)) < 0) {
        do_debug(1, "Trying to connect to the TCP server at %s:%i\n", inet_ntoa(contextSimplemux.remote.sin_addr), htons(contextSimplemux.remote.sin_port));
        perror("connect() error: TCP connect Failed. The TCP server did not accept the connection");
        return 1;
      }
      else {
        do_debug(1, "Successfully connected to the TCP server at %s:%i\n", inet_ntoa(contextSimplemux.remote.sin_addr), htons(contextSimplemux.remote.sin_port));

        if ( DISABLE_NAGLE == 1 ) {
          // disable NAGLE algorigthm, see https://holmeshe.me/network-essentials-setsockopt-TCP_NODELAY/
          int flags =1;
          setsockopt(contextSimplemux.tcp_client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));          
        }
        if ( QUICKACK == 1 ) {
          // enable quick ACK, i.e. avoid delayed ACKs
          int flags =1;
          setsockopt(contextSimplemux.tcp_client_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&flags, sizeof(flags));          
        }
      }
    }

    /*** get the MTU of the local interface ***/
    if ( contextSimplemux.mode== UDP_MODE)  {
      if (ioctl(contextSimplemux.udp_mode_fd, SIOCGIFMTU, &iface) == -1)
        interface_mtu = 0;
      else interface_mtu = iface.ifr_mtu;
    }
    else if ( contextSimplemux.mode== NETWORK_MODE) {
      if (ioctl(contextSimplemux.network_mode_fd, SIOCGIFMTU, &iface) == -1)
        interface_mtu = 0;
      else interface_mtu = iface.ifr_mtu;
    }
    else if ( contextSimplemux.mode== TCP_SERVER_MODE ) {
      if (ioctl(contextSimplemux.tcp_welcoming_fd, SIOCGIFMTU, &iface) == -1)
        interface_mtu = 0;
      else interface_mtu = iface.ifr_mtu;
    }
    else if ( contextSimplemux.mode== TCP_CLIENT_MODE ) {
      if (ioctl(contextSimplemux.tcp_client_fd, SIOCGIFMTU, &iface) == -1)
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
    switch ( contextSimplemux.mode) {
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
    //    - the size of the multiplexed packet has exceeded the size threshold specified by the user,
    //      but not the MTU. In this case, a packet is sent and a new period is started with the
    //      buffer empty.
    //    - the size of the multiplexed packet has exceeded the MTU (and the size threshold consequently).
    //      In this case, a packet is sent without the last one. A new period is started, and the last 
    //      packet is stored as the first packet to be sent at the end of the next period.
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
  

    do_debug (1, "Multiplexing policies: size threshold: %i. numpackets: %i. timeout: %"PRIu64"us. period: %"PRIu64"us\n",
              size_threshold, limit_numpackets_tun, timeout, period);
    
    
    // I only need the feedback socket if ROHC is activated
    //but I create it in case the other extreme sends ROHC packets
    if(1) {
      /*** Request a socket for feedback packets ***/
      // AF_INET (exactly the same as PF_INET)
      // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
      // contextSimplemux.feedback_fd is the file descriptor of the socket for managing arrived feedback packets
      if ( ( contextSimplemux.feedback_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
        perror("socket()");
        exit(1);
      }
  
      if (ioctl (contextSimplemux.feedback_fd, SIOCGIFINDEX, &iface) < 0) {
        perror ("ioctl() failed to find interface (feedback)");
        return (EXIT_FAILURE);
      }
      
      // assign the destination address and port for the feedback packets
      memset(&(contextSimplemux.feedback_remote), 0, sizeof(contextSimplemux.feedback_remote));
      contextSimplemux.feedback_remote.sin_family = AF_INET;
      contextSimplemux.feedback_remote.sin_addr.s_addr = inet_addr(remote_ip);  // remote feedback IP (the same IP as the remote one)
      contextSimplemux.feedback_remote.sin_port = htons(port_feedback);    // remote feedback port
  
      // assign the source address and port to the feedback packets
      memset(&(contextSimplemux.feedback), 0, sizeof(contextSimplemux.feedback));
      contextSimplemux.feedback.sin_family = AF_INET;
      contextSimplemux.feedback.sin_addr.s_addr = inet_addr(local_ip);    // local IP
      contextSimplemux.feedback.sin_port = htons(port_feedback);      // local port (feedback)
  
      // bind the socket "contextSimplemux.feedback_fd" to the local feedback address (the same used for multiplexing) and port
       if (bind(contextSimplemux.feedback_fd, (struct sockaddr *)&(contextSimplemux.feedback), sizeof(contextSimplemux.feedback))==-1) {
        perror("bind");
      }
      else {
        do_debug(1, "Socket for ROHC feedback over UDP open. Remote IP %s. Port %i\n", inet_ntoa(contextSimplemux.feedback_remote.sin_addr), htons(contextSimplemux.feedback_remote.sin_port)); 
      }
    }

    //do_debug(1,"tun_fd: %d; network_mode_fd: %d; contextSimplemux.udp_mode_fd: %d; feedback_fd: %d; tcp_welcoming_fd: %d; tcp_client_fd: %d\n", contextSimplemux.tun_fd, contextSimplemux.network_mode_fd, contextSimplemux.udp_mode_fd, contextSimplemux.feedback_fd, contextSimplemux.tcp_welcoming_fd, contextSimplemux.tcp_client_fd);
    
    switch(contextSimplemux.rohcMode) {
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
        do_debug ( 1 , "ROHC Bidirectional Reliable Mode\n", debug);  // Bidirectional Reliable mode (not implemented yet)
        break;*/
    }

    // If ROHC has been selected, I have to initialize it
    // see the API here: https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/
    if ( contextSimplemux.rohcMode > 0 ) {

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
      if ( contextSimplemux.rohcMode == 1 ) {
        decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);  // Unidirectional mode
      }
      else if ( contextSimplemux.rohcMode == 2 ) {
        decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);  // Bidirectional Optimistic mode
      }
      /*else if ( contextSimplemux.rohcMode == 3 ) {
        decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);  // Bidirectional Reliable mode (not implemented yet)
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
      if(!status)  {
        fprintf(stderr, "failed to enable the Uncompressed decompression profile\n");
        goto release_decompressor;
      }
      else {
        do_debug(1, "Uncompressed. ");
      }

      status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_IP, -1);
      if(!status)  {
        fprintf(stderr, "failed to enable the IP-only decompression profile\n");
        goto release_decompressor;
      }
      else {
        do_debug(1, "IP-only. ");
      }

      status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP, -1);
      if(!status)  {
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
      if(!status)  {
        fprintf(stderr, "failed to enable the RTP decompression profile\n");
        goto release_decompressor;
      }
      else {
        do_debug(1, "RTP. ");
      }

      status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_ESP,-1);
      if(!status)  {
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
    

    // in blast mode, fill the vector of timestamps with zeroes
    if(contextSimplemux.blastMode) {
      for(int i=0;i<0xFFFF+1;i++)
        blastModeTimestamps[i] = 0;
    }

    /** prepare POLL structure **/
    // it has size 3 (NUMBER_OF_SOCKETS), because it handles 3 sockets
    // - tun/tap socket where demuxed packets are sent/received
    // - feedback socket
    // - socket where muxed packets are sent/received. It can be:
    //      - Network mode: IP raw socket
    //      - UDP mode: UDP socket
    //      - TCP server mode
    //      - TCP client mode
    struct pollfd* fds_poll = malloc(NUMBER_OF_SOCKETS * sizeof(struct pollfd));
    memset(fds_poll, 0, NUMBER_OF_SOCKETS * sizeof(struct pollfd));
  
    fds_poll[0].fd = contextSimplemux.tun_fd;
    fds_poll[1].fd = contextSimplemux.feedback_fd;
    if ( contextSimplemux.mode== NETWORK_MODE )
      fds_poll[2].fd = contextSimplemux.network_mode_fd;
    else if ( contextSimplemux.mode== UDP_MODE )
      fds_poll[2].fd = contextSimplemux.udp_mode_fd;
    else if ( contextSimplemux.mode==TCP_SERVER_MODE )
      fds_poll[2].fd = contextSimplemux.tcp_welcoming_fd;
    else
      fds_poll[2].fd = contextSimplemux.tcp_client_fd;
    
    fds_poll[0].events = POLLIN;
    fds_poll[1].events = POLLIN;
    fds_poll[2].events = POLLIN;
    /** END prepare POLL structure **/  
      
    // I calculate 'now' as the moment of the last sending
    time_last_sent_in_microsec = GetTimeStamp();

    if(contextSimplemux.blastMode) {
      lastHeartBeatSent = time_last_sent_in_microsec;
      lastHeartBeatReceived = 0; // this means that I have received no heartbeats yet
    }
    


    /*****************************************/
    /************** Main loop ****************/
    /*****************************************/
    while(1) {
    
      /* Initialize the timeout data structure. */

      if(contextSimplemux.blastMode) {

        time_last_sent_in_microsec = findLastSentTimestamp(packetsToSend);

        if(debug>1)
          printList(&packetsToSend);

        now_microsec = GetTimeStamp();
        //do_debug(1, " %"PRIu64": Starting the while\n", now_microsec);

        if (time_last_sent_in_microsec == 0) {
          time_last_sent_in_microsec = now_microsec;
          do_debug(2, "%"PRIu64" No blast packet is waiting to be sent to the network\n", now_microsec);
        }

        if(time_last_sent_in_microsec + period > now_microsec) {
          microseconds_left = time_last_sent_in_microsec + period - now_microsec;
          do_debug(2, "%"PRIu64" The next blast packet will be sent in %"PRIu64" us\n", now_microsec, microseconds_left);         
        }
        else {
          // the period is already expired
          do_debug(2, "%"PRIu64" Call the poll with limit 0\n", now_microsec);
          microseconds_left = 0;
        }

        // in blast mode, heartbeats have to be sent periodically
        // if the time to the next heartbeat is smaller than the time to the next blast sent,
        //then the time has to be reduced
        uint64_t microsecondsToNextHeartBeat = lastHeartBeatSent + HEARTBEATPERIOD - now_microsec;

        // choose the smallest one
        if(microsecondsToNextHeartBeat < microseconds_left)
          microseconds_left = microsecondsToNextHeartBeat;
      }

      else {
        // not in blast mode

        now_microsec = GetTimeStamp();

        if ( period > (now_microsec - time_last_sent_in_microsec)) {
          // the period is not expired
          microseconds_left = (period - (now_microsec - time_last_sent_in_microsec));
        }
        else {
          // the period is expired
          //printf("the period is expired\n");
          microseconds_left = 0;
        }        

        do_debug(3, " Time last sending: %"PRIu64" us\n", time_last_sent_in_microsec);
        do_debug(3, " The next packet will be sent in %"PRIu64" us\n", microseconds_left);        
      }


      //if (microseconds_left > 0) do_debug(0,"%"PRIu64"\n", microseconds_left);
      int milliseconds_left = (int)(microseconds_left / 1000.0);
      //printf("milliseconds_left: %d", milliseconds_left);
      
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
        //do_debug(0,"fd2read: %d; mode: %c; accepting_tcp_connections: %i\n", fd2read, mode, accepting_tcp_connections);

        /******************************************************************/
        /*************** TCP connection request from a client *************/
        /******************************************************************/
        // a connection request has arrived to the welcoming socket
        if ((fds_poll[2].revents & POLLIN) && (contextSimplemux.mode==TCP_SERVER_MODE) && (accepting_tcp_connections == 1) ) {

          // accept the connection
          unsigned int len = sizeof(struct sockaddr);
          contextSimplemux.tcp_server_fd = accept(contextSimplemux.tcp_welcoming_fd, (struct sockaddr*)&TCPpair, &len);
          
          if ( DISABLE_NAGLE == 1 ) {
            // disable NAGLE algorigthm, see https://holmeshe.me/network-essentials-setsockopt-TCP_NODELAY/
            int flags =1;
            setsockopt(contextSimplemux.tcp_client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
          }

          // from now on, the TCP welcoming socket will NOT accept any other connection
          // FIXME: Does this make sense?
          accepting_tcp_connections = 0;
  
          if(contextSimplemux.tcp_server_fd <= 0) {
            perror("Error in 'accept()': TCP welcoming Socket");
          }
  
          // change the descriptor to that of contextSimplemux.tcp_server_fd
          // from now on, contextSimplemux.tcp_server_fd will be used
          fds_poll[2].fd = contextSimplemux.tcp_server_fd;
          //if(contextSimplemux.tcp_server_fd > maxfd) maxfd = contextSimplemux.tcp_server_fd;
          
          do_debug(1,"TCP connection started by the client. Socket for connecting to the client: %d\n", contextSimplemux.tcp_server_fd);        
  
        }
        
        /*****************************************************************************/
        /***************** NET to tun. demux and decompress **************************/
        /*****************************************************************************/
  
        // data arrived at the network interface: read, demux, decompress and forward it.
        // In TCP_SERVER_MODE, I will only enter here if the TCP connection is already started
        // in the rest of modes, I will enter here if a muxed packet has arrived        
        else if ( (fds_poll[2].revents & POLLIN) && 
                  (((contextSimplemux.mode== TCP_SERVER_MODE) && (accepting_tcp_connections == 0))  ||
                  (contextSimplemux.mode== NETWORK_MODE) || 
                  (contextSimplemux.mode== UDP_MODE) ||
                  (contextSimplemux.mode== TCP_CLIENT_MODE) ) )
        {
          int is_multiplexed_packet;
          int nread_from_net;                 // number of bytes read from network which will be demultiplexed
          uint8_t buffer_from_net[BUFSIZE];   // stores the packet received from the network, before sending it to tun
          uint16_t packet_length;

          is_multiplexed_packet = readPacketFromNet(&contextSimplemux,
                                                    buffer_from_net,
                                                    //received,
                                                    slen,
                                                    port,
                                                    ipheader,
                                                    ipprotocol,
                                                    &protocol_rec,
                                                    &nread_from_net,
                                                    &packet_length,
                                                    &pending_bytes_muxed_packet,
                                                    size_separator_fast_mode,
                                                    &read_tcp_bytes_separator,
                                                    &read_tcp_bytes/*,
                                                    &contextSimplemux.length_muxed_packet*/ );
    
          // now 'buffer_from_net' may contain a full packet or frame.
          // check if the packet is a multiplexed one
          if (is_multiplexed_packet == -1) {
            // I have read nothing
          }
          
          else if (is_multiplexed_packet == 1) {
            demuxPacketFromNet( &contextSimplemux,
                                &net2tun,
                                /*local,
                                remote,
                                feedback_remote,*/
                                nread_from_net,
                                packet_length,
                                log_file,
                                &packetsToSend,
                                blastModeTimestamps,
                                buffer_from_net,
                                &protocol_rec,
                                &status,
                                &lastHeartBeatReceived,
                                debug );
          }
  
          else { // is_multiplexed_packet == 0
            // packet with the correct destination port, but a source port different from the multiplexing one
            // if the packet does not come from the multiplexing port, write it directly into the tun interface
            do_debug(1, "NON-SIMPLEMUX PACKET #%"PRIu32": Non-multiplexed packet. Writing %i bytes to tun\n", net2tun, nread_from_net);
            cwrite ( contextSimplemux.tun_fd, buffer_from_net, nread_from_net);
  
            // write the log file
            if ( log_file != NULL ) {
              // the packet is good
              fprintf (log_file, "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(contextSimplemux.remote.sin_addr), ntohs(contextSimplemux.remote.sin_port));
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
  
        //else if ( FD_ISSET ( contextSimplemux.feedback_fd, &rd_set )) {    /* FD_ISSET tests to see if a file descriptor is part of the set */
        else if(fds_poll[1].revents & POLLIN) {
        
          int nread_from_net; // number of bytes read from network which will be demultiplexed
          uint8_t buffer_from_net[BUFSIZE];         // stores the packet received from the network, before sending it to tun

          // a packet has been received from the network, destinated to the feedbadk port. 'slen_feedback' is the length of the IP address
          nread_from_net = recvfrom ( contextSimplemux.feedback_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&(contextSimplemux.feedback_remote), &slen_feedback );
  
          if (nread_from_net == -1) perror ("recvfrom()");
  
          // now buffer_from_net contains a full packet or frame.
          // check if the packet comes (source port) from the feedback port (default 55556).  (Its destination port IS the feedback port)
  
          if (port_feedback == ntohs(contextSimplemux.feedback_remote.sin_port)) {
  
            // the packet comes from the feedback port (default 55556)
            do_debug(1, "\nFEEDBACK %lu: Read ROHC feedback packet (%i bytes) from %s:%d\n", feedback_pkts, nread_from_net, inet_ntoa(contextSimplemux.feedback.sin_addr), ntohs(contextSimplemux.feedback.sin_port));
  
            feedback_pkts ++;
  
            // write the log file
            if ( log_file != NULL ) {
              fprintf (log_file, "%"PRIu64"\trec\tROHC feedback\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, feedback_pkts, inet_ntoa(contextSimplemux.remote.sin_addr), ntohs(contextSimplemux.remote.sin_port));
              fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
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
            if (debug>0) {
              do_debug(2, " ROHC feedback packet received\n");
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
            do_debug(1, "NON-FEEDBACK PACKET %"PRIu32": Non-feedback packet. Writing %i bytes to tun\n", net2tun, nread_from_net);
            cwrite ( contextSimplemux.tun_fd, buffer_from_net, nread_from_net);
  
            // write the log file
            if ( log_file != NULL ) {
              // the packet is good
              fprintf (log_file, "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, net2tun, inet_ntoa(contextSimplemux.remote.sin_addr), ntohs(contextSimplemux.remote.sin_port));
              fflush(log_file);
            }
          }
        }
  
  
  
        /**************************************************************************************/  
        /***************** TUN to NET: compress and multiplex *********************************/
        /**************************************************************************************/
  
        /*** data arrived at tun: read it, and check if the stored packets should be written to the network ***/
        /*** a local packet has arrived to tun/tap, and it has to be multiplexed and sent to the destination***/
  
        /* FD_ISSET tests if a file descriptor is part of the set */
        //else if(FD_ISSET(contextSimplemux.tun_fd, &rd_set)) {
        else if(fds_poll[0].revents & POLLIN) {
          /* increase the counter of the number of packets read from tun*/
          tun2net++;

          if (contextSimplemux.blastMode) {
            tunToNetBlastMode(&contextSimplemux,
                              tun2net,
                              /*local,
                              remote,*/
                              &packetsToSend,
                              &lastHeartBeatReceived );
          }

          else {
            // not in blast mode
            tunToNetNoBlastMode(&contextSimplemux,
                                tun2net,
                                accepting_tcp_connections,
                                /*local,
                                remote,*/
                                &ipheader,
                                ipprotocol,
                                &num_pkts_stored_from_tun,
                                size_packets_to_multiplex,
                                packets_to_multiplex,
                                size_separators_to_multiplex,
                                separators_to_multiplex,
                                protocol,
                                selected_mtu,
                                &first_header_written,
                                size_separator_fast_mode,
                                size_max,
                                &size_muxed_packet,
                                &time_last_sent_in_microsec,
                                limit_numpackets_tun,
                                size_threshold,
                                timeout,
                                log_file );
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
        do_debug(2, "Poll timeout expired\n");
        
        if(contextSimplemux.blastMode) {

          // go through the list and send all the packets with now_microsec > sentTimestamp + period
          int fd;
          if(contextSimplemux.mode==UDP_MODE)
            fd = contextSimplemux.udp_mode_fd;
          else if(contextSimplemux.mode==NETWORK_MODE)
            fd = contextSimplemux.network_mode_fd;

          periodExpiredBlastMode (&contextSimplemux,
                                  fd,
                                  &time_last_sent_in_microsec,
                                  period,
                                  lastHeartBeatReceived,
                                  &lastHeartBeatSent,
                                  /*local,
                                  remote,*/
                                  packetsToSend);

        }
        else {
          // not in blast mode
          if ( num_pkts_stored_from_tun > 0 ) {
            // There are some packets stored

            periodExpiredNoBlastMode (&contextSimplemux,
                                      tun2net,
                                      &num_pkts_stored_from_tun,
                                      &first_header_written,
                                      &time_last_sent_in_microsec,
                                      protocol,
                                      size_separators_to_multiplex,
                                      separators_to_multiplex,
                                      &size_muxed_packet,
                                      size_packets_to_multiplex,
                                      packets_to_multiplex,
                                      /*local,
                                      remote,*/
                                      ipprotocol,
                                      &ipheader,
                                      log_file );

          }
          else {
            // No packet arrived
            //do_debug(2, "Period expired. Nothing to be sent\n");
          }
          // restart the period
          time_last_sent_in_microsec = now_microsec; 
          do_debug(3, "%"PRIu64" Period expired\n", time_last_sent_in_microsec);
        }
      }     
    }  // end while(1)

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
