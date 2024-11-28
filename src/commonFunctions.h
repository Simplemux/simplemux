#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>  // required for using uint8_t, uint16_t, etc.
#include <netinet/ip.h>       // for using iphdr type

// If you comment the next lines, the program will be a bit faster
#define DEBUG 1   // if you comment this line, debug info is not allowed
#define LOGFILE 1 // if you comment this line, logs are not allowed
#define ASSERT 1  // if you comment this line, assertions are not allowed

#ifdef ASSERT
  #include <assert.h>     // for using assert()
#endif

#define BUFSIZE 2304
#define IPv4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
//#define TCP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 32      // in some cases, the TCP header is 32 byte long
#define BLAST_HEADER_SIZE 6     // fixme: we could use sizeof(simplemuxBlastHeader) instead

#define TIME_UNTIL_SENDING_AGAIN_BLAST 5000000 // milliseconds before sending again a packet with the same ID
                                                // there are 65536 possible values of the ID
                                                // if a packet with an ID has been sent 5 seconds ago,
                                                //it can be sent again

// Protocol IDs, according to IANA
// see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define IPPROTO_IP_ON_IP 4        // IP on IP Protocol ID
#define IPPROTO_ROHC 142          // ROHC Protocol ID
#define IPPROTO_ETHERNET 143      // Ethernet Protocol ID

#define IPPROTO_SIMPLEMUX 253       // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_FAST 254  // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_BLAST 252

#define PORT 55555              // default port
#define PORT_FEEDBACK 55556     // port for sending ROHC feedback
#define PORT_FAST 55557         // port for sending Simplemux fast
#define PORT_BLAST 55558        // port for sending Simplemux fast

#define DISABLE_NAGLE 1         // disable TCP Nagle algorithm
#define QUICKACK 1              // enable TCP quick ACKs (non delayed)

#define Linux_TTL 64            // the initial value of the TTL IP field in Linux

#define NETWORK_MODE    'N'     // N: network mode
#define UDP_MODE        'U'     // U: UDP mode
#define TCP_CLIENT_MODE 'T'     // T: TCP client mode
#define TCP_SERVER_MODE 'S'     // S: TCP server mode

#define TUN_MODE 'U'            // T: tun mode, i.e. IP packets will be tunneled inside Simplemux
#define TAP_MODE 'A'            // A: tap mode, i.e. Ethernet frames will be tunneled inside Simplemux

#define MAXPKTS 100             // maximum number of packets to store in normal and fast flavor

#define SIZE_LENGTH_FIELD_FAST_MODE 2   // the length field in fast mode is always two bytes

#define HEARTBEATDEADLINE 5000000 // after this time, if a heartbeat is not received, packets will no longer be sent
#define HEARTBEATPERIOD 1000000   // a heartbeat will be sent every second
#define MAXTIMEOUT 100000000.0    // maximum value of the timeout (microseconds). (default 100 seconds)

#define NUMBER_OF_SOCKETS 3     // I am using 3 sockets in the program:
                                // - one for tun/tap: 'context.tun_fd'
                                // - one for connecting to the network. It may be
                                //     - context.network_mode_fd
                                //     - context.udp_mode_fd
                                //     - context.tcp_welcoming_fd and later context.tcp_server_fd
                                //     - context.tcp_client_fd
                                // - one for feedback packets: 'context.feedback_fd'

// colors for the debug info
#define ANSI_COLOR_RESET        "\x1b[0m"
#define ANSI_COLOR_RED          "\x1b[31m"
#define ANSI_COLOR_BOLD_RED     "\x1b[1;31m"
#define ANSI_COLOR_GREEN        "\x1b[32m"
#define ANSI_COLOR_BOLD_GREEN   "\x1b[1;32m"
#define ANSI_COLOR_BOLD_YELLOW  "\x1b[33m"
#define ANSI_COLOR_YELLOW       "\x1b[01;33m"
#define ANSI_COLOR_BLUE         "\x1b[34m"
#define ANSI_COLOR_BRIGHT_BLUE  "\x1b[94m"
#define ANSI_COLOR_MAGENTA      "\x1b[35m"
#define ANSI_COLOR_CYAN         "\x1b[36m"


// this struct includes all the variables used in different places of the code
// it is passed to the different functions
struct contextSimplemux {
  char mode;        // Network ('N') or UDP ('U') or TCP server ('S') or TCP client ('T')
  char tunnelMode;  // TUN ('U', default) or TAP ('T')
  char flavor;      // Normal ('N', default), Fast ('F'), Blast ('B')

  int rohcMode; // 0: ROHC is not used
                // 1: ROHC Unidirectional mode (headers are to be compressed/decompressed)
                // 2: ROHC Bidirectional Optimistic mode
                // 3: ROHC Bidirectional Reliable mode (not implemented yet)

  // variables for managing the network interfaces
  int tun_fd;             // file descriptor of the tun interface(no mux packet)
  int udp_mode_fd;        // file descriptor of the socket in UDP mode
  int network_mode_fd;    // file descriptor of the socket in Network mode
  int feedback_fd;        // file descriptor of the socket of the feedback received from the network interface
  int tcp_welcoming_fd;   // file descriptor of the TCP welcoming socket
  int tcp_client_fd;      // file descriptor of the TCP client socket
  int tcp_server_fd;      // file descriptor of the TCP server socket

  // structs for storing sockets
  struct sockaddr_in local;
  struct sockaddr_in remote;
  struct sockaddr_in feedback;
  struct sockaddr_in feedback_remote;
  struct sockaddr_in received;

  // network interface
  struct ifreq iface;

  // variables for storing the packets to multiplex
  int numPktsStoredFromTun;                     // number of packets received and not sent from tun (stored)
  uint8_t protocol[MAXPKTS];                    // protocol field of each packet (1 byte)
  uint16_t sizeSeparatorsToMultiplex[MAXPKTS];  // size of each Simplemux separator ('protocol' not included)
  uint8_t separatorsToMultiplex[MAXPKTS][3];    // Simplemux header ('protocol' not included), before sending it to the network
  uint16_t sizePacketsToMultiplex[MAXPKTS];     // size of each packet to be multiplexed. The maximum length is 65535 bytes
  uint8_t packetsToMultiplex[MAXPKTS][BUFSIZE]; // content of each packet to be multiplexed 
  int sizeMuxedPacket;                          // accumulated size of the multiplexed packet

  uint16_t length_muxed_packet;                 // length of the next TCP packet

  uint64_t timeLastSent;          // timestamp (us) when the last multiplexed packet was sent
  uint64_t microsecondsLeft;      // the time (us) until the period expires 

  // only for tcpserver mode
  bool acceptingTcpConnections;     // it is set to '1' if this is a TCP server and no connections have started

  // only for blast flavor
  struct packet *unconfirmedPacketsBlast;     // pointer to the list of unconfirmed packets (blast flavor)
  uint64_t blastTimestamps[0xFFFF+1];         // I will store 65536 different timestamps: one for each possible identifier
  uint64_t lastBlastHeartBeatSent;            // timestamp of the last heartbeat sent
  uint64_t lastBlastHeartBeatReceived;

  // variables for counting the arrived and sent packets
  uint32_t tun2net;           // number of packets read from tun
  uint32_t net2tun;           // number of packets read from net
  uint32_t feedback_pkts;     // number of ROHC feedback packets
  uint16_t blastIdentifier;   // Identifier field of the blast header

  char remote_ip[16];       // dotted quad IP string with the IP of the remote machine
  char local_ip[16];        // dotted quad IP string with the IP of the local machine
  uint16_t port;            // UDP/TCP port to be used for sending the multiplexed packets
  uint16_t port_feedback;   // UDP port to be used for sending the ROHC feedback packets, when using ROHC bidirectional
  uint8_t ipprotocol;

  char tun_if_name[IFNAMSIZ];    // name of the tun interface (e.g. "tun0")
  char mux_if_name[IFNAMSIZ];    // name of the network interface (e.g. "eth0")

  // variables for the log file
  char log_file_name[100];     // name of the log file  
  FILE *log_file;              // file descriptor of the log file
  int file_logging;            // it is set to 1 if logging into a file is enabled

  // parameters that control the multiplexing
  uint64_t timeout;       // (microseconds) if a packet arrives and the 'timeout' has expired (time from the  
                          //previous sending), the sending is triggered. default 100 seconds
  uint64_t period;        // (microseconds). If the 'period' expires, a packet is sent
  int limitNumpackets;    // limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
  int sizeThreshold;      // if the number of bytes stored is higher than this, a muxed packet is sent
  int userMtu;            // the MTU specified by the user (it must be <= interface_mtu)
  int selectedMtu;        // the MTU that will be used in the program ('-m' option)
  int sizeMax;            // threshold for the packet size ('-b' option)

  int firstHeaderWritten; // it indicates if the first header has been written or not

  // fixed size of the separator in fast flavor
  // added to the context in order to make this calculation only once
  int sizeSeparatorFastMode;

  // variables needed for TCP mode
  uint8_t protocol_rec;               // protocol field of the received muxed packet
                                      // this varialbe has to be here: in case of TCP, it may be
                                      //necessary to store the value of the protocol between packets
  uint16_t pendingBytesMuxedPacket;   // number of bytes that still have to be read (TCP, fast flavor)
  uint16_t readTcpBytes;              // number of bytes of the content that have been read (TCP, fast flavor)
  uint8_t readTcpSeparatorBytes;      // number of bytes of the fast separator that have been read (TCP, fast flavor)
};

#ifdef DEBUG
  void do_debug(int level, char *msg, ...);
  void do_debug_c(int level, char* color, char *msg, ...);
#endif

unsigned short in_cksum(unsigned short *addr, int len);

void BuildIPHeader( struct iphdr *iph,
                    uint16_t len_data,
                    uint8_t ipprotocol,
                    struct sockaddr_in local,
                    struct sockaddr_in remote );

void BuildFullIPPacket(struct iphdr iph, uint8_t *data_packet, uint16_t len_data, uint8_t *full_ip_packet);

void GetIpHeader(struct iphdr *iph, uint8_t *ip_packet);

void SetIpHeader(struct iphdr iph, uint8_t *ip_packet);

int cread(int fd, uint8_t *buf, int n);

int cwrite(int fd, uint8_t *buf, int n);

int read_n(int fd, uint8_t *buf, int n);

void my_err(char *msg, ...);

uint64_t GetTimeStamp();

uint8_t ToByte(bool b[8]);

void FromByte(uint8_t c, bool b[8]);

void PrintByte(int debug_level, int num_bits, bool b[8]);

void dump_packet (int packet_size, uint8_t packet[BUFSIZE]);

int date_and_time(char buffer[25]);

// global variable
extern int debug;     // 0:no debug
                      // 1:minimum debug level
                      // 2:medimum debug level
                      // 3:maximum debug level

// global variables related to ROHC compression
extern struct rohc_comp *compressor;         // the ROHC compressor
extern uint8_t ip_buffer[BUFSIZE];           // the buffer that will contain the IPv4 packet to compress
extern struct rohc_buf ip_packet;// = rohc_buf_init_empty(ip_buffer, BUFSIZE);  
extern uint8_t rohc_buffer[BUFSIZE];         // the buffer that will contain the resulting ROHC packet
extern struct rohc_buf rohc_packet;// = rohc_buf_init_empty(rohc_buffer, BUFSIZE);
extern unsigned int seed;
extern rohc_status_t status;
extern struct rohc_decomp *decompressor;     // the ROHC decompressor
extern uint8_t ip_buffer_d[BUFSIZE];         // the buffer that will contain the resulting IP decompressed packet
extern struct rohc_buf ip_packet_d;// = rohc_buf_init_empty(ip_buffer_d, BUFSIZE);
extern uint8_t rohc_buffer_d[BUFSIZE];       // the buffer that will contain the ROHC packet to decompress
extern struct rohc_buf rohc_packet_d;// = rohc_buf_init_empty(rohc_buffer_d, BUFSIZE);

// structures to handle ROHC feedback
extern uint8_t rcvd_feedback_buffer_d[BUFSIZE];  // the buffer that will contain the ROHC feedback packet received
extern struct rohc_buf rcvd_feedback;// = rohc_buf_init_empty(rcvd_feedback_buffer_d, BUFSIZE);

extern uint8_t feedback_send_buffer_d[BUFSIZE];  // the buffer that will contain the ROHC feedback packet to be sent
extern struct rohc_buf feedback_send;// = rohc_buf_init_empty(feedback_send_buffer_d, BUFSIZE);