#include <netinet/ip.h>         // for using iphdr type

// If you comment the next lines, the program will be a bit faster
#define DEBUG 1   // if you comment this line, debug info is not allowed
#define LOGFILE 1 // if you comment this line, logs are not allowed
#define ASSERT 1  // if you comment this line, assertions are not allowed

#ifdef ASSERT
  #include <assert.h>           // for using assert()
#endif

#define BUFSIZE 2304
#define IPv4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
//#define TCP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 32      // in some cases, the TCP header is 32 byte long

#define TIME_UNTIL_SENDING_AGAIN_BLAST 5000000 // milliseconds before sending again a packet with the same ID
                                                // there are 65536 possible values of the ID
                                                // if a packet with an ID has been sent 5 seconds ago,
                                                //it can be sent again

// Protocol IDs, according to IANA
// see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define IPPROTO_IP_ON_IP 4          // IP on IP Protocol ID
#define IPPROTO_SIMPLEMUX 253       // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_FAST 254  // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_BLAST 252

#define IPPROTO_ROHC 142          // ROHC Protocol ID
#define IPPROTO_ETHERNET 143      // Ethernet Protocol ID

#define PORT 55555              // default port
#define PORT_FEEDBACK 55556     // port for sending ROHC feedback
#define PORT_FAST 55557         // port for sending Simplemux fast
#define PORT_BLAST 55558         // port for sending Simplemux fast

#define DISABLE_NAGLE 1         // disable TCP Nagle algorithm
#define QUICKACK 1              // enable TCP quick ACKs (non delayed)

#define Linux_TTL 64            // the initial value of the TTL IP field in Linux

#define NETWORK_MODE    'N'     // N: network mode
#define UDP_MODE        'U'     // U: UDP mode
#define TCP_CLIENT_MODE 'T'     // T: TCP client mode
#define TCP_SERVER_MODE 'S'     // S: TCP server mode

#define TUN_MODE 'U'            // T: tun mode, i.e. IP packets will be tunneled inside Simplemux
#define TAP_MODE 'A'            // A: tap mode, i.e. Ethernet frames will be tunneled inside Simplemux

#define MAXPKTS 100             // maximum number of packets to store
#define SIZE_PROTOCOL_FIELD 1   // 1: protocol field of one byte
                                // 2: protocol field of two bytes
#define SIZE_LENGTH_FIELD_FAST_MODE 2   // the length field in fast mode is always two bytes

#define HEARTBEATDEADLINE 5000000 // after this time, if a heartbeat is not received, packets will no longer be sent
#define HEARTBEATPERIOD 1000000 // a heartbeat will be sent every second
#define MAXTIMEOUT 100000000.0  // maximum value of the timeout (microseconds). (default 100 seconds)

struct contextSimplemux {
  char mode;        // Network (N) or UDP (U) or TCP server (S) or TCP client (T) mode
  char tunnelMode;  // TUN (U, default) or TAP (T) tunnel mode
  char flavor;      // Normal ('N'), Fast ('F'), Blast ('B')

  int rohcMode; // it is 0 if ROHC is not used
                // it is 1 for ROHC Unidirectional mode (headers are to be compressed/decompressed)
                // it is 2 for ROHC Bidirectional Optimistic mode
                // it is 3 for ROHC Bidirectional Reliable mode (not implemented yet)

  // variables for managing the network interfaces
  int tun_fd;                     // file descriptor of the tun interface(no mux packet)
  int udp_mode_fd;                // file descriptor of the socket in UDP mode
  int network_mode_fd;            // file descriptor of the socket in Network mode
  int feedback_fd;                // file descriptor of the socket of the feedback received from the network interface
  int tcp_welcoming_fd;           // file descriptor of the TCP welcoming socket
  int tcp_client_fd;              // file descriptor of the TCP socket
  int tcp_server_fd;

  // structs for storing sockets
  struct sockaddr_in local;
  struct sockaddr_in remote;
  struct sockaddr_in feedback;
  struct sockaddr_in feedback_remote;
  struct sockaddr_in received;  

  // variables for storing the packets to multiplex
  int num_pkts_stored_from_tun;                     // number of packets received and not sent from tun (stored)
  uint8_t protocol[MAXPKTS][SIZE_PROTOCOL_FIELD];   // protocol field of each packet
  uint16_t size_separators_to_multiplex[MAXPKTS];   // stores the size of the Simplemux separator. It does not include the "Protocol" field
  uint8_t separators_to_multiplex[MAXPKTS][3];      // stores the header ('protocol' not included) received from tun, before sending it to the network
  uint16_t size_packets_to_multiplex[MAXPKTS];      // stores the size of the received packet
  uint8_t packets_to_multiplex[MAXPKTS][BUFSIZE];   // stores the packets received from tun, before storing it or sending it to the network 
  int size_muxed_packet;                            // accumulated size of the multiplexed packet

  uint16_t length_muxed_packet;                     // length of the next TCP packet

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

  char remote_ip[16];       // dotted quad IP string with the IP of the remote machine
  char local_ip[16];        // dotted quad IP string with the IP of the local machine
  uint16_t port;            // UDP/TCP port to be used for sending the multiplexed packets
  uint16_t port_feedback;   // UDP port to be used for sending the ROHC feedback packets, when using ROHC bidirectional
  uint8_t ipprotocol;

  char tun_if_name[IFNAMSIZ];    // name of the tun interface (e.g. "tun0")
  char mux_if_name[IFNAMSIZ];    // name of the network interface (e.g. "eth0")

  // variables for the log file
  char log_file_name[100];       // name of the log file  
  FILE *log_file;              // file descriptor of the log file
  int file_logging;               // it is set to 1 if logging into a file is enabled

  // parameters that control the multiplexing
  uint64_t timeout;             // (microseconds) if a packet arrives and the 'timeout' has expired (time from the  
                                //previous sending), the sending is triggered. default 100 seconds
  uint64_t period;              // (microseconds). If the 'period' expires, a packet is sent
  int limit_numpackets_tun;     // limit of the number of tun packets that can be stored. it has to be smaller than MAXPKTS
  int size_threshold;           // if the number of bytes stored is higher than this, a muxed packet is sent
  int user_mtu;                 // the MTU specified by the user (it must be <= interface_mtu) 

  int firstHeaderWritten;       // it indicates if the first header has been written or not

  /*
  struct iphdr ipheader;              // IP header
  struct ifreq iface;                 // network interface

  int size_max;                       // maximum value of the packet size

  // fixed size of the separator in fast flavor
  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;
  */
};

#ifdef DEBUG
void do_debug(int level, char *msg, ...);
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