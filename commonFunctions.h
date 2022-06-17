#include <netinet/ip.h>         // for using iphdr type

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


#define Linux_TTL 64            // the initial value of the TTL IP field in Linux


#define NETWORK_MODE    'N'     // N: network mode
#define UDP_MODE        'U'     // U: UDP mode
#define TCP_CLIENT_MODE 'T'     // T: TCP client mode
#define TCP_SERVER_MODE 'S'     // S: TCP server mode

void do_debug(int level, char *msg, ...);

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