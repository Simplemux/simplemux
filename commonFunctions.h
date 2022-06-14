#include <netinet/ip.h>         // for using iphdr type

#define BUFSIZE 2304
#define IPv4_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
//#define TCP_HEADER_SIZE 20
#define TCP_HEADER_SIZE 32      // in some cases, the TCP header is 32 byte long


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