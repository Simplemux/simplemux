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
#include <inttypes.h>           // for printing uint_64 numbers
#include <stdbool.h>            // for using the bool type
#include <rohc/rohc.h>          // for using header compression
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>
//#include <netinet/ip.h>         // for using iphdr type
#include <ifaddrs.h>            // required for using getifaddrs()
#include <netdb.h>              // required for using getifaddrs()
#include <poll.h>
#include <assert.h>
#include <linux/tcp.h>          // makes it possible to use TCP_NODELAY (disable Nagle algorithm)
//#include "packetsToSend.c"      // FIXME: Why not .h ¿?
//#include "buildMuxedPacket.c"   // FIXME: Why not .h ¿?
//#include "commonFunctions.c"
//#include "netToTun.c"
#include "tunToNet.c"

//#define BUFSIZE 2304            // buffer for reading from tun/tap interface, must be >= MTU of the network
//#define IPv4_HEADER_SIZE 20
//#define UDP_HEADER_SIZE 8
//#define TCP_HEADER_SIZE 20
//#define TCP_HEADER_SIZE 32      // in some cases, the TCP header is 32 byte long


#define NUMBER_OF_SOCKETS 3     // I am using 3 sockets in the program

#define PORT 55555              // default port
#define PORT_FEEDBACK 55556     // port for sending ROHC feedback
#define PORT_FAST 55557         // port for sending Simplemux fast
#define PORT_BLAST 55558         // port for sending Simplemux fast

#define MAXTIMEOUT 100000000.0  // maximum value of the timeout (microseconds). (default 100 seconds)
#define HEARTBEATPERIOD 1000000 // a heartbeat will be sent every second
//#define HEARTBEATDEADLINE 5000000 // after this time, if a heartbeat is not received, packets will no longer be sent

/*
// Protocol IDs, according to IANA
// see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define IPPROTO_IP_ON_IP 4          // IP on IP Protocol ID
#define IPPROTO_SIMPLEMUX 253       // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_FAST 254  // Simplemux Protocol ID (experimental number according to IANA)
#define IPPROTO_SIMPLEMUX_BLAST 252

#define IPPROTO_ROHC 142          // ROHC Protocol ID
#define IPPROTO_ETHERNET 143      // Ethernet Protocol ID
*/
//#define NETWORK_MODE    'N'     // N: network mode
//#define UDP_MODE        'U'     // U: UDP mode
//#define TCP_CLIENT_MODE 'T'     // T: TCP client mode
//#define TCP_SERVER_MODE 'S'     // S: TCP server mode

//#define TUN_MODE 'U'            // T: tun mode, i.e. IP packets will be tunneled inside Simplemux
//#define TAP_MODE 'A'            // A: tap mode, i.e. Ethernet frames will be tunneled inside Simplemux

//#define Linux_TTL 64            // the initial value of the TTL IP field in Linux

#define DISABLE_NAGLE 1         // disable TCP Nagle algorithm
#define QUICKACK 1              // enable TCP quick ACKs (non delayed)


//#define linkedList