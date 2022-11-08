#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for using getopt()
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

#include <linux/tcp.h>          // makes it possible to use TCP_NODELAY (disable Nagle algorithm)
//#include "packetsToSend.c"      // FIXME: Why not .h ¿?
//#include "buildMuxedPacket.c"   // FIXME: Why not .h ¿?
//#include "commonFunctions.c"
//#include "netToTun.c"
//#include "tunToNet.c"
//#include "periodExpired.c"
//#include "help.c"
//#include "socketRequest.c"
//#include "rohc.c"
#include "init.c"

#define NUMBER_OF_SOCKETS 3     // I am using 3 sockets in the program