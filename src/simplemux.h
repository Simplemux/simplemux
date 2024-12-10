//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <stdbool.h>            // for using the bool type
#include <unistd.h>           // for using getopt()
#include <net/if.h>
#include <linux/if_tun.h>     // for using tun/tap interfaces
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

#include <rohc/rohc.h>          // for using header compression
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>

//#include <netinet/ip.h>       // for using iphdr type
#include <ifaddrs.h>            // required for using getifaddrs()
#include <netdb.h>              // required for using getifaddrs()
#include <poll.h>

#include <linux/tcp.h>          // makes it possible to use TCP_NODELAY (disable Nagle algorithm)

#include "init.h"
#include "help.h"
#include "socketRequest.h"
#include "packetsToSend.h"
#include "periodExpired.h"
#include "netToTun.h"
#include "tunToNet.h"
#include "commonfunctions.h"