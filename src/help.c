#include "help.h"

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(char* progname) {
  fprintf(stderr, "Usage:\n");
  #ifdef USINGROHC
    fprintf(stderr, "%s -i <ifacename> -e <ifacename> -c <peerIP> -M <'network' or 'udp' or 'tcpclient' or 'tcpserver'> [-T 'tun' or 'tap'] [-p <port>] [-d <debug_level>] [-r <ROHC_option>] [-n <num_mux_tun>] [-m <MTU>] [-B <num_bytes_threshold>] [-t <timeout (microsec)>] [-P <period (microsec)>] [-l <log file name>] [-L] [-f] [-b]\n\n" , progname);
  #else
    fprintf(stderr, "%s -i <ifacename> -e <ifacename> -c <peerIP> -M <'network' or 'udp' or 'tcpclient' or 'tcpserver'> [-T 'tun' or 'tap'] [-p <port>] [-d <debug_level>] [-n <num_mux_tun>] [-m <MTU>] [-B <num_bytes_threshold>] [-t <timeout (microsec)>] [-P <period (microsec)>] [-l <log file name>] [-L] [-f] [-b]\n\n" , progname);
  #endif
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of tun/tap interface to be used for capturing native packets (mandatory)\n");
  fprintf(stderr, "-e <ifacename>: Name of local interface which IP will be used for reception of muxed packets, i.e., the tunnel local end (mandatory)\n");
  fprintf(stderr, "-c <peerIP>: specify peer destination IP address, i.e. the tunnel remote end (mandatory)\n");
  fprintf(stderr, "-M <mode>: 'network' or 'udp' or 'tcpclient' or 'tcpserver' mode (mandatory)\n");
  fprintf(stderr, "-T <tunnel mode>: 'tun' (default) or 'tap' mode\n");
  fprintf(stderr, "-f: fast flavor (compression rate is lower, but it is faster). Compulsory for TCP mode\n");
  fprintf(stderr, "-b: blast flavor (packets are sent until an application-level ACK is received from the other side). A period (-P) is needed in this case\n");
  fprintf(stderr, "-p <port>: port to listen on, and to connect to (default 55555)\n");
  #ifdef USINGROHC
    fprintf(stderr, "-d <debug_level>: Debug level. 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC)\n");
    fprintf(stderr, "-r <ROHC_option>: 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)\n");
  #else
    fprintf(stderr, "-d <debug_level>: Debug level. 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug\n");
  #endif
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