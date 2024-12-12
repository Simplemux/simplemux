#include "init.h"

// set the initial values of the context variables
void initContext(contextSimplemux* context)
{
  context->flavor = 'N';  // by default 'normal flavor' is selected
  context->rohcMode = 0;  // by default it is 0: ROHC is not used
  context->numPktsStoredFromTun = 0; 
  context->sizeMuxedPacket = 0;
  context->unconfirmedPacketsBlast = NULL;
  context->tun2net = 0;
  context->net2tun = 0; 
  context->feedback_pkts = 0;
  context->blastIdentifier = 0;
  context->acceptingTcpConnections = false;
  context->remote_ip[0] = '\0';
  context->local_ip[0] = '\0';
  context->port = PORT;
  context->port_feedback = PORT_FEEDBACK;
  context->ipprotocol = IPPROTO_SIMPLEMUX;
  context->tun_if_name[0] = '\0';
  context->mux_if_name[0] = '\0';
  context->log_file_name[0] = '\0';
  context->log_file = NULL;
  context->file_logging = 0;
  context->timeout = MAXTIMEOUT;
  context->period= MAXTIMEOUT;
  context->limitNumpackets = 0;
  context->sizeThreshold = 0;
  context->userMtu = 0;
  context->firstHeaderWritten = 0;
  context->sizeSeparatorFastMode = 1 + SIZE_LENGTH_FIELD_FAST_MODE;
  context->pendingBytesMuxedPacket = 0;
  context->readTcpBytes = 0;
  context->readTcpSeparatorBytes = 0;
}


// parse the command line options
void parseCommandLine(int argc, char *argv[], contextSimplemux* context)
{
  int option; // command line options
  char mode_string[10];
  char tunnel_mode_string[4];

  while((option = getopt(argc, argv, "i:e:M:T:c:p:n:B:t:P:l:d:r:m:fbhL")) > 0) {

    switch(option) {
      case 'd':
        debug = atoi(optarg);    // 0:no debug; 1:minimum debug; 2:medium debug; 3:maximum debug (incl. ROHC)
        break;
      case 'r':
        context->rohcMode = atoi(optarg);  // 0:no ROHC; 1:Unidirectional; 2: Bidirectional Optimistic; 3: Bidirectional Reliable (not available yet)
        break;
      case 'h':            // help
        usage(argv[0]);
        break;
      case 'i':            // put the name of the tun interface (e.g. "tun0") in 'tun_if_name'
        strncpy(context->tun_if_name, optarg, IFNAMSIZ-1);
        break;
      case 'M':            // network (N) or udp (U) or tcpclient (T) or tcpserver (S) mode
        strcpy(mode_string, optarg);

        // check 'mode_string' string and fill 'mode'
        if (strcmp(mode_string, "network") == 0) {
          #ifdef DEBUG
            do_debug(3, "the mode string is network\n");
          #endif
          context->mode = 'N';
        }
        else if (strcmp(mode_string, "udp") == 0) {
          #ifdef DEBUG
            do_debug(3, "the mode string is udp\n");
          #endif
          context->mode= 'U';
        }
        else if (strcmp(mode_string, "tcpserver") == 0) {
          #ifdef DEBUG
            do_debug(3, "the mode string is tcpserver\n");
          #endif
          context->mode= 'S';
        }
        else if (strcmp(mode_string, "tcpclient") == 0) {
          #ifdef DEBUG
            do_debug(3, "the mode string is tcpclient\n");
          #endif
          context->mode= 'T';
        }
        else {
          #ifdef DEBUG
            do_debug(3, "the mode string is not valid\n");
          #endif
        }
        #ifdef DEBUG
          do_debug(3, "mode_string: %s\n", mode_string);
        #endif
        break;
      case 'T':            // TUN (U) or TAP (A) tunnel mode
        strcpy(tunnel_mode_string, optarg);

        // check 'tunnel_mode' string and fill 'tunnelMode'
        if (strcmp(tunnel_mode_string, "tun") == 0) {
          #ifdef DEBUG
            do_debug(3, "the tunnel mode string is tun\n");
          #endif
          context->tunnelMode = 'U';
        }
        else if (strcmp(tunnel_mode_string, "tap") == 0){
          #ifdef DEBUG
            do_debug(3, "the tunnel mode string is tap\n");
          #endif
          context->tunnelMode = 'A';
        }
        else {
          #ifdef DEBUG
            do_debug(3, "the tunnel mode string is not valid\n");
          #endif
        }
        #ifdef DEBUG
          do_debug(3, "tunnel_mode_string: %s\n", tunnel_mode_string);
        #endif

        break;
      case 'f':            // fast flavor
        if(context->flavor == 'B') {
          // both -f and -b options have been selected
          my_err("fast ('-f') and blast (`-b') flavors are not compatible\n");
          usage(argv[0]);
        }
        else{
          context->flavor = 'F';
          context->port = PORT_FAST;   // by default, port = PORT. In fast flavor, it is PORT_FAST
          context->ipprotocol = IPPROTO_SIMPLEMUX_FAST; // in 'fast flavor', in 'network mode', use protocol 254
          #ifdef DEBUG
            do_debug_c(1, ANSI_COLOR_RESET, "Fast flavor selected\n");
          #endif        
        }
        break;
      case 'b':            // blast flavor
        if(context->flavor == 'F') {
          // both -f and -b options have been selected
          my_err("fast ('-f') and blast (`-b') flavors are not compatible\n");
          usage(argv[0]);
        }
        else{
          context->flavor = 'B';
          context->port = PORT_BLAST;   // by default, port = PORT. In blast flavor, it is PORT_BLAST
          context->ipprotocol = IPPROTO_SIMPLEMUX_BLAST; // in blast flavor, in network mode, use protocol 252
          #ifdef DEBUG
            do_debug_c(1, ANSI_COLOR_RESET, "Blast flavor selected\n");
          #endif
        }
        break;
      case 'e':            // copy the name of the network interface (e.g. 'eth0') in 'mux_if_name'
        strncpy(context->mux_if_name, optarg, IFNAMSIZ-1);
        break;
      case 'c':            // copy the destination address of the machine where the tunnel ends in 'remote_ip'
        strncpy(context->remote_ip, optarg, 16);
        break;
      case 'l':            // copy the name of the log file in 'log_file_name'
        strncpy(context->log_file_name, optarg, 100);
        context->file_logging = 1;
        break;
      case 'L':            // the name of the log file is assigned automatically
        date_and_time(context->log_file_name);
        context->file_logging = 1;
        break;
      case 'p':            // port number
        context->port = atoi(optarg);    // atoi() Parses a string interpreting its content as an 'int'
        context->port_feedback = context->port + 1;
        break;
      case 'n':            // limit of the number of packets for triggering a muxed packet
        context->limitNumpackets = atoi(optarg);
        break;
      case 'm':            // MTU forced by the user
        context->userMtu = atoi(optarg);
        break;
      case 'B':            // size threshold (in bytes) for triggering a muxed packet
        context->sizeThreshold = atoi(optarg);
        break;
      case 't':            // timeout for triggering a muxed packet
        context->timeout = atoll(optarg);
        break;
      case 'P':            // Period for triggering a muxed packet
        context->period = atoll(optarg);
        context->microsecondsLeft = context->period; 
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage(argv[0]);
        break;
    }
  }
}


// check the correctness of the command line options
int checkCommandLineOptions(int argc, char *progname, contextSimplemux* context)
{

  if(argc > 0) {
    my_err("Too many options\n");
    usage(progname);
    return 0;
  }

  // check interface options
  if(context->tun_if_name[0] == '\0') {
    my_err("Must specify a tun/tap interface name for native packets ('-i' option)\n");
    usage(progname);
    return 0;
  } else if(context->remote_ip[0] == '\0') {
    my_err("Must specify the IP address of the peer ('-c' option)\n");
    usage(progname);
    return 0;
  } else if(context->mux_if_name[0] == '\0') {
    my_err("Must specify the local interface name for multiplexed packets ('-e' option)\n");
    usage(progname);
    return 0;
  } 

  // check if a mode has been selected (mandatory)
  else if((context->mode!= NETWORK_MODE) && (context->mode!= UDP_MODE) && (context->mode!= TCP_CLIENT_MODE) && (context->mode!= TCP_SERVER_MODE)) {
    my_err("Must specify a valid mode ('-M' option MUST either be 'network', 'udp', 'tcpserver' or 'tcpclient')\n");
    usage(progname);
    return 0;
  } 

  // check if a tunnel mode has been selected (mandatory)
  else if((context->tunnelMode != TUN_MODE) && (context->tunnelMode != TAP_MODE)) {
    my_err("Must specify a valid tunnel mode ('-T' option MUST either be 'tun' or 'tap')\n");
    usage(progname);
    return 0;
  } 

  // TCP mode requires fast flavor
  else if(((context->mode== TCP_SERVER_MODE) || (context->mode== TCP_CLIENT_MODE)) && (context->flavor != 'F')) {
    my_err("TCP server ('-M tcpserver') and TCP client mode ('-M tcpclient') require fast flavor (option '-f')\n");
    usage(progname);
    return 0;
  }

  // Parameter n cannot be higher than MAXPKTS
  else if((context->limitNumpackets > MAXPKTS) && (context->flavor != 'B')) {
    my_err("The limit of the number of packets (-n %i) is higher than the maximum allowed (%i)\n", context->limitNumpackets, MAXPKTS);
    usage(progname);
    return 0;
  }

  // blast flavor is restricted
  else if(context->flavor == 'B') {
    if((context->mode== TCP_SERVER_MODE) || (context->mode== TCP_CLIENT_MODE)){
      my_err("blast flavor (-b) is not allowed in TCP server ('-M tcpserver') and TCP client mode ('-M tcpclient')\n");
      usage(progname);
      return 0;
    }
    if(context->rohcMode!=0) {
      my_err("blast flavor (-b) is not compatible with RoHC (-r)\n");
      usage(progname);
      return 0;     
    }
    if(context->sizeThreshold!=0) {
      my_err("blast flavor (-b) is not compatible with size threshold (-B)\n");
      usage(progname);
      return 0;     
    }
    if(context->timeout!=MAXTIMEOUT) {
      my_err("blast flavor (-b) is not compatible with timeout (-t)\n");
      usage(progname);
      return 0;     
    }
    if(context->limitNumpackets!=0) {
      my_err("blast flavor (-b) is not compatible with a limit of the number of packets. Only a packet is sent (-n)\n");
      usage(progname);
      return 0;     
    }
    if(context->period==MAXTIMEOUT) {
      my_err("In blast flavor (-b) you must specify a period (-P)\n");
      usage(progname);
      return 0;      
    }
  }
  return 1;
}


/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 *          flags can be IFF_TUN (1) or IFF_TAP (2)                       *
 **************************************************************************/
// explained here https://www.fatalerrors.org/a/tun-tap-interface-usage-guidance.html
// declared as 'static' because it is only used by 'initTunTapInterface()'
static int tun_alloc( char *dev,    // the name of an interface (or '\0')
                      int flags)
{
  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  // open the clone device
  // it is used as a starting point for creating any tun/tap virtual interface
  if( (fd = open(clonedev , O_RDWR)) < 0 ) { // Open with Read-Write
    #ifdef DEBUG
    //#if (defined (DEBUG))
      do_debug(0, "[tun_alloc] Could not open the Clone device ");
    #endif
    perror("Opening /dev/net/tun");
    return fd;
  }
  // if I am here, then the clone device has been opened for read/write
  #ifdef DEBUG
    do_debug(3, "[tun_alloc] Clone device open correctly\n");
  #endif

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


// initialize tun/tap interface
void initTunTapInterface(contextSimplemux* context)
{
  if (context->tunnelMode == TUN_MODE) {
    // tun tunnel mode (i.e. send IP packets)

    // initialize tun interface for native packets
    if ( (context->tun_fd = tun_alloc(context->tun_if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
      my_err("Error connecting to tun/tap interface for capturing native packets %s\n", context->tun_if_name);
      exit(1);
    }
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "Successfully connected to tun/tap interface for native packets %s\n",
                  context->tun_if_name);
    #endif
  }
  else if (context->tunnelMode == TAP_MODE) {
    // tap tunnel mode (i.e. send Ethernet frames)
    
    // ROHC mode cannot be used in tunnel mode TAP, because Ethernet headers cannot be compressed
    if (context->rohcMode != 0) {
      my_err("Error ROHC cannot be used in 'tap' mode (Ethernet headers cannot be compressed)\n");
      exit(1);          
    }        

    // initialize tap interface for native packets
    if ( (context->tun_fd = tun_alloc(context->tun_if_name, IFF_TAP | IFF_NO_PI)) < 0 ) {
      my_err("Error connecting to tap interface %s for capturing native Ethernet frames\n", context->tun_if_name);
      exit(1);
    }
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "Successfully connected to interface %s for Ethernet frames\n",
                  context->tun_if_name);
    #endif   
  }
  else exit(1); // this would be a failure
}


// it starts the context variables
// - selectedMtu
// - userMtu
// - sizeMax
void initSizeMax(contextSimplemux* context)
{
  // the real MTU of the interface
  int interface_mtu;

  /*** get the MTU of the local interface ***/
  if ( context->mode == UDP_MODE)  {
    if (ioctl(context->udp_mode_fd, SIOCGIFMTU, &context->iface) == -1)
      interface_mtu = 0;
    else interface_mtu = context->iface.ifr_mtu;
  }
  else if ( context->mode == NETWORK_MODE) {
    if (ioctl(context->network_mode_fd, SIOCGIFMTU, &context->iface) == -1)
      interface_mtu = 0;
    else interface_mtu = context->iface.ifr_mtu;
  }
  else if ( context->mode == TCP_SERVER_MODE ) {
    if (ioctl(context->tcp_welcoming_fd, SIOCGIFMTU, &context->iface) == -1)
      interface_mtu = 0;
    else interface_mtu = context->iface.ifr_mtu;
  }
  else if ( context->mode == TCP_CLIENT_MODE ) {
    if (ioctl(context->tcp_client_fd, SIOCGIFMTU, &context->iface) == -1)
      interface_mtu = 0;
    else interface_mtu = context->iface.ifr_mtu;
  }

  // check if the user has specified a bad MTU
  #ifdef DEBUG
    do_debug (1,
              "Local interface MTU: %i\t ",
              interface_mtu);

    if ( context->userMtu > 0 ) {
      do_debug (1,
                "User-selected MTU: %i\n",
                context->userMtu);
    }
    else {
      do_debug (1, "\n");
    }
  #endif

  if (context->userMtu > interface_mtu) {
    perror ("Error: The MTU specified by the user is higher than the MTU of the interface\n");
    exit (1);
  }
  else {

    // if the user has specified a MTU, I use it instead of network MTU
    if (context->userMtu > 0) {
      context->selectedMtu = context->userMtu;

    // otherwise, use the MTU of the local interface
    }
    else {
      context->selectedMtu = interface_mtu;
    }
  }

  if (context->selectedMtu > BUFSIZE ) {
    #ifdef DEBUG
      do_debug (1,
                "Selected MTU: %i\t Size of the buffer for packet storage: %i\n",
                context->selectedMtu, BUFSIZE);
    #endif
    perror ("Error: The MTU selected is higher than the size of the buffer defined.\nCheck #define BUFSIZE at the beginning of this application\n");
    exit (1);
  }

  // define the maximum size threshold
  switch ( context->mode) {
    case NETWORK_MODE:
      context->sizeMax = context->selectedMtu - IPv4_HEADER_SIZE ;
    break;
    
    case UDP_MODE:
      context->sizeMax = context->selectedMtu - IPv4_HEADER_SIZE - UDP_HEADER_SIZE ;
    break;
    
    case TCP_CLIENT_MODE:
      context->sizeMax = context->selectedMtu - IPv4_HEADER_SIZE - TCP_HEADER_SIZE;
    break;
    
    case TCP_SERVER_MODE:
      context->sizeMax = context->selectedMtu - IPv4_HEADER_SIZE - TCP_HEADER_SIZE;
    break;
  }

  // the size threshold has not been established by the user 
  if (context->sizeThreshold == 0 ) {
    context->sizeThreshold = context->sizeMax;
    #ifdef DEBUG
      //do_debug (1, "Size threshold established to the maximum: %i.", context->sizeMax);
    #endif
  }

  // the user has specified a too big size threshold
  if (context->sizeThreshold > context->sizeMax ) {
    #ifdef DEBUG
      do_debug (1,
                "Warning: Size threshold too big: %i. Automatically set to the maximum: %i\n",
                context->sizeThreshold, context->sizeMax);
    #endif
    context->sizeThreshold = context->sizeMax;
  }
}


// initialize trigger paramteter
// set the triggering parameters according to user selections (or default values)
void initTriggerParameters(contextSimplemux* context)
{
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
  if (( (context->sizeThreshold < context->sizeMax) || (context->timeout < MAXTIMEOUT) || (context->period < MAXTIMEOUT) ) && (context->limitNumpackets == 0))
    context->limitNumpackets = MAXPKTS;

  // if no option is set by the user, it is assumed that every packet will be sent immediately
  if (( (context->sizeThreshold == context->sizeMax) && (context->timeout == MAXTIMEOUT) && (context->period == MAXTIMEOUT)) && (context->limitNumpackets == 0))
    context->limitNumpackets = 1;

  #ifdef DEBUG
    do_debug (1,
              "Multiplexing policies: size threshold: %i. numpackets: %i. timeout: %"PRIu64"us. period: %"PRIu64"us\n",
              context->sizeThreshold,
              context->limitNumpackets,
              context->timeout,
              context->period);
  #endif
}


// initializations for blast flavor
void initBlastFlavor(contextSimplemux* context)
{
  // fill the vector of timestamps with zeroes
  for(int i=0; i < 0xFFFF + 1; i++) {
    context->blastTimestamps[i] = 0;
  }
  // fill the variables 'lastBlastHeartBeatSent' and 'lastBlastHeartBeatReceived'
  context->lastBlastHeartBeatSent = context->timeLastSent;
  context->lastBlastHeartBeatReceived = 0; // this means that I have received no heartbeats yet
}