#include "help.c"

/*** Request a socket for writing and receiving muxed packets ***/
int socketRequest(struct contextSimplemux* context,
                  struct iphdr* ipheader,
                  struct ifreq* iface,
                  const int on)
{
  if ( context->mode== NETWORK_MODE ) {
    // initialize header IP to be used when receiving a packet in NETWORK mode
    memset(ipheader, 0, sizeof(struct iphdr));      
    memset (iface, 0, sizeof (*iface));
    snprintf (iface->ifr_name, sizeof (iface->ifr_name), "%s", context->mux_if_name);

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
      
      if((strcmp(ifa->ifa_name,context->mux_if_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
        if (s != 0) {
            printf("getnameinfo() failed: %s\n", gai_strerror(s));
            exit(EXIT_FAILURE);
        }
        do_debug(1,"Raw socket for multiplexing over IP open. Interface %s\nLocal IP %s. Protocol number %i\n", ifa->ifa_name, host, context->ipprotocol);
        break;
      }
    }

    // assign the local address for the multiplexed packets
    memset(&(context->local), 0, sizeof(context->local));
    context->local.sin_family = AF_INET;
    context->local.sin_addr.s_addr = inet_addr(host);  // convert the string 'host' to an IP address

    freeifaddrs(ifaddr);
    
     // assign the destination address for the multiplexed packets
    memset(&(context->remote), 0, sizeof(context->remote));
    context->remote.sin_family = AF_INET;
    context->remote.sin_addr.s_addr = inet_addr(context->remote_ip);    // remote IP. There are no ports in Network Mode

    // AF_INET (exactly the same as PF_INET)
    // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
    // context->network_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets
    // create a raw socket for reading and writing multiplexed packets belonging to protocol Simplemux (protocol ID 253)
    // Submit request for a raw socket descriptor
    if ((context->network_mode_fd = socket (AF_INET, SOCK_RAW, context->ipprotocol)) < 0) {
      perror ("Raw socket for sending muxed packets failed ");
      exit (EXIT_FAILURE);
    }
    else {
      do_debug(1,"Remote IP %s\n", inet_ntoa(context->remote.sin_addr));
    }

    // Set flag so socket expects us to provide IPv4 header
    if (setsockopt (context->network_mode_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
      perror ("setsockopt() failed to set IP_HDRINCL ");
      exit (EXIT_FAILURE);
    }

    // Bind the socket "context->network_mode_fd" to interface index
    // bind socket descriptor "context->network_mode_fd" to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    if (setsockopt (context->network_mode_fd, SOL_SOCKET, SO_BINDTODEVICE, iface, sizeof (*iface)) < 0) {
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
  else if ( context->mode== UDP_MODE ) {
    /*** Request a socket for writing and receiving muxed packets in UDP mode ***/
    // AF_INET (exactly the same as PF_INET)
    // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
    // context->udp_mode_fd is the file descriptor of the socket for managing arrived multiplexed packets

    /* creates an UN-named socket inside the kernel and returns
     * an integer known as socket descriptor
     * This function takes domain/family as its first argument.
     * For Internet family of IPv4 addresses we use AF_INET
     */
    if ( ( context->udp_mode_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) ) < 0) {
      perror("socket() UDP mode");
      exit(1);
    }

    // Use ioctl() to look up interface index which we will use to bind socket descriptor "context->udp_mode_fd" to
    memset (iface, 0, sizeof (*iface));
    snprintf (iface->ifr_name, sizeof (iface->ifr_name), "%s", context->mux_if_name);
    if (ioctl (context->udp_mode_fd, SIOCGIFINDEX, iface) < 0) {
      perror ("ioctl() failed to find interface (UDP mode) ");
      return (EXIT_FAILURE);
    }

    /*** get the IP address of the local interface ***/
    if (ioctl(context->udp_mode_fd, SIOCGIFADDR, iface) < 0) {
      perror ("ioctl() failed to find the IP address for local interface ");
      return (EXIT_FAILURE);
    }
    else {
      // source IPv4 address: it is the one of the interface
      strcpy (context->local_ip, inet_ntoa(((struct sockaddr_in *)&iface->ifr_addr)->sin_addr));
      do_debug(1, "Local IP for multiplexing %s\n", context->local_ip);
    }

    // assign the destination address and port for the multiplexed packets
    memset(&(context->remote), 0, sizeof(context->remote));
    context->remote.sin_family = AF_INET;
    context->remote.sin_addr.s_addr = inet_addr(context->remote_ip);    // remote IP
    context->remote.sin_port = htons(context->port);            // remote port

    // assign the local address and port for the multiplexed packets
    memset(&(context->local), 0, sizeof(context->local));
    context->local.sin_family = AF_INET;
    context->local.sin_addr.s_addr = inet_addr(context->local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
    context->local.sin_port = htons(context->port);            // local port

    // bind the socket "context->udp_mode_fd" to the local address and port
    if (bind(context->udp_mode_fd, (struct sockaddr *)&(context->local), sizeof(context->local))==-1) {
      perror("bind");
    }
    else {
      do_debug(1, "Socket for multiplexing over UDP open. Remote IP %s. Port %i\n", inet_ntoa(context->remote.sin_addr), htons(context->remote.sin_port)); 
    }
  }

  // TCP server mode
  else if (context->mode== TCP_SERVER_MODE ) {
    /*** Request a socket for writing and receiving muxed packets in TCP mode ***/
    // AF_INET (exactly the same as PF_INET)
    // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
    // context->tcp_welcoming_fd is the file descriptor of the socket for managing arrived multiplexed packets

    /* creates an UN-named socket inside the kernel and returns
     * an integer known as socket descriptor
     * This function takes domain/family as its first argument.
     * For Internet family of IPv4 addresses we use AF_INET
     */
    if ( ( context->tcp_welcoming_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
      perror("socket() TCP server mode");
      exit(1);
    }      

    // Use ioctl() to look up interface index which we will use to bind socket descriptor "context->udp_mode_fd" to
    memset (iface, 0, sizeof (*iface));
    snprintf (iface->ifr_name, sizeof (iface->ifr_name), "%s", context->mux_if_name);
              
    /*** get the IP address of the local interface ***/
    if (ioctl(context->tcp_welcoming_fd, SIOCGIFADDR, iface) < 0) {
      perror ("ioctl() failed to find the IP address for local interface ");
      return (EXIT_FAILURE);
    }
    else {
      // source IPv4 address: it is the one of the interface
      strcpy (context->local_ip, inet_ntoa(((struct sockaddr_in *)&iface->ifr_addr)->sin_addr));
      do_debug(1, "Local IP for multiplexing %s\n", context->local_ip);
    }

    // assign the destination address and port for the multiplexed packets
    memset(&(context->remote), 0, sizeof(context->remote));
    context->remote.sin_family = AF_INET;
    context->remote.sin_addr.s_addr = inet_addr(context->remote_ip);    // remote IP
    context->remote.sin_port = htons(context->port);            // remote port

    // assign the local address and port for the multiplexed packets
    memset(&(context->local), 0, sizeof(context->local));
    context->local.sin_family = AF_INET;
    context->local.sin_addr.s_addr = inet_addr(context->local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
    context->local.sin_port = htons(context->port);            // local port

    /* The call to the function "bind()" assigns the details specified
     * in the structure 'sockaddr' to the socket created above
     */  
    if (bind(context->tcp_welcoming_fd, (struct sockaddr *)&(context->local), sizeof(context->local))==-1) {
      perror("bind");
    }
    else {
      do_debug(1, "Welcoming TCP socket open. Remote IP %s. Port %i\n", inet_ntoa(context->remote.sin_addr), htons(context->remote.sin_port)); 
    }

    /* The call to the function "listen()" with second argument as 1 specifies
     * maximum number of client connections that the server will queue for this listening
     * socket.
     */
    listen(context->tcp_welcoming_fd, 1);
    
    // from now on, I will accept a TCP connection
    context->acceptingTcpConnections = true;
  }

  // TCP client mode
  else if ( context->mode== TCP_CLIENT_MODE ) {
    /*** Request a socket for writing and receiving muxed packets in TCP mode ***/
    // AF_INET (exactly the same as PF_INET)
    // transport_protocol:   SOCK_DGRAM creates a UDP socket (SOCK_STREAM would create a TCP socket)  
    // context->tcp_client_fd is the file descriptor of the socket for managing arrived multiplexed packets

    /* creates an UN-named socket inside the kernel and returns
     * an integer known as socket descriptor
     * This function takes domain/family as its first argument.
     * For Internet family of IPv4 addresses we use AF_INET
     */
    if ( ( context->tcp_client_fd = socket(AF_INET, SOCK_STREAM, 0) ) < 0) {
      perror("socket() TCP mode");
      exit(1);
    }
    
    // Use ioctl() to look up interface index which we will use to bind socket descriptor "context->udp_mode_fd" to
    memset (iface, 0, sizeof (*iface));
    snprintf (iface->ifr_name, sizeof (iface->ifr_name), "%s", context->mux_if_name);
    
    /*** get the IP address of the local interface ***/
    if (ioctl(context->tcp_client_fd, SIOCGIFADDR, iface) < 0) {
      perror ("ioctl() failed to find the IP address for local interface ");
      return (EXIT_FAILURE);
    }
    else {
      // source IPv4 address: it is the one of the interface
      strcpy (context->local_ip, inet_ntoa(((struct sockaddr_in *)&iface->ifr_addr)->sin_addr));
      do_debug(1, "Local IP for multiplexing %s\n", context->local_ip);
    }

    // assign the local address and port for the multiplexed packets
    memset(&(context->local), 0, sizeof(context->local));
    context->local.sin_family = AF_INET;
    context->local.sin_addr.s_addr = inet_addr(context->local_ip);    // local IP; "htonl(INADDR_ANY)" would take the IP address of any interface
    context->local.sin_port = htons(context->port);            // local port
    
    // assign the destination address and port for the multiplexed packets
    memset(&(context->remote), 0, sizeof(context->remote));
    context->remote.sin_family = AF_INET;
    context->remote.sin_addr.s_addr = inet_addr(context->remote_ip);    // remote IP
    context->remote.sin_port = htons(context->port);            // remote port


    /* Information like IP address of the remote host and its port is
     * bundled up in a structure and a call to function connect() is made
     * which tries to connect this socket with the socket (IP address and port)
     * of the remote host
     */
    if( connect(context->tcp_client_fd, (struct sockaddr *)&(context->remote), sizeof(context->remote)) < 0) {
      do_debug(1, "Trying to connect to the TCP server at %s:%i\n", inet_ntoa(context->remote.sin_addr), htons(context->remote.sin_port));
      perror("connect() error: TCP connect Failed. The TCP server did not accept the connection");
      return 1;
    }
    else {
      do_debug(1, "Successfully connected to the TCP server at %s:%i\n", inet_ntoa(context->remote.sin_addr), htons(context->remote.sin_port));

      if ( DISABLE_NAGLE == 1 ) {
        // disable NAGLE algorigthm, see https://holmeshe.me/network-essentials-setsockopt-TCP_NODELAY/
        int flags =1;
        setsockopt(context->tcp_client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));          
      }
      if ( QUICKACK == 1 ) {
        // enable quick ACK, i.e. avoid delayed ACKs
        int flags =1;
        setsockopt(context->tcp_client_fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&flags, sizeof(flags));          
      }
    }
  }
  return 0;
}