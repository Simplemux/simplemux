#include "simplemux.h"

#ifdef USINGROHC
// these 'static' functions are only used in this .c file

// The -Wextra option in GCC enables several additional warnings, including those for
//unused variables. When you pass functions as pointers, you might still get these
//warnings if the parameters of those functions are not used within the function body.
// I use __attribute__((unused)) to avoid the warnings
static int gen_random_num(const struct rohc_comp *const comp __attribute__((unused)),
                          void *const user_context __attribute__((unused)))
{
  return rand();
}

/**
 * @brief Callback to print traces of the RoHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level    The priority level of the trace
 * @param entity  The entity that emitted the trace among:
 *          \li ROHC_TRACE_COMP
 *          \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *          the trace is related to
 * @param format  The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt __attribute__((unused)),
                              const rohc_trace_level_t level __attribute__((unused)),
                              const rohc_trace_entity_t entity __attribute__((unused)),
                              const int profile __attribute__((unused)),
                              const char *const format,
                              ...)
{
  // Only prints ROHC messages if debug level is > 2
  #ifdef DEBUG
    if ( debug > 2 ) {
      va_list args;
      va_start(args, format);
      vfprintf(stdout, format, args);
      va_end(args);
    }
  #endif
}


/**
 * @brief The RTP detection callback which does detect RTP stream.
 * it assumes that UDP packets belonging to certain ports are RTP packets
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rtp_detect( const uint8_t *const ip __attribute__((unused)),
                        const uint8_t *const udp,
                        const uint8_t *const payload __attribute__((unused)),
                        const unsigned int payload_size __attribute__((unused)),
                        void *const rtp_private __attribute__((unused)))
{
  const size_t default_rtp_ports_nr = 5;
  unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
  uint16_t udp_dport;
  bool is_rtp = false;
  size_t i;

  if (udp == NULL) {
    return false;
  }

  /* get the UDP destination port */
  memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

  /* is the UDP destination port in the list of ports reserved for RTP
   * traffic by default (for compatibility reasons) */
  for(i = 0; i < default_rtp_ports_nr; i++) {
    if(ntohs(udp_dport) == default_rtp_ports[i]) {
      is_rtp = true;
      break;
    }
  }
  return is_rtp;
}


// initialize RoHC header compression
// declared as 'static' because it is only used by 'main()'
static int initRohc(contextSimplemux* context)
{
  // present some debug info
  #ifdef DEBUG
    switch(context->rohcMode) {
      case 0:
        do_debug_c(1, ANSI_COLOR_MAGENTA, "RoHC not activated\n", debug);
        break;
      case 1:
        do_debug_c(1, ANSI_COLOR_MAGENTA, "RoHC Unidirectional Mode\n", debug);
        break;
      case 2:
        do_debug_c(1, ANSI_COLOR_MAGENTA, "RoHC Bidirectional Optimistic Mode\n", debug);
        break;
      /*case 3:
        do_debug (1, "RoHC Bidirectional Reliable Mode\n", debug);  // Bidirectional Reliable mode (not implemented yet)
        break;*/
    }
  #endif

  if ( context->rohcMode > 0 ) {
    // initialize the random generator
    seed = time(NULL);
    srand(seed);
    
    /* Create a RoHC compressor with Large CIDs and the largest MAX_CID
     * possible for large CIDs */
    compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, gen_random_num, NULL);
    if(compressor == NULL) {
      fprintf(stderr, "failed to create the RoHC compressor\n");
      /*fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
      if ( context->log_file != NULL )
        fclose (context->log_file);
      return 1;*/
      goto error;
    }
    
    #ifdef DEBUG
      do_debug_c(1, ANSI_COLOR_RESET, "RoHC compressor created. Profiles: ");
    #endif
    
    // Set the callback function to be used for detecting RTP.
    // RTP is not detected automatically. So you have to create a callback function "rtp_detect" where you specify the conditions.
    // In our case we will consider as RTP the UDP packets belonging to certain ports
    if(!rohc_comp_set_rtp_detection_cb(compressor, rtp_detect, NULL)) {
      fprintf(stderr, "failed to set RTP detection callback\n");
      /*fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
      if ( context->log_file != NULL )
        fclose (context->log_file);
      return 1;*/
      goto error;
    }

    // set the function that will manage the RoHC compressing traces (it will be 'print_rohc_traces')
    if(!rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL)) {
      fprintf(stderr, "failed to set the callback for traces on compressor\n");
      goto release_compressor;
    }

    // Enable the RoHC compression profiles
    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED)) {
      fprintf(stderr, "failed to enable the Uncompressed compression profile\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "Uncompressed. ");
      #endif
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP)) {
      fprintf(stderr, "failed to enable the IP-only compression profile\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "IP-only. ");
      #endif
    }

    if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP, ROHC_PROFILE_UDPLITE, -1)) {
      fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite compression profiles\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "IP/UDP. IP/UDP-Lite. ");
      #endif
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP)) {
      fprintf(stderr, "failed to enable the RTP compression profile\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "RTP (UDP ports 1234, 36780, 33238, 5020, 5002). ");
      #endif
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP)) {
      fprintf(stderr, "failed to enable the ESP compression profile\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "ESP. ");
      #endif
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP)) {
      fprintf(stderr, "failed to enable the TCP compression profile\n");
      goto release_compressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "TCP. ");
      #endif
    }
    #ifdef DEBUG
      do_debug_c(1, ANSI_COLOR_RESET, "\n");
    #endif


    /* Create a RoHC decompressor to operate:
    *  - with large CIDs use ROHC_LARGE_CID, ROHC_LARGE_CID_MAX
    *  - with small CIDs use ROHC_SMALL_CID, ROHC_SMALL_CID_MAX maximum of 5 streams (MAX_CID = 4),
    *  - ROHC_O_MODE: Bidirectional Optimistic mode (O-mode)
    *  - ROHC_U_MODE: Unidirectional mode (U-mode).    */
    if ( context->rohcMode == 1 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);  // Unidirectional mode
    }
    else if ( context->rohcMode == 2 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);  // Bidirectional Optimistic mode
    }
    /*else if ( rohcMode == 3 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);  // Bidirectional Reliable mode (not implemented yet)
    }*/

    if(decompressor == NULL)
    {
      fprintf(stderr, "failed create the RoHC decompressor\n");
      goto release_decompressor;
    }

    #ifdef DEBUG
      do_debug_c(1, ANSI_COLOR_RESET, "RoHC decompressor created. Profiles: ");
    #endif

    // set the function that will manage the RoHC decompressing traces (it will be 'print_rohc_traces')
    if(!rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL)) {
      fprintf(stderr, "failed to set the callback for traces on decompressor\n");
      goto release_decompressor;
    }

    // enable rohc decompression profiles
    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the Uncompressed decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "Uncompressed. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_IP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the IP-only decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "IP-only. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the IP/UDP decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "IP/UDP. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDPLITE, -1);
    if(!status)
    {
      fprintf(stderr, "failed to enable the IP/UDP-Lite decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "IP/UDP-Lite. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_RTP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the RTP decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "RTP. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_ESP,-1);
    if(!status)  {
    fprintf(stderr, "failed to enable the ESP decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "ESP. ");
      #endif
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_TCP, -1);
    if(!status) {
      fprintf(stderr, "failed to enable the TCP decompression profile\n");
      goto release_decompressor;
    }
    else {
      #ifdef DEBUG
        do_debug_c(1, ANSI_COLOR_RESET, "TCP. ");
      #endif
    }

    #ifdef DEBUG
      do_debug(1, "\n");
    #endif
  }

  return 1;

  /******* labels ************/
  release_compressor:
    rohc_comp_free(compressor);
    return -1;

  release_decompressor:
    rohc_decomp_free(decompressor);
    return -1;
  
  error:
    fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
    if ( context->log_file != NULL )
      fclose (context->log_file);
    return -1;
}
#endif

// main Simplemux program
int main(int argc, char *argv[]) {

  // almost all the variables are stored in 'context'
  contextSimplemux context;

  // set the initial values of some context variables
  initContext(&context);

  const int on = 1;   // needed when creating a socket

  // read command line options
  char *progname;
  progname = argv[0];    // argument used when calling the program

  // no arguments specified by the user. Print usage and finish
  if (argc == 1 ) {
    // print the instructions
    usage (progname);
  }
  else {
    parseCommandLine(argc, argv, &context);

    argv += optind;
    argc -= optind;

    int correctOptions = checkCommandLineOptions(argc, progname, &context);
    if (correctOptions == 0)
      exit(1);

    // open the log file
    if ( context.file_logging == 1 ) {
      if (strcmp(context.log_file_name, "stdout") == 0) {
        context.log_file = stdout;
      } else {
        context.log_file = fopen(context.log_file_name, "w");
        if (context.log_file == NULL) my_err("Error: cannot open the log file!\n");
      }
    }

    #ifdef DEBUG
      // check debug option
      if ( debug < 0 ) debug = 0;
      else if ( debug > 3 ) debug = 3;
      do_debug (1 , "debug level set to %i\n", debug);
    #endif

    #ifdef USINGROHC
      // check ROHC option
      if ( context.rohcMode < 0 ) {
        context.rohcMode = 0;
      }
      else if ( context.rohcMode > 2 ) { 
        context.rohcMode = 2;
      }
    #endif


    // initialize the tun/tap interface
    initTunTapInterface(&context);

    // Initialize the sockets
    int correctSocket = 1;
    correctSocket = socketRequest(&context, /*&ipheader,*/ on);
    if (correctSocket == 1) {
      my_err("Error creating the sockets\n");
      exit(1);
    }

    // calculate the MTU
    initSizeMax(&context);

    // initialize the triggering parameters
    initTriggerParameters(&context);

    #ifdef USINGROHC
      // I only need the feedback socket if ROHC is activated
      //but I create it in case the other extreme sends ROHC packets
      feedbackSocketRequest(&context);
      
      // If ROHC has been selected, it has to be initialized
      // see the API here: https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/
      initRohc(&context);
    #endif

    #ifdef DEBUG
      do_debug_c(1, ANSI_COLOR_RESET, "\n");
    #endif
    
    /** prepare the POLL structure **/
    // it has size 3 (NUMBER_OF_SOCKETS), because it handles 3 sockets
    // - tun/tap socket where demuxed packets are sent/received
    // - feedback socket
    // - socket where muxed packets are sent/received. It can be:
    //      - Network mode: IP raw socket
    //      - UDP mode: UDP socket
    //      - TCP server mode
    //      - TCP client mode
    struct pollfd* fds_poll = malloc(NUMBER_OF_SOCKETS * sizeof(struct pollfd));
    memset(fds_poll, 0, NUMBER_OF_SOCKETS * sizeof(struct pollfd));
  
    fds_poll[0].fd = context.tun_fd;
    fds_poll[0].events = POLLIN;

    if ( context.mode== NETWORK_MODE )
      fds_poll[1].fd = context.network_mode_fd;
    else if ( context.mode== UDP_MODE )
      fds_poll[1].fd = context.udp_mode_fd;
    else if ( context.mode==TCP_SERVER_MODE )
      fds_poll[1].fd = context.tcp_welcoming_fd;
    else
      fds_poll[1].fd = context.tcp_client_fd;
    fds_poll[1].events = POLLIN;

    #ifdef USINGROHC
      fds_poll[2].fd = context.feedback_fd;
      fds_poll[2].events = POLLIN;
    #endif
    
    // set the current moment as the moment of the last sending
    context.timeLastSent = GetTimeStamp();  
      
    // initializations for blast flavor
    if(context.flavor == 'B')
      initBlastFlavor(&context);

    uint64_t now_microsec; // variable to store timestamps

    /*****************************************/
    /************** Main loop ****************/
    /*****************************************/
    while(1) {
    
      // Initialize the timeout data structure
      if(context.flavor == 'B') {
        // blast flavor
        context.timeLastSent = findLastSentTimestamp(context.unconfirmedPacketsBlast);

        #ifdef DEBUG
          if(debug > 2)
            printList(&context.unconfirmedPacketsBlast);
        #endif

        now_microsec = GetTimeStamp();

        if (context.timeLastSent == 0) {
          context.timeLastSent = now_microsec;
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_YELLOW,
                        "%"PRIu64" No blast packet is waiting to be sent to the network\n",
                        now_microsec);
          #endif
        }

        if(context.timeLastSent + context.period > now_microsec) {
          context.microsecondsLeft = context.timeLastSent + context.period - now_microsec;
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_YELLOW,
                        "%"PRIu64" The next blast packet will be sent in %"PRIu64" us\n",
                        now_microsec,
                        context.microsecondsLeft);
          #endif      
        }
        else {
          // the period is already expired
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_YELLOW,
                        "%"PRIu64" Call the poll with limit 0\n",
                        now_microsec);
          #endif
          context.microsecondsLeft = 0;
        }

        // in blast flavor, heartbeats have to be sent periodically
        // if the time to the next heartbeat is smaller than the time to the next sending of a blast packet,
        //then the time has to be reduced
        uint64_t microsecondsToNextHeartBeat = context.lastBlastHeartBeatSent + HEARTBEATPERIOD - now_microsec;

        // choose the smallest one
        if(microsecondsToNextHeartBeat < context.microsecondsLeft)
          context.microsecondsLeft = microsecondsToNextHeartBeat;
      }

      else {
        // not in blast flavor
        now_microsec = GetTimeStamp();

        if ( context.period > (now_microsec - context.timeLastSent)) {
          // the period is not expired
          context.microsecondsLeft = (context.period - (now_microsec - context.timeLastSent));
        }
        else {
          // the period is expired
          context.microsecondsLeft = 0;
        }        

        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_YELLOW,
                      "Time last sending: %"PRIu64" us\n",
                      context.timeLastSent);
          do_debug_c( 3,
                      ANSI_COLOR_YELLOW,
                      "The next packet will be sent in %"PRIu64" us\n",
                      context.microsecondsLeft);
        #endif
      }

      int milliseconds_left = (int)(context.microsecondsLeft / 1000.0);
      
      /** POLL **/
      // check if a frame has arrived to any of the file descriptors
      // - the first argument is the pollfd struct
      // - the second argument is '3', i.e. the number of sockets NUMBER_OF_SOCKETS
      // - third argument: the timeout specifies the number of milliseconds that
      //   poll() should block waiting for a file descriptor to become ready.
      int fd2read = poll(fds_poll, NUMBER_OF_SOCKETS, milliseconds_left);

      /********************************/
      /**** Error in poll function ****/
      /********************************/
      if(fd2read < 0) {
        if(fd2read == -1 || errno != EINTR ) {
  
        }
        else {
          perror("Error in poll function");
          return -1;
        }
      }
  
      /*******************************************/
      /**** A frame has arrived to one socket ****/
      /*******************************************/
      // a frame has arrived to one of the sockets in 'fds_poll'
      else if (fd2read > 0) {

        /******************************************************************/
        /*************** TCP connection request from a client *************/
        /******************************************************************/
        // a connection request has arrived to the welcoming socket
        if ((fds_poll[1].revents & POLLIN) && (context.mode==TCP_SERVER_MODE) && (context.acceptingTcpConnections == true) ) {

          // accept the connection
          struct sockaddr_in TCPpair;
          unsigned int len = sizeof(struct sockaddr);
          context.tcp_server_fd = accept(context.tcp_welcoming_fd, (struct sockaddr*)&TCPpair, &len);
          
          if ( DISABLE_NAGLE == 1 ) {
            // disable NAGLE algorigthm, see https://holmeshe.me/network-essentials-setsockopt-TCP_NODELAY/
            int flags =1;
            setsockopt(context.tcp_client_fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
          }

          // from now on, the TCP welcoming socket will NOT accept any other connection
          // FIXME: Does this make sense?
          context.acceptingTcpConnections = false;
  
          if(context.tcp_server_fd <= 0) {
            perror("Error in 'accept()': TCP welcoming Socket");
          }
  
          // change the descriptor to that of context.tcp_server_fd
          // from now on, context.tcp_server_fd will be used
          fds_poll[1].fd = context.tcp_server_fd;
          //if(context.tcp_server_fd > maxfd) maxfd = context.tcp_server_fd;
          
          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        "TCP connection started by the client. Socket for connecting to the client: %d\n",
                        context.tcp_server_fd);
          #endif       
        }
        
        /*****************************************************************************/
        /***************** NET to tun. demux and decompress **************************/
        /*****************************************************************************/
  
        // data arrived at the network interface: read, demux, decompress and forward it.
        // In TCP_SERVER_MODE, I will only enter here if the TCP connection is already started
        // in the rest of modes, I will enter here if a muxed packet has arrived        
        else if ( (fds_poll[1].revents & POLLIN) && 
                  (((context.mode== TCP_SERVER_MODE) && (context.acceptingTcpConnections == false)) ||
                  (context.mode== NETWORK_MODE) || 
                  (context.mode== UDP_MODE) ||
                  (context.mode== TCP_CLIENT_MODE) ) )
        {
          int is_multiplexed_packet;
          int nread_from_net;                 // number of bytes read from network which will be demultiplexed
          uint8_t buffer_from_net[BUFSIZE];   // stores the packet received from the network, before sending it to tun
          uint16_t packet_length;

          is_multiplexed_packet = readPacketFromNet(&context,
                                                    buffer_from_net,
                                                    &nread_from_net,
                                                    &packet_length);
    
          // now 'buffer_from_net' may contain a full packet or frame.
          // check if the packet is a multiplexed one
          if (is_multiplexed_packet == -1) {
            // I have read nothing
          }
          
          else if (is_multiplexed_packet == 1) {
            #ifdef USINGROHC
            demuxBundleFromNet( &context,
                                nread_from_net,
                                packet_length,
                                buffer_from_net,
                                &status);
            #else
            demuxBundleFromNet( &context,
                                nread_from_net,
                                packet_length,
                                buffer_from_net);
            #endif
          }
  
          else { // is_multiplexed_packet == 0
            // packet with the correct destination port, but a source port different from the multiplexing one
            // if the packet does not come from the multiplexing port, write it directly into the tun interface
            #ifdef DEBUG
              do_debug_c( 1,
                          ANSI_COLOR_RED,
                          "NON-SIMPLEMUX PACKET #%"PRIu32": Non-multiplexed packet arrived to the Simplemux port. Writing %i bytes to tun/tap\n",
                          context.net2tun,
                          nread_from_net);
            #endif
            
            if (cwrite (context.tun_fd,
                        buffer_from_net,
                        nread_from_net) != nread_from_net)
            {
              perror("could not write the non-multiplexed packet correctly");
            }
            else {
              // write the log file
              if ( context.log_file != NULL ) {
                // the packet is good
                fprintf(context.log_file,
                        "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                        GetTimeStamp(),
                        nread_from_net,
                        context.net2tun,
                        inet_ntoa(context.remote.sin_addr),
                        ntohs(context.remote.sin_port));

                fflush(context.log_file);              
              }
            }
          }
        }
  
        #ifdef USINGROHC
        /****************************************************************************************************************/    
        /******* ROHC feedback packet from the remote decompressor to be delivered to the local compressor **************/
        /****************************************************************************************************************/
  
        /*** ROHC feedback data arrived at the network interface: read it in order to deliver it to the local compressor ***/
  
        // the ROHC mode only affects the decompressor. So if I receive a ROHC feedback packet, I will use it
        // this implies that if the origin is in ROHC Unidirectional mode and the destination in Bidirectional, feedback will still work
        else if(fds_poll[2].revents & POLLIN) {
        
          int nread_from_net; // number of bytes read from network which will be demultiplexed
          uint8_t buffer_from_net[BUFSIZE];         // stores the packet received from the network, before sending it to tun

          // a packet has been received from the network, destinated to the feedbadk port. 'slen_feedback' is the length of the IP address
          socklen_t slen_feedback = sizeof(context.feedback);   // size of the socket. The type is like an int, but adequate for the size of the socket
          nread_from_net = recvfrom ( context.feedback_fd,
                                      buffer_from_net,
                                      BUFSIZE,
                                      0,
                                      (struct sockaddr *)&(context.feedback_remote),
                                      &slen_feedback );
  
          if (nread_from_net == -1) perror ("recvfrom()");
  
          // now buffer_from_net contains a full packet or frame.
          // check if the packet comes (source port) from the feedback port (default 55556).  (Its destination port IS the feedback port)  
          if (context.port_feedback == ntohs(context.feedback_remote.sin_port)) {
  
            // the packet comes from the feedback port (default 55556)
            #ifdef DEBUG
              do_debug_c( 1,
                          ANSI_COLOR_MAGENTA,
                          "FEEDBACK PACKET #%lu: Read RoHC feedback packet (",
                          context.feedback_pkts);
              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%i",
                          nread_from_net);
              do_debug_c( 1,
                          ANSI_COLOR_MAGENTA,
                          " bytes) from ");
              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          inet_ntoa(context.feedback_remote.sin_addr));
              do_debug_c( 1,
                          ANSI_COLOR_MAGENTA,
                          ":");
              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%d\n",
                          ntohs(context.feedback_remote.sin_port));
            #endif
  
            context.feedback_pkts ++;
  
            // write the log file
            if ( context.log_file != NULL ) {
              fprintf(context.log_file, "%"PRIu64"\trec\tRoHC feedback\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                      GetTimeStamp(),
                      nread_from_net,
                      context.feedback_pkts,
                      inet_ntoa(context.feedback_remote.sin_addr),
                      ntohs(context.feedback_remote.sin_port));

              fflush(context.log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
            }
  
            // reset the buffer where the packet is to be stored
            rohc_buf_reset (&rohc_packet_d);
  
            // Copy the compressed length and the compressed packet
            rohc_packet_d.len = nread_from_net;
      
            // Copy the packet itself
            for (int l = 0; l < nread_from_net ; l++) {
              rohc_buf_byte_at(rohc_packet_d, l) = buffer_from_net[l];
            }

            #ifdef DEBUG
              // dump the ROHC packet on terminal
              if (debug>0) {
                do_debug_c( 2,
                            ANSI_COLOR_MAGENTA,
                            " ROHC feedback packet received\n");

                dump_packet ( rohc_packet_d.len, rohc_packet_d.data );

                do_debug_c( 2,
                            ANSI_COLOR_MAGENTA,
                            "\n");
              }

  
              // deliver the feedback received to the local compressor
              //https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html    
              if ( rohc_comp_deliver_feedback2 ( compressor, rohc_packet_d ) == false ) {
                do_debug_c( 3,
                            ANSI_COLOR_MAGENTA,
                            "Error delivering feedback to the compressor");
              }
              else {
                do_debug_c( 3,
                            ANSI_COLOR_MAGENTA,
                            "Feedback delivered to the compressor: %i bytes\n",
                            rohc_packet_d.len);
              }
            #endif  
            // the information received does not have to be decompressed, because it has been 
            // generated as feedback on the other side.
            // So I don't have to decompress the packet
          }
          else {
  
            // packet with destination port 55556, but a source port different from the feedback one
            // if the packet does not come from the feedback port, write it directly into the tun interface
            #ifdef DEBUG
              do_debug_c( 1,
                          ANSI_COLOR_MAGENTA,
                          "NON-FEEDBACK PACKET %"PRIu32": Non-feedback packet arrived to feecback port. Writing %i bytes to tun\n",
                          context.net2tun, nread_from_net);
            #endif

            if (cwrite (context.tun_fd,
                        buffer_from_net,
                        nread_from_net) != nread_from_net)
            {
              perror("could not write the non-feedback packet correctly");
            }
            else {
              // write the log file
              if ( context.log_file != NULL ) {
                // the packet is good
                fprintf(context.log_file,
                        "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                        GetTimeStamp(),
                        nread_from_net,
                        context.net2tun,
                        inet_ntoa(context.remote.sin_addr),
                        ntohs(context.remote.sin_port));

                fflush(context.log_file);              
              }
            }
          }
        }
        #endif

        /**************************************************************************************/  
        /***************** TUN to NET: compress and multiplex *********************************/
        /**************************************************************************************/
  
        // data arrived at tun/tap: read it, store it, and check if the stored
        //packets should be written to the network
  
        /* FD_ISSET tests if a file descriptor is part of the set */
        //else if(FD_ISSET(context.tun_fd, &rd_set)) {
        else if(fds_poll[0].revents & POLLIN) {

          if (context.flavor == 'B') {
            tunToNetBlastFlavor(&context);
          }
          else {
            // not in blast flavor

            // increase the counter of the number of packets read from tun
            context.tun2net++;

            tunToNetNoBlastFlavor(&context);
          }
        }
      }  

      /*************************************************************************************/  
      /*** Period expired: multiplex in normal/fast flavor; send expired in blast flavor ***/
      /*************************************************************************************/  

      // The period has expired
      // Check if there is something stored, and send it
      // since there is no new packet, it is not necessary to compress anything here
      else {
        // fd2read == 0
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "Poll timeout expired\n");
        #endif
        
        if(context.flavor == 'B') {
          // blast flavor
          // go through the list and send all the packets with 'now_microsec > sentTimestamp + period'
          periodExpiredblastFlavor (&context);
        }
        else {
          // not in blast flavor
          if ( context.numPktsStoredFromTun > 0 ) {
            // There are some packets stored
            //send them
            periodExpiredNoblastFlavor (&context);
          }
          else {
            // No packet arrived
            #ifdef DEBUG
              do_debug_c( 3,
                          ANSI_COLOR_RESET,
                          "Period expired. Nothing to be sent\n");
            #endif
          }
          // restart the period
          context.timeLastSent = now_microsec;
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_YELLOW,
                        "%"PRIu64" Period expired\n",
                        context.timeLastSent);
          #endif
        }
      }     
    }  // end while(1)

    // free the variables
    free(fds_poll);

    return(0);
  }
}