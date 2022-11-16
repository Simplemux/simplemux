#include "simplemux.h"

int main(int argc, char *argv[]) {

  // almost all the variables are stored in 'context'
  struct contextSimplemux context;

  // set the initial values of some context variables
  initContext(&context);

  int fd2read;
  
  const int on = 1;                   // needed when creating a socket

  struct sockaddr_in TCPpair;

  struct iphdr ipheader;              // Variable used to create an IP header when needed

  socklen_t slen = sizeof(context.remote);              // size of the socket. The type is like an int, but adequate for the size of the socket
  socklen_t slen_feedback = sizeof(context.feedback);   // size of the socket. The type is like an int, but adequate for the size of the socket

  uint8_t protocol_rec;                     // protocol field of the received muxed packet

  uint16_t pending_bytes_muxed_packet = 0;  // number of bytes that still have to be read (TCP, fast flavor)
  uint16_t read_tcp_bytes = 0;              // number of bytes of the content that have been read (TCP, fast flavor)
  uint8_t read_tcp_bytes_separator = 0;     // number of bytes of the fast separator that have been read (TCP, fast flavor)

  uint64_t now_microsec;                    // current time

  // fixed size of the separator in fast flavor
  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;



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

    checkCommandLineOptions(argc, progname, &context);

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
      do_debug ( 1 , "debug level set to %i\n", debug);
    #endif

    // check ROHC option
    if ( context.rohcMode < 0 ) {
      context.rohcMode = 0;
    }
    else if ( context.rohcMode > 2 ) { 
      context.rohcMode = 2;
    }


    // initialize the tun/tap interface
    initTunTapInterface(&context);

    // Initialize the sockets
    int correctSocket = 1;
    correctSocket = socketRequest(&context, &ipheader, on);
    if (correctSocket == 1) {
      my_err("Error creating the sockets\n");
      exit(1);
    }

    // calculate the MTU
    initSizeMax(&context);

    // initialize the triggering parameters
    initTriggerParameters(&context);

    // I only need the feedback socket if ROHC is activated
    //but I create it in case the other extreme sends ROHC packets
    feedbackSocketRequest(&context);
    
    // If ROHC has been selected, it has to be initialized
    // see the API here: https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/
    initRohc(&context);

    #ifdef DEBUG
      do_debug(1, "\n");
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
    fds_poll[1].fd = context.feedback_fd;
    if ( context.mode== NETWORK_MODE )
      fds_poll[2].fd = context.network_mode_fd;
    else if ( context.mode== UDP_MODE )
      fds_poll[2].fd = context.udp_mode_fd;
    else if ( context.mode==TCP_SERVER_MODE )
      fds_poll[2].fd = context.tcp_welcoming_fd;
    else
      fds_poll[2].fd = context.tcp_client_fd;
    
    fds_poll[0].events = POLLIN;
    fds_poll[1].events = POLLIN;
    fds_poll[2].events = POLLIN;


    // set the current moment as the moment of the last sending
    context.timeLastSent = GetTimeStamp();  
      
    // initializations for blast flavor
    if(context.flavor == 'B')
      initBlastFlavor(&context);


    /*****************************************/
    /************** Main loop ****************/
    /*****************************************/
    while(1) {
    
      /* Initialize the timeout data structure */

      if(context.flavor == 'B') {

        context.timeLastSent = findLastSentTimestamp(context.unconfirmedPacketsBlast);

        #ifdef DEBUG
          if(debug>1)
            printList(&context.unconfirmedPacketsBlast);
        #endif

        now_microsec = GetTimeStamp();
        //do_debug(1, " %"PRIu64": Starting the while\n", now_microsec);

        if (context.timeLastSent == 0) {
          context.timeLastSent = now_microsec;
          #ifdef DEBUG
            do_debug(2, "%"PRIu64" No blast packet is waiting to be sent to the network\n", now_microsec);
          #endif
        }

        if(context.timeLastSent + context.period > now_microsec) {
          context.microsecondsLeft = context.timeLastSent + context.period - now_microsec;
          #ifdef DEBUG
            do_debug(2, "%"PRIu64" The next blast packet will be sent in %"PRIu64" us\n", now_microsec, context.microsecondsLeft);
          #endif      
        }
        else {
          // the period is already expired
          #ifdef DEBUG
            do_debug(2, "%"PRIu64" Call the poll with limit 0\n", now_microsec);
          #endif
          context.microsecondsLeft = 0;
        }

        // in blast flavor, heartbeats have to be sent periodically
        // if the time to the next heartbeat is smaller than the time to the next blast sent,
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
          //printf("the period is expired\n");
          context.microsecondsLeft = 0;
        }        

        #ifdef DEBUG
          do_debug(3, " Time last sending: %"PRIu64" us\n", context.timeLastSent);
          do_debug(3, " The next packet will be sent in %"PRIu64" us\n", context.microsecondsLeft);
        #endif   
      }

      //if (context.microsecondsLeft > 0) do_debug(0,"%"PRIu64"\n", context.microsecondsLeft);
      int milliseconds_left = (int)(context.microsecondsLeft / 1000.0);
      //printf("milliseconds_left: %d", milliseconds_left);
      
      /** POLL **/
      // check if a frame has arrived to any of the file descriptors
      // - the first argument is the pollfd struct
      // - the second argument is '3', i.e. the number of sockets NUMBER_OF_SOCKETS
      // - third argument: the timeout specifies the number of milliseconds that
      //   poll() should block waiting for a file descriptor to become ready.
      fd2read = poll(fds_poll, NUMBER_OF_SOCKETS, milliseconds_left);

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
        //do_debug(0,"fd2read: %d; mode: %c; context.acceptingTcpConnections: %i\n", fd2read, mode, context.acceptingTcpConnections);

        /******************************************************************/
        /*************** TCP connection request from a client *************/
        /******************************************************************/
        // a connection request has arrived to the welcoming socket
        if ((fds_poll[2].revents & POLLIN) && (context.mode==TCP_SERVER_MODE) && (context.acceptingTcpConnections == true) ) {

          // accept the connection
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
          fds_poll[2].fd = context.tcp_server_fd;
          //if(context.tcp_server_fd > maxfd) maxfd = context.tcp_server_fd;
          
          #ifdef DEBUG
            do_debug(1,"TCP connection started by the client. Socket for connecting to the client: %d\n", context.tcp_server_fd);
          #endif       
        }
        
        /*****************************************************************************/
        /***************** NET to tun. demux and decompress **************************/
        /*****************************************************************************/
  
        // data arrived at the network interface: read, demux, decompress and forward it.
        // In TCP_SERVER_MODE, I will only enter here if the TCP connection is already started
        // in the rest of modes, I will enter here if a muxed packet has arrived        
        else if ( (fds_poll[2].revents & POLLIN) && 
                  (((context.mode== TCP_SERVER_MODE) && (context.acceptingTcpConnections == false))  ||
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
                                                    slen,
                                                    ipheader,
                                                    &protocol_rec,
                                                    &nread_from_net,
                                                    &packet_length,
                                                    &pending_bytes_muxed_packet,
                                                    size_separator_fast_mode,
                                                    &read_tcp_bytes_separator,
                                                    &read_tcp_bytes );
    
          // now 'buffer_from_net' may contain a full packet or frame.
          // check if the packet is a multiplexed one
          if (is_multiplexed_packet == -1) {
            // I have read nothing
          }
          
          else if (is_multiplexed_packet == 1) {
            demuxPacketFromNet( &context,
                                nread_from_net,
                                packet_length,
                                buffer_from_net,
                                &protocol_rec,
                                &status );
          }
  
          else { // is_multiplexed_packet == 0
            // packet with the correct destination port, but a source port different from the multiplexing one
            // if the packet does not come from the multiplexing port, write it directly into the tun interface
            #ifdef DEBUG
              do_debug(1, "NON-SIMPLEMUX PACKET #%"PRIu32": Non-multiplexed packet. Writing %i bytes to tun\n",
                context.net2tun, nread_from_net);
            #endif
            cwrite ( context.tun_fd, buffer_from_net, nread_from_net);
  
            // write the log file
            if ( context.log_file != NULL ) {
              // the packet is good
              fprintf (context.log_file, "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(),
                nread_from_net, context.net2tun, inet_ntoa(context.remote.sin_addr), ntohs(context.remote.sin_port));
              fflush(context.log_file);
            }
          }
        }
  
        /****************************************************************************************************************************/    
        /******* NET to tun. ROHC feedback packet from the remote decompressor to be delivered to the local compressor **************/
        /****************************************************************************************************************************/
  
        /*** ROHC feedback data arrived at the network interface: read it in order to deliver it to the local compressor ***/
  
        // the ROHC mode only affects the decompressor. So if I receive a ROHC feedback packet, I will use it
        // this implies that if the origin is in ROHC Unidirectional mode and the destination in Bidirectional, feedback will still work
  
        //else if ( FD_ISSET ( context.feedback_fd, &rd_set )) {    /* FD_ISSET tests to see if a file descriptor is part of the set */
        else if(fds_poll[1].revents & POLLIN) {
        
          int nread_from_net; // number of bytes read from network which will be demultiplexed
          uint8_t buffer_from_net[BUFSIZE];         // stores the packet received from the network, before sending it to tun

          // a packet has been received from the network, destinated to the feedbadk port. 'slen_feedback' is the length of the IP address
          nread_from_net = recvfrom ( context.feedback_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&(context.feedback_remote), &slen_feedback );
  
          if (nread_from_net == -1) perror ("recvfrom()");
  
          // now buffer_from_net contains a full packet or frame.
          // check if the packet comes (source port) from the feedback port (default 55556).  (Its destination port IS the feedback port)
  
          if (context.port_feedback == ntohs(context.feedback_remote.sin_port)) {
  
            // the packet comes from the feedback port (default 55556)
            #ifdef DEBUG
              do_debug(1, "\nFEEDBACK %lu: Read ROHC feedback packet (%i bytes) from %s:%d\n",
                context.feedback_pkts, nread_from_net, inet_ntoa(context.feedback.sin_addr), ntohs(context.feedback.sin_port));
            #endif
  
            context.feedback_pkts ++;
  
            // write the log file
            if ( context.log_file != NULL ) {
              fprintf (context.log_file, "%"PRIu64"\trec\tROHC feedback\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                GetTimeStamp(), nread_from_net, context.feedback_pkts, inet_ntoa(context.remote.sin_addr), ntohs(context.remote.sin_port));
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
                do_debug(2, " ROHC feedback packet received\n");
                dump_packet ( rohc_packet_d.len, rohc_packet_d.data );
              }

  
              // deliver the feedback received to the local compressor
              //https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
    
              if ( rohc_comp_deliver_feedback2 ( compressor, rohc_packet_d ) == false ) {
                do_debug(3, "Error delivering feedback to the compressor");
              }
              else {
                do_debug(3, "Feedback delivered to the compressor: %i bytes\n", rohc_packet_d.len);
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
              do_debug(1, "NON-FEEDBACK PACKET %"PRIu32": Non-feedback packet. Writing %i bytes to tun\n", context.net2tun, nread_from_net);
            #endif
            cwrite ( context.tun_fd, buffer_from_net, nread_from_net);
  
            // write the log file
            if ( context.log_file != NULL ) {
              // the packet is good
              fprintf (context.log_file, "%"PRIu64"\tforward\tnative\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, context.net2tun, inet_ntoa(context.remote.sin_addr), ntohs(context.remote.sin_port));
              fflush(context.log_file);
            }
          }
        }
    
        /**************************************************************************************/  
        /***************** TUN to NET: compress and multiplex *********************************/
        /**************************************************************************************/
  
        /*** data arrived at tun: read it, and check if the stored packets should be written to the network ***/
        /*** a local packet has arrived to tun/tap, and it has to be multiplexed and sent to the destination***/
  
        /* FD_ISSET tests if a file descriptor is part of the set */
        //else if(FD_ISSET(context.tun_fd, &rd_set)) {
        else if(fds_poll[0].revents & POLLIN) {
          /* increase the counter of the number of packets read from tun*/
          context.tun2net++;

          if (context.flavor == 'B') {
            tunToNetBlastFlavor(&context);
          }
          else {
            // not in blast flavor
            tunToNetNoBlastFlavor(&context,
                                  &ipheader,
                                  size_separator_fast_mode);
          }
        }
      }  

      /*************************************************************************************/  
      /******************** Period expired: multiplex **************************************/
      /*************************************************************************************/  

      // The period has expired
      // Check if there is something stored, and send it
      // since there is no new packet, here it is not necessary to compress anything
      else {  // fd2read == 0
        #ifdef DEBUG
          do_debug(2, "Poll timeout expired\n");
        #endif
        
        if(context.flavor == 'B') {
          // go through the list and send all the packets with now_microsec > sentTimestamp + period
          periodExpiredblastFlavor (&context);
        }
        else {
          // not in blast flavor
          if ( context.num_pkts_stored_from_tun > 0 ) {
            // There are some packets stored
            // send them
            periodExpiredNoblastFlavor (&context,
                                        &ipheader );
          }
          else {
            // No packet arrived
            #ifdef DEBUG
              //do_debug(2, "Period expired. Nothing to be sent\n");
            #endif
          }
          // restart the period
          context.timeLastSent = now_microsec;
          #ifdef DEBUG
            do_debug(3, "%"PRIu64" Period expired\n", context.timeLastSent);
          #endif
        }
      }     
    }  // end while(1)

    // free the variables
    free(fds_poll);

    return(0);
  }
}