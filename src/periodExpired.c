#include "tunToNet.c"

void periodExpiredblastFlavor (struct contextSimplemux* context)
{
  // blast flavor
  #ifdef ASSERT
    assert(context->flavor == 'B');
  #endif

  // I may be here because of two different causes (both may have been accomplished):
  // - period expired
  // - heartbeat period expired

  uint64_t now_microsec = GetTimeStamp();

  // - period expired
  if(now_microsec - context->timeLastSent > context->period) {
    if(now_microsec - context->lastBlastHeartBeatReceived > HEARTBEATDEADLINE) {
      // heartbeat from the other side not received recently
      //so it seems there are problems at the other side
      #ifdef DEBUG
        if(context->lastBlastHeartBeatReceived == 0) {
          do_debug_c( 3,
                      ANSI_COLOR_BLUE,
                      " Period expired. But nothing is sent because no heartbeat has been received yet\n");
        }
        else {
          do_debug_c( 3,
                      ANSI_COLOR_BLUE,
                      " Period expired. But nothing is sent because the last heartbeat was received %"PRIu64" us ago\n",
                      now_microsec - context->lastBlastHeartBeatReceived);
        }
      #endif
    }
    else {
      // heartbeat from the other side received recently
      //so the other side is running correctly

      // send the expired packets
      int n = sendExpiredPackets(context, now_microsec);

      if (n > 0) {
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_BLUE,
                      " Period expired: Sent %d blast packets (copies) at the end of the period\n",
                      n);
        #endif           
      }
      else {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_BLUE,
                      " Period expired: Nothing to send\n");
        #endif         
      }        
    }            
  }

  // check if the heartbeat period is expired
  if(now_microsec - (context->lastBlastHeartBeatSent) > HEARTBEATPERIOD) {
    // heartbeat period expired: send a heartbeat to the other side

    struct packet heartBeat;
    heartBeat.header.packetSize = 0;
    heartBeat.header.protocolID = 0;
    heartBeat.header.identifier = 0;
    heartBeat.header.ACK = HEARTBEAT;

    sendPacketBlastFlavor(context, &heartBeat);

    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_BOLD_YELLOW,
                  " Sent blast heartbeat to the network");

      do_debug_c( 3,
                  ANSI_COLOR_BOLD_YELLOW,
                  " (%"PRIu64" > %"PRIu64")",
                  now_microsec - context->lastBlastHeartBeatSent,
                  HEARTBEATPERIOD);

      do_debug(1, "\n");
    #endif

    context->lastBlastHeartBeatSent = now_microsec;          
  }
  else {
    // heartbeat period not expired. Do nothing

    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BOLD_YELLOW,
                  " Not sending blast heartbeat to the network (%"PRIu64" < %"PRIu64")\n",
                  now_microsec - context->lastBlastHeartBeatSent,
                  HEARTBEATPERIOD);
    #endif
  }
}


void periodExpiredNoblastFlavor ( struct contextSimplemux* context)
{
  // normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  // There are some packets stored

  // it will be '1' when the Single-Protocol-Bit of the first header is '1'
  int single_protocol;

  if(context->flavor == 'N') {
    // normal flavor

    // calculate if all the packets belong to the same protocol
    single_protocol = 1;
    for (int k = 1; k < context->numPktsStoredFromTun ; k++) {
      if (context->protocol[k] != context->protocol[k-1])
        single_protocol = 0;
    }

    // Add the Single Protocol Bit in the first header (the most significant bit)
    // It is 1 if all the multiplexed packets belong to the same protocol
    if (single_protocol == 1) {
       // this puts a '1' in the most significant bit position
      context->separatorsToMultiplex[0][0] = context->separatorsToMultiplex[0][0] + 0x80;

      // one byte corresponding to the 'protocol' field of the first header
      context->sizeMuxedPacket = context->sizeMuxedPacket + 1;
    }
    else {
      // one byte per packet, corresponding to the 'protocol' field
      context->sizeMuxedPacket = context->sizeMuxedPacket + context->numPktsStoredFromTun;
    }

    #ifdef DEBUG
      // calculate the time difference
      uint64_t now_microsec = GetTimeStamp();
      uint64_t time_difference = now_microsec - context->timeLastSent; 
      if (debug>0) {
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "\n");

        do_debug_c( 1,
                    ANSI_COLOR_CYAN,
                    "SENDING TRIGGERED (Period expired). Time since last trigger: %"PRIu64" us\n",
                    time_difference);

        if (single_protocol) {
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      " Normal flavor. All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
        }
        else {
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      " Normal flavor. Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",
                      context->numPktsStoredFromTun);
        }
        switch (context->mode) {
          case UDP_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " bytes\n");  
          break;

          case TCP_CLIENT_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " bytes\n");   
          break;

          case TCP_SERVER_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " bytes\n");   
          break;

          case NETWORK_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_CYAN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->sizeMuxedPacket + IPv4_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_CYAN,
                        " bytes\n"); 
          break;
        }
      }
    #endif
  }
  else {
    // fast flavor
    // in Fast flavor the Protocol is sent in every separator

    // in this case, the value of 'single_protocol' is not relevant,
    //but it is needed by 'buildMultiplexedPacket()'
    single_protocol = 1;

    #ifdef DEBUG
      // calculate the time difference
      uint64_t now_microsec = GetTimeStamp();
      uint64_t time_difference = now_microsec - context->timeLastSent;
      if (debug>0) {
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "\n");

        do_debug_c( 1,
                    ANSI_COLOR_CYAN,
                    "SENDING TRIGGERED (Period expired). Time since last trigger: ",
                    time_difference);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%"PRIu64"",
                    time_difference);
        do_debug_c( 1,
                    ANSI_COLOR_CYAN,
                    " usec\n");

        do_debug_c( 2,
                    ANSI_COLOR_CYAN,
                    " Fast flavor: Added 1 Protocol byte in each separator. Total ");
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->numPktsStoredFromTun);
        do_debug_c( 2,
                    ANSI_COLOR_CYAN,
                    " bytes\n");

        switch (context->mode) {
          case UDP_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        sizeof(uint8_t) * context->numPktsStoredFromTun + context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " bytes\n");  

          break;

          case TCP_CLIENT_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " bytes\n");
 
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        sizeof(uint8_t) * context->numPktsStoredFromTun + context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " bytes\n");  
          break;

          case TCP_SERVER_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " bytes\n");
 
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        sizeof(uint8_t) * context->numPktsStoredFromTun + context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " bytes\n");  
          break;

          case NETWORK_MODE:
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Added tunneling header: ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        IPv4_HEADER_SIZE);
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " bytes\n");

            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " Writing ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->numPktsStoredFromTun);
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " packets to network: ");  
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        sizeof(uint8_t) * context->numPktsStoredFromTun + context->sizeMuxedPacket + IPv4_HEADER_SIZE);  
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        " bytes\n");  
          break;
        }
      }
    #endif
  }

  // build the multiplexed packet
  uint16_t total_length;          // total length of the built multiplexed packet
  uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

  total_length = buildMultiplexedPacket ( context,
                                          single_protocol,
                                          muxed_packet);

  // send the multiplexed packet
  switch (context->mode) {
    
    case NETWORK_MODE: ;
      // build the header
      struct iphdr ipheader;
      BuildIPHeader(&ipheader,
                    total_length,
                    context->ipprotocol,
                    context->local,
                    context->remote);

      // build the full IP multiplexed packet
      uint8_t full_ip_packet[BUFSIZE];
      BuildFullIPPacket(ipheader,
                        muxed_packet,
                        total_length,
                        full_ip_packet);

      // send the packet
      if (sendto (context->network_mode_fd,
                  full_ip_packet, total_length + sizeof(struct iphdr),
                  0,
                  (struct sockaddr *) &(context->remote),
                  sizeof (struct sockaddr)) < 0)
      {
        perror ("sendto() failed ");
        exit (EXIT_FAILURE);
      }

      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  //"%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n",
                  "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tperiod\n",
                  GetTimeStamp(),
                  context->sizeMuxedPacket + IPv4_HEADER_SIZE,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  0,  // there is no period in network mode
                  context->numPktsStoredFromTun);  
      }
    break;
    
    case UDP_MODE:
      // send the packet. I don't need to build the header, because I have a UDP socket  
      if (sendto( context->udp_mode_fd,
                  muxed_packet,
                  total_length,
                  0,
                  (struct sockaddr *)&(context->remote),
                  sizeof(context->remote))==-1)
      {
        perror("sendto()");
        exit (EXIT_FAILURE);
      }

      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  //"%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n",
                  "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tperiod\n",
                  GetTimeStamp(),
                  context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  ntohs(context->remote.sin_port),
                  context->numPktsStoredFromTun);  
      }
    break;

    case TCP_SERVER_MODE:
      // send the packet. I don't need to build the header, because I have a TCP socket

      // FIXME: This said 'tcp_welcoming_fd', but I think it was a bug            
      if (write(context->tcp_server_fd,
                muxed_packet,
                total_length)==-1)
      {
        perror("write() in TCP server mode failed");
        exit (EXIT_FAILURE);  
      }

      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  //"%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n",
                  "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tperiod\n",
                  GetTimeStamp(),
                  context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  ntohs(context->remote.sin_port),
                  context->numPktsStoredFromTun);  
      }
    break;

    case TCP_CLIENT_MODE:
      // send the packet. I don't need to build the header, because I have a TCP socket  
      if (write(context->tcp_client_fd,
                muxed_packet,
                total_length)==-1)
      {
        perror("write() in TCP client mode failed");
        exit (EXIT_FAILURE);  
      }

      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  //"%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n",
                  "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tperiod\n",
                  GetTimeStamp(),
                  context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  ntohs(context->remote.sin_port),
                  context->numPktsStoredFromTun);  
      }
    break;
  }

  // I have sent a packet, so I set to 0 the "first_header_written" bit
  context->firstHeaderWritten = 0;

  // reset the length and the number of packets
  context->sizeMuxedPacket = 0 ;
  context->numPktsStoredFromTun = 0;
}