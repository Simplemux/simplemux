#include "tunToNet.c"

void periodExpiredblastFlavor ( struct contextSimplemux* context,
                                int fd )
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
      #ifdef DEBUG
        do_debug(2, " Period expired. But nothing is sent because the last heartbeat was received %"PRIu64" us ago\n", now_microsec - context->lastBlastHeartBeatReceived);
      #endif
    }
    else {
      // heartbeat from the other side received recently
      int n = sendExpiredPackects(context->unconfirmedPacketsBlast,
                                  now_microsec,
                                  context->period,
                                  fd,
                                  context->mode,
                                  context->remote,
                                  context->local);
      
      if (n > 0) {
        #ifdef DEBUG
          do_debug(1, " Period expired: Sent %d blast packets (copies) at the end of the period\n", n);
        #endif           
      }
      else {
        #ifdef DEBUG
          do_debug(2, " Period expired: Nothing to send\n");
        #endif         
      }        
    }            
  }

  // heartbeat period expired: send a heartbeat to the other side
  if(now_microsec - (context->lastBlastHeartBeatSent) > HEARTBEATPERIOD) {
    struct packet heartBeat;
    heartBeat.header.packetSize = 0;
    heartBeat.header.protocolID = 0;
    heartBeat.header.identifier = 0;
    heartBeat.header.ACK = HEARTBEAT;

    sendPacketBlastFlavor(fd,
                          context->mode,
                          &heartBeat,
                          context->remote,
                          context->local);

    #ifdef DEBUG
      do_debug(1," Sent blast heartbeat to the network: %"PRIu64" > %"PRIu64"\n", now_microsec - context->lastBlastHeartBeatSent, HEARTBEATPERIOD);
    #endif
    context->lastBlastHeartBeatSent = now_microsec;          
  }
  else {
    #ifdef DEBUG
      do_debug(2," Not sending blast heartbeat to the network: %"PRIu64" < %"PRIu64"\n", now_microsec - context->lastBlastHeartBeatSent, HEARTBEATPERIOD);
    #endif
  }
}


void periodExpiredNoblastFlavor ( struct contextSimplemux* context,
                                  int* first_header_written,
                                  struct iphdr* ipheader )
{
  // normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  // There are some packets stored

  // it is 1 when the Single-Protocol-Bit of the first header is 1
  int single_protocol;

  if(context->flavor == 'N') {
    // normal flavor

    // calculate if all the packets belong to the same protocol
    single_protocol = 1;
    for (int k = 1; k < context->num_pkts_stored_from_tun ; k++) {
      for (int l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
        if (context->protocol[k][l] != context->protocol[k-1][l]) single_protocol = 0;
      }
    }

    // Add the Single Protocol Bit in the first header (the most significant bit)
    // It is 1 if all the multiplexed packets belong to the same protocol
    if (single_protocol == 1) {
      context->separators_to_multiplex[0][0] = context->separators_to_multiplex[0][0] + 0x80;  // this puts a '1' in the most significant bit position
      (context->size_muxed_packet) = (context->size_muxed_packet) + 1;                // one byte corresponding to the 'protocol' field of the first header
    }
    else {
      (context->size_muxed_packet) = (context->size_muxed_packet) + context->num_pkts_stored_from_tun;    // one byte per packet, corresponding to the 'protocol' field
    }


    #ifdef DEBUG
      // calculate the time difference
      uint64_t now_microsec = GetTimeStamp();
      uint64_t time_difference = now_microsec - context->timeLastSent; 
      if (debug>0) {
        //do_debug(2, "\n");
        do_debug(1, "SENDING TRIGGERED (Period expired). Time since last trigger: %"PRIu64" us\n", time_difference);
        if (single_protocol) {
          do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
        }
        else {
          do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",context->num_pkts_stored_from_tun);
        }
        switch (context->mode) {
          case UDP_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, (context->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);  
          break;
          case TCP_CLIENT_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, (context->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
          break;
          case NETWORK_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, (context->size_muxed_packet) + IPv4_HEADER_SIZE );
          break;
        }
      }
    #endif
  }
  else {
    // fast flavor
    // in Fast flavor the Protocol is sent in every separator

    // in this case, the value of 'single_protocol' is not relevant,
    //but it is needed by 'build_multiplexed_packet()'
    single_protocol = 1;

    #ifdef DEBUG
      // calculate the time difference
      uint64_t now_microsec = GetTimeStamp();
      uint64_t time_difference = now_microsec - context->timeLastSent;
      if (debug>0) {
        //do_debug(2, "\n");
        do_debug(1, "SENDING TRIGGERED (Period expired). Time since last trigger: %" PRIu64 " usec\n", time_difference);
        do_debug(2, "   Fast mode: Added 1 Protocol byte in each separator. Total %i bytes\n",context->num_pkts_stored_from_tun);

        switch (context->mode) {
          case UDP_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, sizeof(uint8_t) * context->num_pkts_stored_from_tun + (context->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);  
          break;
          case TCP_CLIENT_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, sizeof(uint8_t) * context->num_pkts_stored_from_tun + (context->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);  
          break;
          case NETWORK_MODE:
            do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
            do_debug(1, " Writing %i packets to network: %i bytes\n", context->num_pkts_stored_from_tun, sizeof(uint8_t) * context->num_pkts_stored_from_tun + (context->size_muxed_packet) + IPv4_HEADER_SIZE );
          break;
        }
      }
    #endif
  }

  // build the multiplexed packet
  uint16_t total_length;          // total length of the built multiplexed packet
  uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

  total_length = build_multiplexed_packet ( context,
                                            single_protocol,
                                            muxed_packet);

  // send the multiplexed packet
  switch (context->mode) {
    
    case NETWORK_MODE:
      // build the header
      BuildIPHeader(ipheader, total_length, context->ipprotocol, context->local, context->remote);

      // build the full IP multiplexed packet
      uint8_t full_ip_packet[BUFSIZE];
      BuildFullIPPacket(*ipheader,
                        muxed_packet,
                        total_length,
                        full_ip_packet);

      // send the packet
      if (sendto (context->network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *) &(context->remote), sizeof (struct sockaddr)) < 0)  {
        perror ("sendto() failed ");
        exit (EXIT_FAILURE);
      }
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), (context->size_muxed_packet) + IPv4_HEADER_SIZE, context->tun2net, inet_ntoa(context->remote.sin_addr), context->num_pkts_stored_from_tun);  
      }
    break;
    
    case UDP_MODE:
      // send the packet. I don't need to build the header, because I have a UDP socket  
      if (sendto(context->udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&(context->remote), sizeof(context->remote))==-1) {
        perror("sendto()");
        exit (EXIT_FAILURE);
      }
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), (context->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, context->tun2net, inet_ntoa(context->remote.sin_addr), context->num_pkts_stored_from_tun);  
      }
    break;

    case TCP_SERVER_MODE:
      // send the packet. I don't need to build the header, because I have a TCP socket

      // FIXME: This said 'tcp_welcoming_fd', but I think it was a bug            
      if (write(context->tcp_server_fd, muxed_packet, total_length)==-1) {
        perror("write() in TCP server mode failed");
        exit (EXIT_FAILURE);  
      }
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), (context->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, context->tun2net, inet_ntoa(context->remote.sin_addr), context->num_pkts_stored_from_tun);  
      }
    break;

    case TCP_CLIENT_MODE:
      // send the packet. I don't need to build the header, because I have a TCP socket  
      if (write(context->tcp_client_fd, muxed_packet, total_length)==-1) {
        perror("write() in TCP client mode failed");
        exit (EXIT_FAILURE);  
      }
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tperiod\n", GetTimeStamp(), (context->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, context->tun2net, inet_ntoa(context->remote.sin_addr), context->num_pkts_stored_from_tun);  
      }
    break;
  }

  // I have sent a packet, so I set to 0 the "first_header_written" bit
  (*first_header_written) = 0;

  // reset the length and the number of packets
  (context->size_muxed_packet) = 0 ;
  context->num_pkts_stored_from_tun = 0;

}