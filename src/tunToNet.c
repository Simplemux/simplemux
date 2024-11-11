#include "netToTun.c"

// packet/frame arrived at tun: read it, and send a blast packet to the network
void tunToNetBlastFlavor (struct contextSimplemux* context)
{
  // blast flavor
  #ifdef ASSERT
    assert(context->flavor == 'B');
  #endif

  uint64_t now = GetTimeStamp();

  #ifdef DEBUG
    do_debug_c( 3,
                ANSI_COLOR_BRIGHT_BLUE,
                "%"PRIu64": NATIVE PACKET arrived from local computer (",
                now);

    do_debug_c( 3,
                ANSI_COLOR_RESET,
                "%s",
                context->tun_if_name);

    do_debug_c( 3,
                ANSI_COLOR_BRIGHT_BLUE,
                ")\n");
  #endif           

  // add a new empty packet to the list
  struct packet* thisPacket = insertLast(&context->unconfirmedPacketsBlast,0,NULL);

  // read the packet from context->tun_fd and add the data
  // use 'htons()' because these fields will be sent through the network
  thisPacket->header.packetSize = htons(cread (context->tun_fd, thisPacket->tunneledPacket, BUFSIZE));
  // the ID is the 16 LSBs of 'tun2net' (it is an uint32_t)
  thisPacket->header.identifier = htons((uint16_t)context->blastIdentifier); 

  #ifdef DEBUG
    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                "NATIVE PACKET #%"PRIu32" from ",
                context->tun2net);

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%s",
                context->tun_if_name);

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                ": ID ");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%i",
                ntohs(thisPacket->header.identifier));

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                ", Length ");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%i",
                ntohs(thisPacket->header.packetSize));

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                " bytes\n");
  #endif

  if (context->tunnelMode == TAP_MODE) {
    thisPacket->header.protocolID = IPPROTO_ETHERNET;
  }
  else if (context->tunnelMode == TUN_MODE) {
    thisPacket->header.protocolID = IPPROTO_IP_ON_IP;
  }

  // this packet will require an ACK
  thisPacket->header.ACK = ACKNEEDED;

  // send the packet to the network
  sendPacketBlastFlavor(context, thisPacket);

  #ifdef DEBUG
    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                " Sent blast packet to the network (");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%s",
                context->mux_if_name);

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                "). ID ");

     do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%i",
                ntohs(thisPacket->header.identifier));

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                ", Length ");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%i",
                ntohs(thisPacket->header.packetSize));

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                " bytes (plus headers)\n");
  #endif

  // No need to write in the log file here: it is done in 'sendPacketBlastFlavor()'

  // the packet has been sent. Store the timestamp
  thisPacket->sentTimestamp = now;

  if(now - (context->lastBlastHeartBeatReceived) > HEARTBEATDEADLINE) {
    // heartbeat from the other side not received recently
    if(delete(&context->unconfirmedPacketsBlast,
              ntohs(thisPacket->header.identifier))==false)
    {
      #ifdef DEBUG
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " The packet had already been removed from the list\n");
      #endif
    }
    else {
      #ifdef DEBUG
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " Packet with ID ");

        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(thisPacket->header.identifier));

        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " removed from the list\n");
      #endif
    }              
    #ifdef DEBUG
      if (context->lastBlastHeartBeatReceived == 0) {
        // no heartbeat has been received yet
        do_debug_c( 3,
                    ANSI_COLOR_RED,
                    " %"PRIu64" The arrived packet has not been stored because no heartbeat has been received yet. Total %i pkts stored\n",
                    now,
                    length(&context->unconfirmedPacketsBlast));   
      }
      else {
        // at least one heartbeat has arrived
        do_debug_c( 3,
                    ANSI_COLOR_RED,
                    " %"PRIu64" The arrived packet has not been stored because the last heartbeat was received %"PRIu64" us ago. Total %i pkts stored\n",
                    now,
                    now - context->lastBlastHeartBeatReceived,
                    length(&context->unconfirmedPacketsBlast));        
      }

    #endif
  }
  else {
    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BRIGHT_BLUE,
                  " %"PRIu64"",
                  thisPacket->sentTimestamp);

      do_debug_c( 2,
                  ANSI_COLOR_BRIGHT_BLUE,
                  " The arrived packet has been stored. Total ");

      do_debug_c( 2,
                  ANSI_COLOR_RESET,
                  "%i",
                  length(&context->unconfirmedPacketsBlast));

      do_debug_c( 2,
                  ANSI_COLOR_BRIGHT_BLUE,
                  " pkts stored\n");

      if(debug > 1)
        dump_packet ( ntohs(thisPacket->header.packetSize), thisPacket->tunneledPacket );
    #endif            
  }
}


bool checkPacketSize (struct contextSimplemux* context, uint16_t size)
{
  bool dropPacket = false;

  // UDP mode
  if (context->mode == UDP_MODE) {
    if ( size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3 > context->selectedMtu ) {
      dropPacket = true;
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n",
                    size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3,
                    context->selectedMtu);
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          fprintf ( context->log_file,
                    "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\n",
                    GetTimeStamp(),
                    size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3,
                    context->tun2net,
                    inet_ntoa(context->remote.sin_addr),
                    ntohs(context->remote.sin_port));

          // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
          fflush(context->log_file);
        }
      #endif
    }
  }
  
  // TCP client or TCP server mode
  else if ((context->mode == TCP_CLIENT_MODE) || (context->mode == TCP_SERVER_MODE)) {          
    if ( size + IPv4_HEADER_SIZE + TCP_HEADER_SIZE + 3 > context->selectedMtu ) {
      dropPacket = true;

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n",
                    size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3,
                    context->selectedMtu);
      #endif

      #ifdef LOGFILE
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\n",
                  GetTimeStamp(),
                  size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  ntohs(context->remote.sin_port));

        // If the IO is buffered, I have to insert fflush(fp) after the write
        fflush(context->log_file);
      }
      #endif
    }
  }
  
  // network mode
  else {
    if ( size + IPv4_HEADER_SIZE + 3 > context->selectedMtu ) {
      dropPacket = true;

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n",
                    size + IPv4_HEADER_SIZE + 3,
                    context->selectedMtu);
      #endif

      #ifdef LOGFILE
      // write the log file
      if ( context->log_file != NULL ) {
        // FIXME: remove 'nun_packets_stored_from_tun' from the expression
        fprintf ( context->log_file,
                  "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\n",
                  GetTimeStamp(),
                  size + IPv4_HEADER_SIZE + 3,
                  context->tun2net,
                  inet_ntoa(context->remote.sin_addr),
                  ntohs(context->remote.sin_port),
                  context->numPktsStoredFromTun);

        // If the IO is buffered, I have to insert fflush(fp) after the write
        fflush(context->log_file);
      }
      #endif
    }
  }
  return dropPacket;
}


void compressPacket(struct contextSimplemux* context, uint16_t size)
{
  // note
  // the next global variables are used:
  //  struct rohc_buf ip_packet
  //  rohc_status_t status

  // copy the length read from tun to the buffer where the packet to be compressed is stored
  ip_packet.len = size;

  // copy the packet
  memcpy(rohc_buf_data_at(ip_packet, 0), context->packetsToMultiplex[context->numPktsStoredFromTun], size);

  // reset the buffer where the rohc packet is to be stored
  rohc_buf_reset (&rohc_packet);

  // compress the IP packet
  // note: 'rohc_status_t status' is a global variable
  status = rohc_compress4(compressor, ip_packet, &rohc_packet);

  // check the result of the compression
  if(status == ROHC_STATUS_SEGMENT) {
    /* success: compression succeeded, but resulting ROHC packet was too
     * large for the Maximum Reconstructed Reception Unit (MRRU) configured
     * with \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
     * first ROHC segment and \ref rohc_comp_get_segment can be used to
     * retrieve the next ones. */
  }

  else if (status == ROHC_STATUS_OK) {
    /* success: compression succeeded, and resulting ROHC packet fits the
    * Maximum Reconstructed Reception Unit (MRRU) configured with
    * \ref rohc_comp_set_mrru, the rohc_packet buffer contains the
    * rohc_packet_len bytes of the ROHC packet */

    // since this packet has been compressed with ROHC, its protocol number must be 142
    // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    context->protocol[context->numPktsStoredFromTun] = IPPROTO_ROHC;

    // copy the compressed length
    context->sizePacketsToMultiplex[context->numPktsStoredFromTun] = rohc_packet.len;

    // copy the compressed packet itself
    for (uint16_t l = 0; l < context->sizePacketsToMultiplex[context->numPktsStoredFromTun] ; l++) {
      context->packetsToMultiplex[context->numPktsStoredFromTun][l] = rohc_buf_byte_at(rohc_packet, l);
    }

    #ifdef DEBUG
      // dump the ROHC packet on terminal
      if (debug >= 1 ) {
        do_debug_c( 1,
                    ANSI_COLOR_MAGENTA,
                    " RoHC-compressed to %i bytes\n",
                    rohc_packet.len);
      }
      if (debug == 2) {
        //do_debug(2, "   ");
        dump_packet ( rohc_packet.len, rohc_packet.data );
      }
    #endif

  }
  else {
    /* compressor failed to compress the IP packet */
    /* Send it in its native form */

    // I don't have to copy the native length and the native packet, because they
    // have already been stored in 'context->sizePacketsToMultiplex[context->numPktsStoredFromTun]' and 'context->packetsToMultiplex[context->numPktsStoredFromTun]'

    // since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP'
    // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
    context->protocol[context->numPktsStoredFromTun] = IPPROTO_IP_ON_IP;

    fprintf(stderr, "compression of IP packet failed\n");

    #ifdef LOGFILE
      // print in the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  "%"PRIu64"\terror\tcompr_failed. Native packet sent\t%i\t%"PRIu32"\\n",
                  GetTimeStamp(),
                  size,
                  context->tun2net);

        // If the IO is buffered, I have to insert fflush(fp) after the write
        fflush(context->log_file);
      }
    #endif

    #ifdef DEBUG
      do_debug_c( 2,
                  ANSI_COLOR_RED,
                  "  RoHC did not work. Native packet sent: %i bytes:\n   ",
                  size);
    #endif
    //goto release_compressor;
  }
}


int allSameProtocol(struct contextSimplemux* context)
{
  // in fast flavor I will send the protocol in every packet
  // in normal flavor I may avoid the protocol field in many packets

  int single_protocol;

  if (context->flavor == 'N') {
    // normal flavor
    // calculate if all the packets belong to the same protocol (single_protocol = 1) 
    //or they belong to different protocols (single_protocol = 0)
    single_protocol = 1;
    for (int k = 1; k < context->numPktsStoredFromTun ; k++) {
      if (context->protocol[k] != context->protocol[k-1])
        single_protocol = 0;
    }              
  } 
  else {
    // fast flavor
    // single_protocol does not make sense in fast flavor because
    //all the separators have a Protocol field
    single_protocol = -1;
  }
  return single_protocol;
}


// if the addition of the present packet will imply a multiplexed packet bigger than the size limit:
// - I send the previously stored packets
// - I store the present one
// - I reset the period
void emptyBufferIfNeeded(struct contextSimplemux* context, int single_protocol)
{
  // calculate the size without the present packet
  int predictedSizeMuxedPacket;        // size of the muxed packet if the arrived packet was added to it

  predictedSizeMuxedPacket = predictSizeMultiplexedPacket(context, single_protocol);

  // I add the length of the present packet:

  // separator and length of the present packet
  if (context->flavor == 'N') {
    // normal flavor

    if (context->firstHeaderWritten == 0) {
      // this is the first header, so the maximum length to be expressed in 1 byte is 64
      if (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] < 64 ) {
        predictedSizeMuxedPacket = predictedSizeMuxedPacket + 1 + context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
      }
      else {
        predictedSizeMuxedPacket = predictedSizeMuxedPacket + 2 + context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
      }
    }
    else {
      // this is not the first header, so the maximum length to be expressed in 1 byte is 128
      if (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] < 128 ) {
        predictedSizeMuxedPacket = predictedSizeMuxedPacket + 1 + context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
      }
      else {
        predictedSizeMuxedPacket = predictedSizeMuxedPacket + 2 + context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
      }
    }
  }
  else {
    // fast flavor
    // the header is always fixed: the size of the length field + the size of the protocol field (1 byte per packet)
    predictedSizeMuxedPacket = predictedSizeMuxedPacket +
                               context->sizeSeparatorFastMode +
                               context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
  }


  if (predictedSizeMuxedPacket > context->sizeMax ) {
    // if the present packet is muxed, the max size of the packet will be overriden. So I first empty the buffer
    //i.e. I build and send a multiplexed packet not including the current one
    #ifdef DEBUG
      do_debug(2, "\n");
      switch (context->mode) {
        case UDP_MODE:
          do_debug_c( 1,
                      ANSI_COLOR_GREEN,
                      "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU: %i)\n",
                      predictedSizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                      context->sizeMax );
        break;

        case TCP_CLIENT_MODE:
          do_debug_c( 1,
                      ANSI_COLOR_GREEN,
                      "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU: %i)\n",
                      predictedSizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                      context->sizeMax );
        break;
        
        case NETWORK_MODE:
          do_debug_c( 1,
                      ANSI_COLOR_GREEN,
                      "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU: %i)\n",
                      predictedSizeMuxedPacket + IPv4_HEADER_SIZE,
                      context->sizeMax );
        break;
      }
    #endif

    // add the length corresponding to the Protocol field
    if (context->flavor == 'N') {
      // normal flavor
      // add the Single Protocol Bit in the first header (the most significant bit)
      // it is '1' if all the multiplexed packets belong to the same protocol
      if (single_protocol == 1) {
        // this puts a '1' in the most significant bit position
        context->separatorsToMultiplex[0][0] = context->separatorsToMultiplex[0][0] + 0x80; // FIXME: use operand '|' instead?

        // one byte corresponding to the 'protocol' field of the first header
        context->sizeMuxedPacket = context->sizeMuxedPacket + 1;
      }
      else {
        // one byte per packet, corresponding to the 'protocol' field
        context->sizeMuxedPacket = context->sizeMuxedPacket + context->numPktsStoredFromTun;
      }
    }
    else { 
      // fast flavor
      context->sizeMuxedPacket = context->sizeMuxedPacket + context->numPktsStoredFromTun;
    }

    // build the multiplexed packet without the current one
    uint16_t total_length;          // total length of the built multiplexed packet
    uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

    total_length = buildMultiplexedPacket ( context,
                                            single_protocol,
                                            muxed_packet);

    #ifdef DEBUG
      if (context->flavor == 'N') {
        // normal flavor

        if (single_protocol) {
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " Normal flavor. All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
        }
        else {
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " Normal flavor. Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",
                      context->numPktsStoredFromTun);
        }                
      }
      else {
        // fast flavor
        do_debug_c( 2,
                    ANSI_COLOR_GREEN,
                    " Fast flavor. Added 1 Protocol byte to each separator. Total %i bytes",
                    context->numPktsStoredFromTun);
      }
      
      switch(context->tunnelMode) {
        case TUN_MODE:
          switch (context->mode) {
            case UDP_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE + UDP_HEADER_SIZE);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a UDP muxed packet without this one: %i bytes\n",
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;

            case TCP_CLIENT_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native packet(s) (not this one) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case TCP_SERVER_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native packet(s) (not this one) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case NETWORK_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE );

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") an IP muxed packet without this one: %i bytes\n",
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE );
            break;
          }
        break;

        case TAP_MODE:
          switch (context->mode) {
            case UDP_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE + UDP_HEADER_SIZE);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a UDP packet without this Eth frame: %i bytes\n",
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;

            case TCP_CLIENT_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native Eth frame(s) (not this one) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case TCP_SERVER_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native Eth frame(s) (not this one) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case NETWORK_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE );

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") an IP packet without this Eth frame: %i bytes\n",
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE );
            break;
          }
        break;
      }  
    #endif

    // send the multiplexed packet without the current one
    switch (context->mode) {
      case UDP_MODE:
        // send the packet
        if (sendto( context->udp_mode_fd,
                    muxed_packet,
                    total_length,
                    0,
                    (struct sockaddr *)&(context->remote),
                    sizeof(context->remote)) == -1)
        {
          perror("sendto() in UDP mode failed");
          exit (EXIT_FAILURE);
        }
        
        #ifdef LOGFILE
          // write in the log file
          if ( context->log_file != NULL ) {
            fprintf(context->log_file,
                    "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n",
                    GetTimeStamp(),
                    total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                    context->tun2net,
                    inet_ntoa(context->remote.sin_addr),
                    ntohs(context->remote.sin_port),
                    context->numPktsStoredFromTun);

            // If the IO is buffered, I have to insert fflush(fp) after writing
            fflush(context->log_file);
          }
        #endif
      break;

      case TCP_CLIENT_MODE:
        // send the packet
        if (write(context->tcp_client_fd,
                  muxed_packet,
                  total_length) == -1)
        {
          perror("write() in TCP client mode failed");
          exit (EXIT_FAILURE);
        }
        
        #ifdef LOGFILE
          // write in the log file
          if ( context->log_file != NULL ) {
            fprintf(context->log_file,
                    "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n",
                    GetTimeStamp(),
                    total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                    context->tun2net,
                    inet_ntoa(context->remote.sin_addr),
                    ntohs(context->remote.sin_port),
                    context->numPktsStoredFromTun);

            // If the IO is buffered, I have to insert fflush(fp) after the write
            fflush(context->log_file);
          }
        #endif
      break;

      case TCP_SERVER_MODE:  
        if(context->acceptingTcpConnections == true) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_RED,
                        " The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
          #endif
        }
        else {
          // send the packet
          if (write(context->tcp_server_fd,
                    muxed_packet,
                    total_length) == -1)
          {
            perror("write() in TCP server mode failed");
            exit (EXIT_FAILURE);
          }

          #ifdef LOGFILE
            // write in the log file
            if ( context->log_file != NULL ) {
              fprintf(context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      ntohs(context->remote.sin_port),
                      context->numPktsStoredFromTun);

              // If the IO is buffered, I have to insert fflush(fp) after writing
              fflush(context->log_file);
            }
          #endif           
        }
      break;
      
      case NETWORK_MODE: ;
        // build the header
        struct iphdr ipheader;
        BuildIPHeader(&ipheader, total_length, context->ipprotocol, context->local, context->remote);

        // build the full IP multiplexed packet
        uint8_t full_ip_packet[BUFSIZE];
        BuildFullIPPacket(ipheader, muxed_packet, total_length, full_ip_packet);

        // send the packet
        if (sendto (context->network_mode_fd,
                    full_ip_packet,
                    total_length + sizeof(struct iphdr),
                    0,
                    (struct sockaddr *)&(context->remote),
                    sizeof (struct sockaddr)) < 0 )
        {
          perror ("sendto() in Network mode failed");
          exit (EXIT_FAILURE);
        }

        #ifdef LOGFILE
          // write in the log file
          if ( context->log_file != NULL ) {
            fprintf ( context->log_file,
                      "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tMTU\n",
                      GetTimeStamp(),
                      total_length + IPv4_HEADER_SIZE,
                      context->tun2net,
                      inet_ntoa(context->remote.sin_addr),
                      context->numPktsStoredFromTun);

            // If the IO is buffered, I have to insert fflush(fp) after the write
            fflush(context->log_file);
          }
        #endif
      break;
    }


    // I have sent a packet, so I restart the period: update the time of the last packet sent
    uint64_t now_microsec = GetTimeStamp();
    context->timeLastSent = now_microsec;

    // I have emptied the buffer, so I have to
    //move the current packet to the first position of the 'packetsToMultiplex' array
    memcpy(context->packetsToMultiplex[0], context->packetsToMultiplex[context->numPktsStoredFromTun], BUFSIZE);

    // move the current separator to the first position of the array
    memcpy(context->separatorsToMultiplex[0], context->separatorsToMultiplex[context->numPktsStoredFromTun], 2);

    // move the size of the packet to the first position of the array
    context->sizePacketsToMultiplex[0] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun];

    // set the rest of the values of the size to 0
    // note: it starts with 1, not with 0
    for (int j=1; j < MAXPKTS; j++)
      context->sizePacketsToMultiplex[j] = 0;

    // move the size of the separator to the first position of the array
    context->sizeSeparatorsToMultiplex[0] = context->sizeSeparatorsToMultiplex[context->numPktsStoredFromTun];

    // I have sent a packet, so I set to 0 the "context->firstHeaderWritten" bit
    context->firstHeaderWritten = 0;

    // reset the length and the number of packets
    context->sizeMuxedPacket = 0;
    context->numPktsStoredFromTun = 0;
  }
}


// create the Simplemux separator. normal flavor
// it does NOT add the Protocol field of the separators (1 byte)
void createSimplemuxSeparatorNormal(struct contextSimplemux* context)
{
  // I have to add the multiplexing separator
  //   - It is 1 byte long if the length is smaller than 64 (or 128 for non-first separators) 
  //   - It is 2 bytes long if the length is 64 (or 128 for non-first separators) or more
  //   - It is 3 bytes long if the length is 8192 (or 16384 for non-first separators) or more

  uint16_t limitLengthOneByte;  // the maximum length of a packet in order to express it in a 1-byte separator. It may be 64 (first header) or 128 (non-first header)
  uint16_t limitLengthTwoBytes; // the maximum length of a packet in order to express it in a 2-byte separator. It may be 8192 or 16384 (non-first header)

  if (context->firstHeaderWritten == 0) {
    // this is the first header
    limitLengthOneByte = 64;     // 0x40. The length can be expressed in 6 bits
    limitLengthTwoBytes = 8192;  // 0x2000. The length can be expressed in 13 bits
  }
  else {
    // this is a non-first header
    limitLengthOneByte = 128;     // 0x80. The length can be expressed in 7 bits
    limitLengthTwoBytes = 16384;  // 0x4000. The length can be expressed in 14 bits
  }

  // check if the length has to be one, two or three bytes
  // I am assuming that a packet will never be bigger than 1048576 (2^20) bytes for a first header,
  // or 2097152 (2^21) bytes for a non-first one)

  // one-byte separator
  // - first header: between 1 and 63 bytes
  // - non-first header: between 1 and 127 bytes
  if (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] < limitLengthOneByte ) {

    // the length can be written in the first byte of the separator
    // it can be expressed in 
    // - 6 bits for the first separator
    // - 7 bits for non-first separators
    context->sizeSeparatorsToMultiplex[context->numPktsStoredFromTun] = 1;

    // add the 'length' field to the packet
    context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun];
    // since the value is < limitLengthOneByte:
    // - first separator:
    //    - the length will be expressed in 6 bits
    //    - the two most significant bits will always be 0
    //      - SPB: it will be filled later
    //      - LXT will be 0. This is the desired value, because there is no length extension
    // - non-first separator:
    //    - the length will be expressed in 7 bits
    //    - the most significant bit will be 0 (LXT). This is the desired value, because there is no length extension

    // increase the size of the multiplexed packet
    context->sizeMuxedPacket ++;

    #ifdef DEBUG
      // print the Mux separator (only one byte)
      if(debug) {
        // convert the byte to bits
        bool bits[8];   // used for printing the bits of a byte in debug mode
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][0], bits);
        do_debug_c( 2,
                    ANSI_COLOR_GREEN,
                    " Mux separator of 1 byte (plus Protocol): 0x%02x (",
                    context->separatorsToMultiplex[context->numPktsStoredFromTun][0]);

        if (context->firstHeaderWritten == 0) {
          PrintByte(2, 7, bits);      // first header
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      ", SPB field not included)\n");
        }
        else {
          PrintByte(2, 8, bits);      // non-first header
          do_debug_c( 2,
                      ANSI_COLOR_GREEN, ")\n");
        }
      }
    #endif
  }
  
  // two-byte separator
  // - first header: between 64 and 8191 bytes
  // - non-first header: between 128 and 16383 bytes
  else if (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] < limitLengthTwoBytes ) {

    // the length requires a two-byte separator (length expressed in 13 or 14 bits)
    context->sizeSeparatorsToMultiplex[context->numPktsStoredFromTun] = 2;

    // first byte of the Mux separator
    //  It can be:
    //  - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
    //  - non-first-header: LXT=1 and 7 bits with the most significant bits of the length

    //  Follow these steps:
    //  - get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
    //  - add 64 (or 128) in order to put a '1' in the second (or first) bit
    if (context->firstHeaderWritten == 0) {
      // first header

      //  - get the most significant bits by dividing the size by 128 (the 7 less significant bits will go in the second byte)
      //       Note: division by 128 is equivalent to a 7-bit shift
      //  - add 64 (0100 0000) in order to put a '1' in the second bit (LXT = 1)
      //context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128 ) + 64;  // first header
      context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] >> 7 ) + 0x40;  // first header
    }
    else {
      // non-first header
      // add 128 (1000 0000) to the header, i.e., set the value of LXT to '1' (8th bit)
      context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128 ) + 128;  // non-first header

      // using bitwise OR operand ('|'), set the 8th bit to 1
      //context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = context->separatorsToMultiplex[context->numPktsStoredFromTun][0] | 1 << 7;

      //do_debug(2, "numPktsStoredFromTun: %i\n", context->numPktsStoredFromTun);
      //do_debug(2, "context->sizePacketsToMultiplex[context->numPktsStoredFromTun]: %i\n", context->sizePacketsToMultiplex[context->numPktsStoredFromTun]);
      //do_debug(2, "context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128: %i\n", context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128);
      //do_debug(2, "context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128 + 128: %i\n", (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 128) + 128);
      //do_debug(2, "separatorsToMultiplex[context->numPktsStoredFromTun][0]: %i\n", context->separatorsToMultiplex[context->numPktsStoredFromTun][0]);
    }


    // second byte of the Mux separator

    // Length: the 7 less significant bytes of the length. Use modulo 128
    context->separatorsToMultiplex[context->numPktsStoredFromTun][1] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun] % 128;

    // fill the LXT field of the second byte
    // LXT bit has to be set to 0, because this is the last byte of the length
    // if I do nothing, it will be 0, since I have used modulo 128

    // SPB field will be filled later
    
    // increase the size of the multiplexed packet
    context->sizeMuxedPacket = context->sizeMuxedPacket + 2;

    #ifdef DEBUG
      // print the two bytes of the separator
      if(debug) {
        bool bits[8];   // used for printing the bits of a byte in debug mode

        // first byte
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][0], bits);
        do_debug_c(2, ANSI_COLOR_GREEN, " Mux separator of 2 bytes (plus Protocol): 0x%02x (", context->separatorsToMultiplex[context->numPktsStoredFromTun][0]);
        //do_debug_c(2, ANSI_COLOR_RESET, " Mux separator of 2 bytes (plus Protocol). First byte: ");
        if (context->firstHeaderWritten == 0) {
          PrintByte(2, 7, bits);      // first header
          do_debug_c(2, ANSI_COLOR_GREEN, ", SPB field not included)");
        }
        else {
          PrintByte(2, 8, bits);      // non-first header
          do_debug_c(2, ANSI_COLOR_GREEN, ")");
        }

        // second byte
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][1], bits);
        do_debug_c(2, ANSI_COLOR_GREEN, " 0x%02x (", context->separatorsToMultiplex[context->numPktsStoredFromTun][1]);
        //do_debug(2, ". second byte: ");
        PrintByte(2, 8, bits);
        do_debug_c(2, ANSI_COLOR_GREEN, ")\n");
      }
    #endif
  }

  // three-byte separator
  // - first header: between 8192 and 65535 bytes
  // - non-first header: between 16384 and 65535 bytes
  else {

    // the length requires a three-byte separator (length expressed in 20 or 21 bits)
    context->sizeSeparatorsToMultiplex[context->numPktsStoredFromTun] = 3;

    //FIXME. NOT TESTED. I have just copied the case of two-byte separator
    // first byte of the Mux separator
    // It can be:
    // - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
    // - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
    // get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
    // add 64 (or 128) in order to put a '1' in the second (or first) bit

    if (context->firstHeaderWritten == 0) {
      // first header
      context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 16384 ) + 64;

    }
    else {
      // non-first header
      context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = (context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 16384 ) + 128;  
    }


    // second byte of the Mux separator
    // Length: the 7 second significant bytes of the length. Use modulo 16384
    context->separatorsToMultiplex[context->numPktsStoredFromTun][1] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun] % 16384;

    // LXT bit has to be set to 1, because this is not the last byte of the length
    context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = context->separatorsToMultiplex[context->numPktsStoredFromTun][0] + 128;


    // third byte of the Mux separator
    // Length: the 7 less significant bytes of the length. Use modulo 128
    context->separatorsToMultiplex[context->numPktsStoredFromTun][1] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun] % 128;

    // LXT bit has to be set to 0, because this is the last byte of the length
    // if I do nothing, it will be 0, since I have used modulo 128


    // increase the size of the multiplexed packet
    context->sizeMuxedPacket = context->sizeMuxedPacket + 3;

    // print the three bytes of the separator
    #ifdef DEBUG
      if(debug) {
        bool bits[8];   // used for printing the bits of a byte in debug mode

        // first byte
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][0], bits);
        do_debug_c(2, ANSI_COLOR_GREEN, " Mux separator of 3 bytes: (0x%02x) ", context->separatorsToMultiplex[context->numPktsStoredFromTun][0]);
        if (context->firstHeaderWritten == 0) {
          PrintByte(2, 7, bits);      // first header
        }
        else {
          PrintByte(2, 8, bits);      // non-first header
        }

        // second byte
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][1], bits);
        do_debug_c(2, ANSI_COLOR_GREEN, " (0x%02x) ", context->separatorsToMultiplex[context->numPktsStoredFromTun][1]);
        PrintByte(2, 8, bits);
        do_debug(2, "\n");

        // third byte
        FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][2], bits);
        do_debug_c(2, ANSI_COLOR_GREEN, " (0x%02x) ", context->separatorsToMultiplex[context->numPktsStoredFromTun][2]);
        PrintByte(2, 8, bits);
        do_debug(2, "\n");
      }
    #endif
  }
}


// create the Simplemux separator. fast flavor
// it does NOT add the Protocol field of the separators (1 byte)
void createSimplemuxSeparatorFast(struct contextSimplemux* context)
{
  // the length requires two bytes in fast flavor
  context->sizeSeparatorsToMultiplex[context->numPktsStoredFromTun] = sizeof(uint16_t);

  //separatorsToMultiplex[context->numPktsStoredFromTun] = htons(size);

  // add the first byte of the Mux separator (most significant bits)
  context->separatorsToMultiplex[context->numPktsStoredFromTun][0] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun] / 256;

  // add the second byte of the Mux separator (less significant bits)
  context->separatorsToMultiplex[context->numPktsStoredFromTun][1] = context->sizePacketsToMultiplex[context->numPktsStoredFromTun] % 256;
  
  // increase the size of the multiplexed packet
  context->sizeMuxedPacket = context->sizeMuxedPacket + 2;

  // here do not add the size that corresponds to the Protocol field of all the separators (1 byte)
  // it will be added later

  // print the bytes of the separator
  #ifdef DEBUG
    if(debug>0) {
      bool bits[8];   // used for printing the bits of a byte in debug mode

      // first byte: most significant bits of the length
      FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][0], bits);
      do_debug_c(2, ANSI_COLOR_GREEN, " Mux separator of 3 bytes (fast flavor). Length: 0x%02x (", context->separatorsToMultiplex[context->numPktsStoredFromTun][0]);
      PrintByte(2, 8, bits);
      do_debug_c(2, ANSI_COLOR_GREEN, ")");

      // second byte: less significant bits of the length
      FromByte(context->separatorsToMultiplex[context->numPktsStoredFromTun][1], bits);
      do_debug_c(2, ANSI_COLOR_GREEN, " 0x%02x (", context->separatorsToMultiplex[context->numPktsStoredFromTun][1]);
      PrintByte(2, 8, bits);
      do_debug_c(2, ANSI_COLOR_GREEN, ")");

      // third byte: protocol
      FromByte(context->protocol[context->numPktsStoredFromTun], bits);
      do_debug_c(2, ANSI_COLOR_GREEN, ". Protocol: 0x%02x (", context->protocol[context->numPktsStoredFromTun]);
      PrintByte(2, 8, bits);
      do_debug_c(2, ANSI_COLOR_GREEN, ")\n");
    }
  #endif
}


// adds the size of the Protocol field to the global size of the muxed packet
int addSizeOfProtocolField(struct contextSimplemux* context)
{
  int single_protocol = 1;

  if (context->flavor == 'N') {
    // normal flavor

    // fill the SPB field (Single Protocol Bit)     
    // calculate if all the packets belong to the same protocol
    // it has to be calculated again, because some packets may have been sent
    for (int k = 1; k < context->numPktsStoredFromTun ; k++) {
      if (context->protocol[k] != context->protocol[k-1])
        single_protocol = 0;
    }

    // Add the Single Protocol Bit in the first header (the most significant bit)
    // It is 1 if all the multiplexed packets belong to the same protocol
    if (single_protocol == 1) {
      context->separatorsToMultiplex[0][0] = context->separatorsToMultiplex[0][0] + 128;  // this puts a 1 in the most significant bit position
      // one or two bytes corresponding to the 'protocol' field of the first header
      context->sizeMuxedPacket = context->sizeMuxedPacket + 1;
    }
    else {
      // add the size that corresponds to the Protocol field of all the separators
      context->sizeMuxedPacket = context->sizeMuxedPacket + context->numPktsStoredFromTun;
    }               
  }
  else {
    // fast flavor
    // add the size that corresponds to the Protocol field of all the separators
    context->sizeMuxedPacket = context->sizeMuxedPacket + context->numPktsStoredFromTun;

    single_protocol = -1;
  }
  return single_protocol;
}

#ifdef DEBUG
  void debugInformationAboutTrigger(struct contextSimplemux* context,
                                    int single_protocol,
                                    uint64_t time_difference)
  {
    // write the debug information
    if (debug > 0) {
      do_debug( 2, "\n");
      do_debug_c( 1,
                  ANSI_COLOR_GREEN,
                  "SENDING TRIGGERED: ");
      if (context->numPktsStoredFromTun == context->limitNumpackets)
        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    "num packet limit reached: %i packets\n",
                    context->limitNumpackets);
      if (context->sizeMuxedPacket > context->sizeThreshold)
        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " size threshold reached: %i > %i bytes\n",
                    context->sizeMuxedPacket,
                    context->sizeThreshold);
      if (time_difference > context->timeout)
        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    "timeout reached: %"PRIu64" > %"PRIu64" us\n",
                    time_difference,
                    context->timeout);

      if (context->flavor == 'N') {
        // normal flavor
        if (single_protocol) {
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " Normal flavor. All packets belong to the same protocol. Added 1 Protocol byte (0x%02x",
                      context->protocol[0]);

          if(context->protocol[0] == IPPROTO_IP_ON_IP)
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        ", IP)");
          else if(context->protocol[0] == IPPROTO_ROHC)
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        ", RoHC)");
          else if(context->protocol[0] == IPPROTO_ETHERNET)
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        ", Ethernet)");
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " in the first separator\n",
                      context->protocol[0]);
        }
        else {
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " Normal flavor. Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n",
                      context->numPktsStoredFromTun);
        }
      }
      else {
        // fast flavor
        do_debug_c( 2,
                    ANSI_COLOR_GREEN,
                    " Fast flavor. Added headers: length (2 bytes) + protocol (1 byte) in each separator. Total %i bytes\n",
                    3 * context->numPktsStoredFromTun); 
      }

      switch(context->tunnelMode) {
        case TUN_MODE:
          switch (context->mode) {
            case UDP_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE + UDP_HEADER_SIZE);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a UDP packet containing %i native one(s): %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;

            case TCP_CLIENT_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN, " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native one(s) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case TCP_SERVER_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native one(s) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case NETWORK_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") an IP packet containing %i native one(s): %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE);
            break;
          }
        break;
        
        case TAP_MODE:
          switch (context->mode) {
            case UDP_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE + UDP_HEADER_SIZE);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a UDP packet containing %i native Eth frame(s): %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;

            case TCP_CLIENT_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native Eth frame(s) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case TCP_SERVER_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: IPv4 + TCP\n");

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") a TCP packet containing: %i native Eth frame(s) plus separator(s), %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket);
            break;

            case NETWORK_MODE:
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Added tunneling header: %i bytes\n",
                          IPv4_HEADER_SIZE );

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          " Sending to the network (");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->mux_if_name);

              do_debug_c( 1,
                          ANSI_COLOR_GREEN,
                          ") an IP packet containing %i native Eth frame(s): %i bytes\n",
                          context->numPktsStoredFromTun,
                          context->sizeMuxedPacket + IPv4_HEADER_SIZE);
            break;
          }
        break;
      }
    }     
  }
#endif

// packet/frame arrived at tun: read it, and check if:
// - the packet has to be stored
// - a multiplexed packet has to be sent to the network
void tunToNetNoBlastFlavor (struct contextSimplemux* context)
{
  // normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  // read the packet from context->tun_fd, store it in the array, and store its size
  context->sizePacketsToMultiplex[context->numPktsStoredFromTun] = cread (context->tun_fd,
                                                                          context->packetsToMultiplex[context->numPktsStoredFromTun],
                                                                          BUFSIZE);

  uint16_t size = context->sizePacketsToMultiplex[context->numPktsStoredFromTun];  

  #ifdef DEBUG
    // print the native packet/frame received
    if (debug>0) {
      if (context->tunnelMode == TUN_MODE) {
        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    "NATIVE PACKET #%"PRIu32": Read packet from ",
                    context->tun2net);

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->tun_if_name);

        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    ": ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    size);

        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " bytes\n");
      }
      else if (context->tunnelMode == TAP_MODE) {
        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    "NATIVE FRAME #%"PRIu32": Read frame from ",
                    context->tun2net);

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->tun_if_name);

        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    ": ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    size);

        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " bytes\n");
      }

      // dump the newly-created IP packet on terminal
      dump_packet ( context->sizePacketsToMultiplex[context->numPktsStoredFromTun],
                    context->packetsToMultiplex[context->numPktsStoredFromTun] );
    }
  #endif

  #ifdef LOGFILE
    // write in the log file
    if ( context->log_file != NULL ) {
      fprintf ( context->log_file,
                "%"PRIu64"\trec\tnative\t%i\t%"PRIu32"\n",
                GetTimeStamp(),
                size,
                context->tun2net);

      // If the IO is buffered, I have to insert fflush(fp) after the write
      fflush(context->log_file);
    }
  #endif

  // check if this packet (plus the tunnel and simplemux headers) is bigger than the MTU. Drop it in that case
  bool dropPacket = checkPacketSize (context, size);

  // the length of the packet is adequate
  if ( dropPacket == false ) {

    // compress the headers if the RoHC option has been set
    if ( context->rohcMode > 0 ) {
      // header compression has been selected by the user
      compressPacket(context, size);
    }
    else {
      // header compression has not been selected by the user

      if (context->tunnelMode == TAP_MODE) {
        // tap mode
        
        // since this frame CANNOT be compressed, its protocol number has to be 143: 'Ethernet on IP' 
        // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        context->protocol[context->numPktsStoredFromTun] = IPPROTO_ETHERNET;             
      }
      else if (context->tunnelMode == TUN_MODE) {
        // tun mode
      
        // since this IP packet is NOT compressed, its protocol number has to be 4: 'IP on IP' 
        // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        context->protocol[context->numPktsStoredFromTun] = IPPROTO_IP_ON_IP;
      }

      else {
        perror ("wrong value of 'tunnelMode'");
        exit (EXIT_FAILURE);
      }
    }

    // check if all the packets/frames belong to the same protocol
    int single_protocol = allSameProtocol(context);


    // Calculate if the size limit will be reached when multiplexing the present packet
    // if the addition of the present packet will imply a multiplexed packet bigger than the size limit:
    // - I send the previously stored packets
    // - I store the present one
    // - I reset the period
    emptyBufferIfNeeded(context, single_protocol);


    // update the size of the muxed packet, adding the size of the current one
    context->sizeMuxedPacket = context->sizeMuxedPacket + context->sizePacketsToMultiplex[context->numPktsStoredFromTun];


    // create the separator 
    if (context->flavor == 'N')
      createSimplemuxSeparatorNormal(context);
    else
      createSimplemuxSeparatorFast(context);


    // I have finished storing the packet, so I increase the number of stored packets
    context->numPktsStoredFromTun ++;


    if (context->flavor == 'N') {
      // normal flavor
      // I have written a header of the multiplexed bundle, so I have to set to 1 the "first header written bit"
      if (context->firstHeaderWritten == 0)
        context->firstHeaderWritten = 1; 

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " Packet stopped: accumulated ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->numPktsStoredFromTun);

        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " pkts: ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->sizeMuxedPacket);

        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " bytes (Protocol not included).");
      #endif
    }
    else {
      // fast flavor
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " Packet stopped: accumulated ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->numPktsStoredFromTun);

        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " pkts: ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->sizeMuxedPacket + context->numPktsStoredFromTun);

        do_debug_c( 1,
                    ANSI_COLOR_GREEN,
                    " bytes (Separator(s) included).");
      #endif
    }
    

    // check if a multiplexed packet has to be sent
    uint64_t now_microsec = GetTimeStamp();
    uint64_t time_difference = now_microsec - context->timeLastSent;
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_GREEN,
                  " Time since last trigger: %" PRIu64 " usec\n",
                  time_difference);
    #endif

    // if the packet limit or the size threshold are reached, send all the stored packets to the network
    // do not worry about the MTU. if it is reached, a number of packets will be sent
    if ((context->numPktsStoredFromTun == context->limitNumpackets) || (context->sizeMuxedPacket > context->sizeThreshold) || (time_difference > context->timeout )) {

      // sending triggered: a multiplexed packet has to be sent
      single_protocol = addSizeOfProtocolField(context);

      #ifdef DEBUG
        debugInformationAboutTrigger(context, single_protocol, time_difference);
      #endif

      // build the multiplexed packet including the current one
      uint16_t total_length;          // total length of the built multiplexed packet
      uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

      total_length = buildMultiplexedPacket ( context,
                                              single_protocol,
                                              muxed_packet);

      // send the multiplexed packet
      sendMultiplexedPacket ( context,
                              total_length,
                              muxed_packet,
                              time_difference);

      // I have sent a packet, so I set to 0 the "first_header_written" bit
      context->firstHeaderWritten = 0;

      // reset the length and the number of packets
      context->sizeMuxedPacket = 0 ;
      context->numPktsStoredFromTun = 0;

      // restart the period: update the time of the last packet sent
      context->timeLastSent = now_microsec;
    }

    #ifdef DEBUG
    else {
      // a multiplexed packet does not have to be sent. I have just accumulated this one
      // just add a linefeed
      do_debug(2, "\n");

    }
    #endif
  }
}