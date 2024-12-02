#include "tunToNet.h"

// packet/frame arrived at tun: read it, and send a blast packet to the network
void tunToNetBlastFlavor (contextSimplemux* context)
{
  // blast flavor
  #ifdef ASSERT
    assert(context->flavor == 'B');
  #endif

  uint64_t now = GetTimeStamp();

  #ifdef DEBUG
    if (context->tunnelMode == TUN_MODE) {
      // tun mode
      do_debug_c( 3,
                  ANSI_COLOR_BRIGHT_BLUE,
                  "%"PRIu64": NATIVE PACKET arrived from local computer (",
                  now);
    }
    else {
      // tap mode
      do_debug_c( 3,
                  ANSI_COLOR_BRIGHT_BLUE,
                  "%"PRIu64": NATIVE FRAME arrived from local computer (",
                  now);
    }

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
    if (context->tunnelMode == TUN_MODE) {
      // tun mode
      do_debug_c( 1,
                  ANSI_COLOR_BRIGHT_BLUE,
                  "NATIVE PACKET #%"PRIu32" from ",
                  context->tun2net);
    }
    else {
      // tap mode
      do_debug_c( 1,
                  ANSI_COLOR_BRIGHT_BLUE,
                  "NATIVE FRAME #%"PRIu32" from ",
                  context->tun2net);      
    }
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

  #ifdef LOGFILE
    // write in the log file
    if ( context->log_file != NULL ) {
      fprintf ( context->log_file,
                "%"PRIu64"\trec\tnative\t%i\t%"PRIu32"\n",
                GetTimeStamp(),
                ntohs(thisPacket->header.packetSize),
                context->tun2net);

      // If the IO is buffered, I have to insert fflush(fp) after the write
      fflush(context->log_file);
    }
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
                " Sent blast packet from ");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%s",
                context->mux_if_name);

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                ", ");

    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%s",
                inet_ntoa(context->local.sin_addr));

    do_debug_c( 1,
                ANSI_COLOR_BRIGHT_BLUE,
                ". ID ");

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
        if(context->tunnelMode == TUN_MODE) {
          // tun mode
          do_debug_c( 2,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " The packet had already been removed from the list\n");
        }
        else {
          // tap mode
          do_debug_c( 2,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " The frame had already been removed from the list\n");          
        }
      #endif
    }
    else {
      #ifdef DEBUG
        if(context->tunnelMode == TUN_MODE) {
          // tun mode
          do_debug_c( 2,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " Packet with ID ");
        }
        else {
          // tap mode
          do_debug_c( 2,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " Frame with ID ");          
        }

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
        if(context->tunnelMode == TUN_MODE) {
          // tun mode
          do_debug_c( 3,
                      ANSI_COLOR_RED,
                      " %"PRIu64" The packet has not been stored in the confirmation-pending list because no heartbeat has been received yet. Total %i packets stored\n",
                      now,
                      length(&context->unconfirmedPacketsBlast));
        }
        else {
          // tap mode
          do_debug_c( 3,
                      ANSI_COLOR_RED,
                      " %"PRIu64" The frame has not been stored in the confirmation-pending list because no heartbeat has been received yet. Total %i frames stored\n",
                      now,
                      length(&context->unconfirmedPacketsBlast));          
        }
      }
      else {
        // at least one heartbeat has arrived
        if(context->tunnelMode == TUN_MODE) {
          // tun mode
          do_debug_c( 3,
                      ANSI_COLOR_RED,
                      " %"PRIu64" The packet has not been stored in the confirmation-pending list because the last heartbeat was received %"PRIu64" us ago. Total %i packets stored\n",
                      now,
                      now - context->lastBlastHeartBeatReceived,
                      length(&context->unconfirmedPacketsBlast));
        }
        else {
          // tap mode
          do_debug_c( 3,
                      ANSI_COLOR_RED,
                      " %"PRIu64" The frame has not been stored in the confirmation-pending list because the last heartbeat was received %"PRIu64" us ago. Total %i frames stored\n",
                      now,
                      now - context->lastBlastHeartBeatReceived,
                      length(&context->unconfirmedPacketsBlast));          
        }
      }

    #endif
  }
  else {
    #ifdef DEBUG
      do_debug_c( 3,
                  ANSI_COLOR_BRIGHT_BLUE,
                  " %"PRIu64"",
                  thisPacket->sentTimestamp);

      if(context->tunnelMode == TUN_MODE) {
        // tun mode
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " The packet has been stored in the confirmation-pending list. Total ");
      }
      else {
        // tap mode
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " The frame has been stored in the confirmation-pending list. Total ");
      }

      do_debug_c( 2,
                  ANSI_COLOR_RESET,
                  "%i",
                  length(&context->unconfirmedPacketsBlast));

      if(context->tunnelMode == TUN_MODE) {
        // tun mode
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " packets stored\n");
      }
      else {
        // tap mode
        do_debug_c( 2,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " frames stored\n");        
      }

      if(debug > 1)
        dump_packet ( ntohs(thisPacket->header.packetSize), thisPacket->tunneledPacket );

      do_debug_c( 2,
                  ANSI_COLOR_RESET,
                  "\n");
    #endif            
  }
}


// packet/frame arrived at tun: read it, and check if:
// - the packet has to be stored
// - a multiplexed packet has to be sent to the network
void tunToNetNoBlastFlavor (contextSimplemux* context)
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
        if (context->tunnelMode == TUN_MODE) {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      "  Packet stopped: accumulated ");
        }
        else {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      "  Frame stopped: accumulated ");          
        }
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->numPktsStoredFromTun);
        if (context->tunnelMode == TUN_MODE) {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " packet(s): ");
        }
        else {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " frame(s): ");          
        }
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->sizeMuxedPacket);
        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " bytes (Protocol not included).");
      #endif
    }
    else {
      // fast flavor
      #ifdef DEBUG
        if (context->tunnelMode == TUN_MODE) {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      "  Packet stopped: accumulated ");
        }
        else {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      "  Frame stopped: accumulated ");
        }
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->numPktsStoredFromTun);
        if (context->tunnelMode == TUN_MODE) {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " packet(s): ");
        }
        else {
          do_debug_c( 1,
                      ANSI_COLOR_BRIGHT_BLUE,
                      " frame(s): ");          
        }
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    context->sizeMuxedPacket + context->numPktsStoredFromTun);
        do_debug_c( 1,
                    ANSI_COLOR_BRIGHT_BLUE,
                    " bytes (Separator(s) included).");
      #endif
    }
    

    // check if a multiplexed packet has to be sent
    uint64_t now_microsec = GetTimeStamp();
    uint64_t time_difference = now_microsec - context->timeLastSent;
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_BRIGHT_BLUE,
                  " Time since last trigger: %" PRIu64 " usec\n",
                  time_difference);
    #endif

    // if the packet limit or the size threshold are reached, send all the stored packets to the network
    // do not worry about the MTU. if it is reached, a number of packets will be sent
    if ((context->numPktsStoredFromTun == context->limitNumpackets) || (context->sizeMuxedPacket > context->sizeThreshold) || (time_difference > context->timeout )) {

      // sending triggered: a multiplexed packet has to be sent
      single_protocol = addSizeOfProtocolField(context);

      #ifdef DEBUG
        do_debug( 2,"\n");
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