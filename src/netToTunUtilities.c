#include "netToTunUtilities.h"

#ifdef DEBUG
  // shows the debug information when a new packet arrives
  //from the network
  void showDebugInfoFromNet(contextSimplemux* context,
                            int nread_from_net)
  {
    switch (context->mode) {
      case UDP_MODE:
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "SIMPLEMUX PACKET #%"PRIu32" from ",
                    context->net2tun);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->mux_if_name);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ": UDP muxed packet from ",
                    context->net2tun);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    inet_ntoa(context->remote.sin_addr));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ":");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%d",
                    ntohs(context->remote.sin_port));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ",");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    " %i",
                    nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " bytes\n");
      break;

      case TCP_CLIENT_MODE:
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "SIMPLEMUX PACKET #%"PRIu32" from ",
                    context->net2tun);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->mux_if_name);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ": TCP info from ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    inet_ntoa(context->remote.sin_addr));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ":");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%d",
                    ntohs(context->remote.sin_port));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ", ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    nread_from_net);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " bytes\n");
      break;

      case TCP_SERVER_MODE:
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "SIMPLEMUX PACKET #%"PRIu32" from ",
                    context->net2tun);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->mux_if_name);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ": TCP info from ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    inet_ntoa(context->remote.sin_addr));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ":");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%d",
                    ntohs(context->remote.sin_port));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ", ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    nread_from_net);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " bytes\n");
      break;

      case NETWORK_MODE:
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "SIMPLEMUX PACKET #%"PRIu32" from ",
                    context->net2tun);
        do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%s",
                  context->mux_if_name);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ": IP muxed packet arrived to ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    inet_ntoa(context->remote.sin_addr));
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ". Protocol ");        
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%d",
                    context->ipprotocol);
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    ", 0x%02x",
                    context->ipprotocol);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    ": ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    nread_from_net + IPv4_HEADER_SIZE );
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " bytes\n");
      break;
    }


    if(debug>0) {
      uint64_t now = GetTimeStamp();
      do_debug_c( 3,
                  ANSI_COLOR_YELLOW,
                  "%"PRIu64" Packet arrived from the network\n",
                  now);         
    }
  }
#endif

#ifdef LOGFILE
  void logInfoFromNet(contextSimplemux* context,
                      int nread_from_net,
                      uint8_t* buffer_from_net)
  {
    switch (context->mode) {
      case UDP_MODE:
        if ( context->log_file != NULL ) {
          // in any case, print this information
          fprintf ( context->log_file,
                    "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t",
                    GetTimeStamp(),
                    nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
                    context->net2tun,
                    inet_ntoa(context->remote.sin_addr));

          // Blast mode: these two columns are only printed if we are in blast mode
          if(context->flavor == 'B') {
            // apply the structure of a blast mode packet
            simplemuxBlastHeader* blastHeader = (simplemuxBlastHeader*) (buffer_from_net);

            //int length = ntohs(blastHeader->packetSize);

            if (blastHeader->ACK == HEARTBEAT) {
              // heartbeat
              fprintf ( context->log_file,
                        "%d\t%i\t\tblastHeartbeat",
                        ntohs(context->remote.sin_port),
                        0); // in blast mode, no packet from tun is sent in a heartbeat
            }
            else if (blastHeader->ACK == THISISANACK) {
              // ACK
              fprintf ( context->log_file,
                        "%d\t%i\t\tblastACK\t%"PRIu16"",
                        ntohs(context->remote.sin_port),
                        0, // in blast mode, no packet from tun is sent in an ACK
                        htons(blastHeader->identifier));
            }
            else {
              // blast packet
              #ifdef ASSERT
                assert(blastHeader->ACK == ACKNEEDED);
              #endif
              fprintf ( context->log_file,
                        "%d\t%i\t\tblastPacket\t%"PRIu16"",
                        ntohs(context->remote.sin_port),
                        1, // in blast mode, only 1 packet from tun is sent
                        htons(blastHeader->identifier));
            }
          }
          fprintf ( context->log_file,"\n");

          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write
        }
      break;

      case TCP_CLIENT_MODE:
        if ( context->log_file != NULL ) {
          fprintf ( context->log_file,
                    "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                    GetTimeStamp(),
                    nread_from_net + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                    context->net2tun,
                    inet_ntoa(context->remote.sin_addr),
                    ntohs(context->remote.sin_port));
          
          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write
        }
      break;

      case TCP_SERVER_MODE:
        if ( context->log_file != NULL ) {
          fprintf ( context->log_file,
                    "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                    GetTimeStamp(),
                    nread_from_net + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
                    context->net2tun,
                    inet_ntoa(context->remote.sin_addr),
                    ntohs(context->remote.sin_port));

          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write
        }
      break;

      case NETWORK_MODE:
        if ( context->log_file != NULL ) {
          // in any case, print this information
          fprintf ( context->log_file,
                    "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t",
                    GetTimeStamp(),
                    nread_from_net + IPv4_HEADER_SIZE,
                    context->net2tun,
                    inet_ntoa(context->remote.sin_addr));

          // Blast mode: these two columns are only printed if we are in blast mode
          if(context->flavor == 'B') {
            // apply the structure of a blast mode packet
            simplemuxBlastHeader* blastHeader = (simplemuxBlastHeader*) (buffer_from_net);

            if (blastHeader->ACK == HEARTBEAT) {
              // heartbeat
              fprintf ( context->log_file,
                        "\t%i\t\tblastHeartbeat",
                        //ntohs(context->remote.sin_port),
                        0); // in blast mode, no packet from tun is sent in a heartbeat
            }
            else if (blastHeader->ACK == THISISANACK) {
              // ACK
              fprintf ( context->log_file,
                        "\t%i\t\tblastACK\t%"PRIu16"",
                        //ntohs(context->remote.sin_port),
                        0, // in blast mode, no packet from tun is sent in an ACK
                        htons(blastHeader->identifier));
            }
            else {
              // blast packet
              #ifdef ASSERT
                assert(blastHeader->ACK == ACKNEEDED);
              #endif
              fprintf ( context->log_file,
                        "\t%i\t\tblastPacket\t%"PRIu16"",
                        //ntohs(context->remote.sin_port),
                        1, // in blast mode, only 1 packet from tun is sent
                        htons(blastHeader->identifier));
            }
          }
          fprintf ( context->log_file,"\n");
          fflush(context->log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write
        }
      break;
    }
  }
#endif

// demux a Blast packet
void demuxPacketBlast(contextSimplemux* context,
                      int nread_from_net,
                      uint8_t* buffer_from_net)
{
    // there should be a single packet

    // apply the structure of a blast mode packet
    simplemuxBlastHeader* blastHeader = (simplemuxBlastHeader*) (buffer_from_net);

    int packetLength = ntohs(blastHeader->packetSize);

    if (packetLength > BUFSIZE) {
      perror("Problem with the length of the received packet\n");
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    " Length is %i, but the maximum allowed size is %i\n",
                    packetLength,
                    BUFSIZE);
      #endif
    }

    // check if this is an ACK or not
    if((blastHeader->ACK & MASK ) == THISISANACK) {
      if(packetLength!=0) {
        perror("Problem with the length of the received blast packet\n");
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "Received wrong blast ACK: Its length is %i, but it MUST be %i\n",
                      packetLength + sizeof(blastHeader),
                      sizeof(blastHeader));
        #endif
      }
      else {
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_BOLD_GREEN,
                      " It is a blast ACK for packet ID ");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      ntohs(blastHeader->identifier));
          do_debug_c( 1,
                      ANSI_COLOR_BOLD_GREEN,
                      ". Blast header size: ");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      sizeof(blastHeader));
          do_debug_c( 1,
                      ANSI_COLOR_BOLD_GREEN,
                      " bytes\n");

          // an ACK has arrived. The corresponding packet can be removed from the list of pending packets
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      " Removing packet with ID ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      ntohs(blastHeader->identifier));
          do_debug_c( 3,
                      ANSI_COLOR_BOLD_GREEN,
                      " from the list\n");

          if(debug>2)
            printList(&context->unconfirmedPacketsBlast);
        #endif

        if(delete(&context->unconfirmedPacketsBlast,ntohs(blastHeader->identifier))==false) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " The packet had already been removed from the list. Total ");
          #endif
        }
        else {
          #ifdef DEBUG
            if (context->tunnelMode == TUN_MODE) {
              do_debug_c( 2,
                          ANSI_COLOR_BOLD_GREEN,
                          " Packet with ID ");
            }
            else {
              // TAP mode
              do_debug_c( 2,
                          ANSI_COLOR_BOLD_GREEN,
                          " Frame with ID ");
            }
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        ntohs(blastHeader->identifier));
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " removed from the confirmation-pending list. Total ");
          #endif
        }
        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      length(&context->unconfirmedPacketsBlast));
          if(context->tunnelMode == TUN_MODE) {
            // tun mode
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " packets stored\n\n");
          }
          else {
            // tap mode
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " frames stored\n\n");        
          }
        #endif
      }
    }
    else if((blastHeader->ACK & MASK ) == ACKNEEDED) {
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " It is a blast packet with ID ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(blastHeader->identifier));
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    ", Length ");
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "%i",
                    packetLength);
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " plus blast (");
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "%i",
                    sizeof(blastHeader));
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    ") and tunneling (");
        if (context->mode==UDP_MODE) {
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      UDP_HEADER_SIZE + IPv4_HEADER_SIZE);
        }
        else {
          #ifdef ASSERT
            assert (context->mode==NETWORK_MODE);
          #endif
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      IPv4_HEADER_SIZE);            
        }
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    ") headers, total ");
        if (context->mode==UDP_MODE) {
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      nread_from_net + UDP_HEADER_SIZE + IPv4_HEADER_SIZE);
        }
        else {
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      nread_from_net + IPv4_HEADER_SIZE);
        }
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " bytes");
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "\n");
      #endif

      // if this packet has arrived for the first time, deliver it to the destination
      bool deliverThisPacket=false;

      uint64_t now = GetTimeStamp();

      if(context->blastTimestamps[ntohs(blastHeader->identifier)] == 0) {
        deliverThisPacket=true;
      }
      else {

        if (now - context->blastTimestamps[ntohs(blastHeader->identifier)] < TIME_UNTIL_SENDING_AGAIN_BLAST) {
          // a blast packet with this same ID has been sent recently
          // do not send it again
          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_YELLOW,
                        " The packet with ID ");
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        ntohs(blastHeader->identifier));
            do_debug_c( 1,
                        ANSI_COLOR_YELLOW,
                        " has been sent recently to ",
                        ntohs(blastHeader->identifier));
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%s",
                        context->tun_if_name);
            do_debug_c( 1,
                        ANSI_COLOR_YELLOW,
                        ". Do not send another copy\n");
            do_debug_c( 3,
                        ANSI_COLOR_YELLOW,
                        "  now (%"PRIu64") - blastTimestamps[%i] (%"PRIu64") < %"PRIu64"\n\n",
                        now,
                        ntohs(blastHeader->identifier),
                        context->blastTimestamps[ntohs(blastHeader->identifier)],
                        TIME_UNTIL_SENDING_AGAIN_BLAST);
          #endif
        }
        else {
          deliverThisPacket=true;
        }
      }

      if(deliverThisPacket) {

        #ifdef DEBUG
          if(context->tunnelMode == TUN_MODE) {
            // tun mode
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        " DEMUXED PACKET with ID ");            
          }
          else {
            // tap mode
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        " DEMUXED FRAME with ID ");              
          }

          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      ntohs(blastHeader->identifier));

          if(debug>1) {
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        ":\n");

            dump_packet (packetLength, &buffer_from_net[sizeof(simplemuxBlastHeader)]);                    
          }
          else {
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        "\n");
          }
        #endif

        // tun mode
        if(context->tunnelMode == TUN_MODE) {
           // write the demuxed packet to the tun interface
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_RESET,
                        " %"PRIu64"",
                        now);

            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        "  Sending packet of ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        packetLength);
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        " bytes to ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%s",
                        context->tun_if_name);
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        "\n");
          #endif

          if (cwrite (context->tun_fd,
                      &buffer_from_net[sizeof(simplemuxBlastHeader)],
                      packetLength ) != packetLength)
          {
            perror("could not write the packet correctly (tun mode, blast)");
          }
          else {
            #ifdef DEBUG
              do_debug_c( 3,
                          ANSI_COLOR_YELLOW,
                          "%"PRIu64"",
                          now);

              do_debug_c( 2,
                          ANSI_COLOR_YELLOW,
                          "  Packet with ID ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "%i",
                          ntohs(blastHeader->identifier));
              do_debug_c( 2,
                          ANSI_COLOR_YELLOW,
                          " sent to ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "%s\n\n",
                          context->tun_if_name);
            #endif

            #ifdef LOGFILE
              // write the log file
              if ( context->log_file != NULL ) {
                fprintf ( context->log_file,
                          "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                          GetTimeStamp(),
                          packetLength,
                          context->net2tun);  // the packet is good
                
                fflush(context->log_file);
              }
            #endif
          }

          // update the timestamp when a packet with this identifier has been sent
          uint64_t now = GetTimeStamp();
          context->blastTimestamps[ntohs(blastHeader->identifier)] = now;
        }
        // tap mode
        else if(context->tunnelMode == TAP_MODE) {
          if (blastHeader->protocolID != IPPROTO_ETHERNET) {
            #ifdef DEBUG
              do_debug_c( 2,
                          ANSI_COLOR_RED,
                          "wrong value of 'Protocol' field received. It should be %i, but it is %i",
                          IPPROTO_ETHERNET,
                          blastHeader->protocolID);
            #endif            
          }
          else {
             // write the demuxed frame to the tap interface
            #ifdef DEBUG
              do_debug_c( 2,
                          ANSI_COLOR_YELLOW,
                          "  Sending frame of ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "%i",
                          packetLength);
              do_debug_c( 2,
                          ANSI_COLOR_YELLOW,
                          " bytes to ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->tun_if_name);
              do_debug_c( 2,
                          ANSI_COLOR_YELLOW,
                          "\n");
            #endif

            if(cwrite ( context->tun_fd,
                        &buffer_from_net[sizeof(simplemuxBlastHeader)],
                        packetLength ) != packetLength)
            {
              perror("could not write the frame correctly (tap mode, blast)");
            }
            else {
              #ifdef DEBUG
                do_debug_c( 3,
                            ANSI_COLOR_RESET,
                            " %"PRIu64"",
                            now);

                do_debug_c( 2,
                            ANSI_COLOR_YELLOW,
                            " Frame with ID ");
                do_debug_c( 2,
                            ANSI_COLOR_RESET,
                            "%i",
                            ntohs(blastHeader->identifier));
                do_debug_c( 2,
                            ANSI_COLOR_YELLOW,
                            " sent to ");
                do_debug_c( 2,
                            ANSI_COLOR_RESET,
                            "%s\n",
                            context->tun_if_name);
              #endif

              #ifdef LOGFILE
                // write the log file
                if ( context->log_file != NULL ) {
                  fprintf ( context->log_file,
                            "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                            GetTimeStamp(),
                            packetLength,
                            context->net2tun);  // the packet is good
                  
                  fflush(context->log_file);
                }
              #endif
            }

            // update the timestamp when a packet with this identifier has been sent
            uint64_t now = GetTimeStamp();
            context->blastTimestamps[ntohs(blastHeader->identifier)] = now;
          }
        }
        else {
          perror ("wrong value of 'tunnelMode'");
          exit (EXIT_FAILURE);
        }
      }

      // this packet requires an ACK
      // send the ACK as soon as the packet arrives
      // send an ACK per arrived packet. Do not check if this is the first time it has arrived
      struct packet ACK;
      ACK.header.packetSize = 0; // the length is only that of the payload 
      ACK.header.protocolID = 0; // the ACK does not have a payload, so no protocolID is needed
      ACK.header.identifier = blastHeader->identifier;
      ACK.header.ACK = THISISANACK;

      sendPacketBlastFlavor(context, &ACK);

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " Sent blast ACK to the network. ID ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(ACK.header.identifier));
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    ", packetLength ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    sizeof(blastHeader));
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " (Blast header) plus ");
        if (context->mode==UDP_MODE) {
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      UDP_HEADER_SIZE + IPv4_HEADER_SIZE);
        }
        else {
          #ifdef ASSERT
            assert (context->mode==NETWORK_MODE);
          #endif
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      IPv4_HEADER_SIZE);
        }
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " (tunneling header) bytes\n");

        do_debug_c( 2,
                    ANSI_COLOR_BOLD_GREEN,
                    "\n");
      #endif

      // no need to add log here because 'sendPacketBlastFlavor()' already does it
    }
    else if((blastHeader->ACK & MASK ) == HEARTBEAT) {
      // heartbeat received

      if(packetLength != 0) {
        perror("Problem with the length of the received blast heartbeat\n");
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "Received wrong blast heartbeat: Its length is %i, but it MUST be %i\n",
                      packetLength + sizeof(blastHeader),
                      sizeof(blastHeader));
        #endif
      }
      else {
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_BOLD_YELLOW,
                      " It is a blast heartbeat");
          do_debug_c( 2,
                      ANSI_COLOR_BOLD_YELLOW,
                      ". Blast header size ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      sizeof(blastHeader));
          do_debug_c( 2,
                      ANSI_COLOR_BOLD_YELLOW,
                      " bytes");
          do_debug_c( 1,
                      ANSI_COLOR_BOLD_YELLOW,
                      "\n");
          do_debug_c( 2,
                      ANSI_COLOR_BOLD_YELLOW,
                      "\n");
        #endif

        uint64_t now = GetTimeStamp();
        context->lastBlastHeartBeatReceived = now;
      }
    }
    else {
      perror("Unknown blast packet type\n");
    }
}

// demux a Normal packet/frame
int demuxPacketNormal(contextSimplemux* context,
                      uint8_t* buffer_from_net,
                      int* position,
                      int num_demuxed_packets,
                      int* first_header_read,
                      int *single_protocol_rec,
                      int *LXT_first_byte,
                      int *maximum_packet_length)
{
  int demuxedPacketLength;  // it will store the length of the demuxed packet/frame

  // check if this is the first separator or not
  if (*first_header_read == 0) {

    // this is a first header:
    //  - SPB will be stored in the most significant bit (0x80)
    //  - LXT will be stored in the 7th bit (0x40)
    
    // Read SPB (one bit)
    // It only appears in the first Simplemux header 
    //  - It is set to '0' if all the multiplexed
    //    packets belong to the same protocol (in this case, the "protocol"
    //    field will only appear in the first Simplemux header)
    //  - It is set to '1' when each packet MAY belong to a different protocol.

    // check if the most significant bit (0x80) is '1'
    if  ((0x80 & buffer_from_net[*position] ) == 0x80 ) {
      *single_protocol_rec = 1;
      //do_debug(2, "single protocol\n");
    }
    else {
      *single_protocol_rec = 0;
      //do_debug(2, "multi protocol\n");
    }

    // Read LXT (one bit)
    // as this is a first header
    //  - LXT bit is the second one (0x40) 
    //  - the maximum length of a single-byte packet is 64 bytes                
    if ((0x40 & buffer_from_net[*position]) == 0x00)
      *LXT_first_byte = 0;
    else
      *LXT_first_byte = 1;

    *maximum_packet_length = 64;
  }

  else { 
    // this is a non-first header
    //  - There is no SPB bit
    //  - LXT will be stored in the most significant bit (0x80)
    //  - the maximum length of a single-byte packet is 128 bytes
    if ((0x80 & buffer_from_net[*position]) == 0x00)
      *LXT_first_byte = 0;
    else
      *LXT_first_byte = 1;
    
    *maximum_packet_length = 128;
  }

  #ifdef DEBUG
    if((context->mode == UDP_MODE) || (context->mode == NETWORK_MODE) ) {

      if(context->tunnelMode == TUN_MODE) {
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " DEMUXED PACKET #");
      }
      else {
        // TAP_MODE
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " DEMUXED FRAME #");
      }
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  num_demuxed_packets);

      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  ":");
    }
    else {
      // TCP_SERVER_MODE or TCP_CLIENT_MODE
      if(context->tunnelMode == TUN_MODE) {
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " PACKET DEMUXED");
      }
      else {
        // TAP_MODE
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " FRAME DEMUXED");
      }
      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  ":"); 
    }
  #endif

  if (*LXT_first_byte == 0) {
    // the LXT bit of the first byte is 0 => the separator is one-byte long

    // I have to convert the 6 (or 7) less significant bits to an integer, which means the length of the packet
    // since the two most significant bits are 0, the length is the value of the char
    demuxedPacketLength = buffer_from_net[*position] % *maximum_packet_length;

    #ifdef DEBUG
      if (debug>0) {
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " Mux separator of 1 byte: ");
        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "0x%02x",
                    buffer_from_net[*position]);
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " (");

        bool bits[8];   // used for printing the bits of a byte in debug mode
        FromByte(buffer_from_net[*position], bits);
        PrintByte(2, 8, bits);
        do_debug_c(2, ANSI_COLOR_YELLOW, ")");
      }
    #endif

    // the length is one byte, so advance one position
    *position = *position + 1;
  }

  else {
    // the LXT bit of the first byte is 1 => the separator is NOT one-byte

    // check whether this is a 2-byte or a 3-byte length
    // check the bit 7 of the second byte

    // If the LXT bit is 0, this is a two-byte length
    if ((0x80 & buffer_from_net[*position + 1] ) == 0x00 ) {

      // I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
      // I do the product by 128, because the next byte includes 7 bits of the length
      demuxedPacketLength = ((buffer_from_net[*position] % *maximum_packet_length) * 128 );
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_YELLOW,
                    " initial packet_length (only most significant bits): ");
        do_debug_c( 3,
                    ANSI_COLOR_RESET,
                    "%d, ",
                    demuxedPacketLength);
      #endif
      /*
      uint8_t mask;
      if (*maximum_packet_length == 64)
        mask = 0x3F;
      else
        mask = 0x7F;
      demuxedPacketLength = ((buffer_from_net[*position] & *maximum_packet_length) << 7 );*/

      // I add the value of the 7 less significant bits of the second byte
      demuxedPacketLength = demuxedPacketLength + (buffer_from_net[*position + 1] % 128);
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_YELLOW,
                    "packet_length (all the bits): ");
        do_debug_c( 3,
                    ANSI_COLOR_RESET,
                    "%d\n",
                    demuxedPacketLength);
      #endif
      //demuxedPacketLength = demuxedPacketLength + (buffer_from_net[*position + 1] & 0x7F);

      #ifdef DEBUG
        if (debug>0) {
          bool bits[8];   // used for printing the bits of a byte in debug mode

          // print the first byte
          FromByte(buffer_from_net[*position], bits);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      " Mux separator of 2 bytes: ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x",
                      buffer_from_net[*position]);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      " (");
          PrintByte(2, 8, bits);
          
          // print the second byte
          FromByte(buffer_from_net[*position + 1], bits);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      ") ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x",
                      buffer_from_net[*position + 1]);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      " (");
          PrintByte(2, 8, bits);
          do_debug_c(2, ANSI_COLOR_YELLOW, ")");
        }
      #endif

      // the length is two bytes, so advance two positions
      *position = *position + 2;
    }

    // If the LXT bit of the second byte is 1, this is a three-byte length
    else {
      // I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
      // I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
      //demuxedPacketLength = ((buffer_from_net[*position] % maximum_packet_length) * 16384 );
      demuxedPacketLength = ((buffer_from_net[*position] % *maximum_packet_length) << 14 );

      // I get the 6 (or 7) less significant bits of the second byte by using modulo 128
      // I do the product by 128, because the next byte includes 7 bits of the length
      //demuxedPacketLength = demuxedPacketLength + ((buffer_from_net[*position + 1] % 128) * 128 );
      demuxedPacketLength = demuxedPacketLength + ((buffer_from_net[*position + 1] & 0x7F) << 7 );

      // I add the value of the 7 less significant bits of the second byte
      //demuxedPacketLength = demuxedPacketLength + (buffer_from_net[*position + 2] % 128);
      demuxedPacketLength = demuxedPacketLength + (buffer_from_net[*position + 2] & 0x7F);

      #ifdef DEBUG
        if (debug > 0) {
          bool bits[8];   // used for printing the bits of a byte in debug mode

          // print the first byte
          FromByte(buffer_from_net[*position], bits);
          do_debug_c( 2,
                      ANSI_COLOR_GREEN,
                      " Mux separator of 3 bytes: ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x ",
                      buffer_from_net[*position]);
          PrintByte(2, 8, bits);
          
          // print the second byte
          FromByte(buffer_from_net[*position + 1], bits);
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      " %02x ",
                      buffer_from_net[*position + 1]);
          PrintByte(2, 8, bits);  
          
          // print the third byte
          FromByte(buffer_from_net[*position + 2], bits);
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      " %02x ",
                      buffer_from_net[*position + 2]);
          PrintByte(2, 8, bits);
        }
      #endif

      // the length is three bytes, so advance three positions
      *position = *position + 3;
    }
  }

  // read the 'Protocol'

  // check if this is the first separator or not
  if (*first_header_read == 0) {    // this is the first separator. The protocol field will always be present
    // the next thing I expect is a 'protocol' field
    context->protocol_rec = buffer_from_net[*position];
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  ". Protocol ");
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  buffer_from_net[*position]);
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  ", 0x%02x",
                  buffer_from_net[*position]);

      if(context->protocol_rec == IPPROTO_IP_ON_IP)
        do_debug_c(1, ANSI_COLOR_RESET, " (IP)");
      else if(context->protocol_rec == IPPROTO_ROHC)
        do_debug_c(1, ANSI_COLOR_RESET, " (RoHC)");
      else if(context->protocol_rec == IPPROTO_ETHERNET)
        do_debug_c(1, ANSI_COLOR_RESET, " (Ethernet)");
    #endif

    // the Protocol is one byte, so move one position
    *position = *position + 1;

    // if I am here, it means that I have read the first separator
    *first_header_read = 1;
  }
  else {
    // non-first separator. The protocol field may or may not be present
    if ( *single_protocol_rec == 0 ) {
      // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
      context->protocol_rec = buffer_from_net[*position];
      if(*single_protocol_rec == 0) {
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_YELLOW,
                      ". Protocol ");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      buffer_from_net[*position]);
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      ", 0x%02x",
                      buffer_from_net[*position]);

          if(context->protocol_rec == IPPROTO_IP_ON_IP)
            do_debug_c(1, ANSI_COLOR_RESET, " (IP)");
          else if(context->protocol_rec == IPPROTO_ROHC)
            do_debug_c(1, ANSI_COLOR_RESET, " (RoHC)");
          else if(context->protocol_rec == IPPROTO_ETHERNET)
            do_debug_c(1, ANSI_COLOR_RESET, " (Ethernet)");
        #endif
      }

      // the Protocol is one byte, so move one position
      *position = *position + 1;
    }
  }
  #ifdef DEBUG
    do_debug_c( 1,
                ANSI_COLOR_YELLOW,
                ". Length ");
    do_debug_c( 1,
                ANSI_COLOR_RESET,
                "%i",
                demuxedPacketLength);
    do_debug_c( 1,
                ANSI_COLOR_YELLOW,
                " bytes\n");
  #endif

  return demuxedPacketLength;
}

// demux a fast packet/frame
// for TCP it returns 0
// for UDP/network it returns the length of the demuxed packet
int demuxPacketFast(contextSimplemux* context,
                    uint16_t bundleLength,
                    uint8_t* buffer_from_net,
                    int* position,
                    int num_demuxed_packets)
{
  int demuxedPacketLength = 0;

  #ifdef DEBUG
    if((context->mode == UDP_MODE) || (context->mode == NETWORK_MODE) ) {
      if(context->tunnelMode == TUN_MODE) {
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " DEMUXED PACKET #");
      }
      else {
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " DEMUXED FRAME #");
      }
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  num_demuxed_packets);          
      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  ":");
    }
    else {
      // TCP_SERVER_MODE or TCP_CLIENT_MODE
      if(context->tunnelMode == TUN_MODE) {
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " PACKET DEMUXED");
      }
      else {
        // TAP_MODE
        do_debug_c( 2,
                    ANSI_COLOR_YELLOW,
                    " FRAME DEMUXED");
      }
      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  ":"); 
    }
  #endif


  if ((context->mode == TCP_SERVER_MODE) || (context->mode == TCP_CLIENT_MODE)) {
    // do nothing, because in TCP mode I have already read the length
    #ifdef DEBUG
      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  " Length ");
      do_debug_c( 2,
                  ANSI_COLOR_RESET,
                  "%i",
                  bundleLength);
      do_debug_c( 2,
                  ANSI_COLOR_YELLOW,
                  " bytes.\n");
    #endif

    // do nothing, because I have already read the Protocol
  }
  else {
    // I am in fast mode, but not in TCP mode, so I still have to read the length
    // It is in the two first bytes of the buffer
    //do_debug(0,"buffer_from_net[*position] << 8: 0x%02x  buffer_from_net[*position+1]: 0x%02x\n", buffer_from_net[*position] << 8, buffer_from_net[position+1]);

    // apply the structure of a fast mode packet
    simplemuxFastHeader* fastHeader = (simplemuxFastHeader*) (&buffer_from_net[*position]);

    // read the length
    demuxedPacketLength = ntohs(fastHeader->packetSize);
    //demuxedPacketLength = (buffer_from_net[*position] << 8 ) + buffer_from_net[*position+1];

    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  " Length ");
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  demuxedPacketLength);
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  " bytes. ");
    #endif

    // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
    context->protocol_rec = fastHeader->protocolID;

    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  "Protocol ");
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  context->protocol_rec);
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  ", 0x%02x",
                  context->protocol_rec);

      if(context->protocol_rec == IPPROTO_IP_ON_IP)
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    " (IP)\n");

      else if(context->protocol_rec == IPPROTO_ROHC)
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    " (RoHC)\n");

      else if(context->protocol_rec == IPPROTO_ETHERNET)
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    " (Ethernet)\n");
      else
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "\n");          
    #endif

    // move 'position' to the end of the simplemuxFast header
    *position = *position + sizeof(simplemuxFastHeader);
  }
  return demuxedPacketLength;
}

// send the demuxed/decompressed packet/frame to the tun/tap interface
void sendPacketToTun (contextSimplemux* context,
                      uint8_t* demuxed_packet,
                      int demuxedPacketLength)
{
  // tun mode
  if(context->tunnelMode == TUN_MODE) {
     // write the demuxed packet to the tun interface
    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  "  Sending packet of ");
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%i",
                  demuxedPacketLength);
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  " bytes to ");
      do_debug_c( 1,
                  ANSI_COLOR_RESET,
                  "%s",
                  context->tun_if_name);
      do_debug_c( 1,
                  ANSI_COLOR_YELLOW,
                  "\n");
    #endif

    if (cwrite (context->tun_fd,
                demuxed_packet,
                demuxedPacketLength ) != demuxedPacketLength)
    {
      perror("could not write the demuxed packet correctly (tun mode)");
    }
  }
  // tap mode
  else if(context->tunnelMode == TAP_MODE) {
    if (context->protocol_rec != IPPROTO_ETHERNET) {
      #ifdef DEBUG
        do_debug_c( 2,
                    ANSI_COLOR_RED,
                    "wrong value of 'Protocol' field received. It should be %i, but it is %i",
                    IPPROTO_ETHERNET,
                    context->protocol_rec);
      #endif            
    }
    else {
       // write the demuxed packet to the tap interface
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "  Sending frame of ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    demuxedPacketLength);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    " bytes to ");
        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%s",
                    context->tun_if_name);
        do_debug_c( 1,
                    ANSI_COLOR_YELLOW,
                    "\n");
      #endif

      if (cwrite (context->tun_fd,
                  demuxed_packet,
                  demuxedPacketLength ) != demuxedPacketLength)
      {
        perror("could not write the demuxed packet correctly (tap mode)");
      }
    }
  }
  else {
    perror ("wrong value of 'tunnelMode'");
    exit (EXIT_FAILURE);
  }
  
  #ifdef DEBUG
    do_debug(2, "\n");
  #endif

  #ifdef LOGFILE
    // write the log file
    if ( context->log_file != NULL ) {
      fprintf ( context->log_file,
                "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                GetTimeStamp(),
                demuxedPacketLength,
                context->net2tun);  // the packet is good
      
      fflush(context->log_file);
    }
  #endif
}

// decompress a RoHC packet
// It returns:
//  1 if the packet has been decompressed correctly
//  0 if the packet could not be decompressed
//
// demuxedPacketLength is modified: at the beginning, it contains
//the length of the demuxed (RoHC-compressed) packet. At the end,
//it contains the length of the decompressed packet
//
// RoHC variables are global, so I don't need to pass them as arguments
int decompressRohcPacket( contextSimplemux* context,
                          uint8_t* demuxed_packet,
                          int* demuxedPacketLength,
                          rohc_status_t* status,
                          int nread_from_net)
{
  int sendPacket; // this is the value returned by this function

  if ( context->rohcMode == 0 ) {
    // I cannot decompress the packet if I am not in ROHC mode
    sendPacket = 0;

    #ifdef DEBUG
      do_debug_c( 1,
                  ANSI_COLOR_RED,
                  " RoHC packet received, but not in RoHC mode. Packet dropped\n");
    #endif

    #ifdef LOGFILE
      // write the log file
      if ( context->log_file != NULL ) {
        fprintf ( context->log_file,
                  "%"PRIu64"\tdrop\tno_RoHC_mode\t%i\t%"PRIu32"\n",
                  GetTimeStamp(),
                  *demuxedPacketLength,
                  context->net2tun);  // the packet may be good, but the decompressor is not in ROHC mode
        
        fflush(context->log_file);
      }
    #endif
  }
  else {
    // reset the buffers where the rohc packets, ip packets and feedback info are to be stored
    rohc_buf_reset (&ip_packet_d);
    rohc_buf_reset (&rohc_packet_d);
    rohc_buf_reset (&rcvd_feedback);
    rohc_buf_reset (&feedback_send);

    // Copy the compressed length and the compressed packet
    rohc_packet_d.len = *demuxedPacketLength;

    // Copy the packet itself
    for (int l = 0; l < *demuxedPacketLength ; l++) {
      rohc_buf_byte_at(rohc_packet_d, l) = demuxed_packet[l];
    }
    // I try to use memcpy instead, but it does not work properly
    // memcpy(demuxed_packet, rohc_buf_data_at(rohc_packet_d, 0), demuxedPacketLength);

    #ifdef DEBUG
      // dump the ROHC packet on terminal
      dump_packet (*demuxedPacketLength, demuxed_packet);
    #endif

    // decompress the packet
    *status = rohc_decompress3( decompressor,
                                rohc_packet_d,
                                &ip_packet_d,
                                &rcvd_feedback,
                                &feedback_send);

    // if bidirectional mode has been set, check the feedback
    if ( context->rohcMode > 1 ) {

      // check if the decompressor has received feedback, and it has to be delivered to the local compressor
      if ( !rohc_buf_is_empty( rcvd_feedback) ) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      "   Feedback received from the remote compressor by the decompressor (");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      rcvd_feedback.len);
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      " bytes), to be delivered to the local compressor\n");

          // dump the feedback packet on terminal
          if (debug>0) {
            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        "  RoHC feedback packet received\n");

            dump_packet (rcvd_feedback.len, rcvd_feedback.data );

            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        "\n");
          }
        #endif

        // deliver the feedback received to the local compressor
        //https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
        if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_RED,
                        "   Error delivering feedback received from the remote compressor to the compressor\n");
          #endif
        }
        else {
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_MAGENTA,
                        "   Feedback from the remote compressor delivered to the compressor: ");
            do_debug_c( 3,
                        ANSI_COLOR_RESET,
                        "%i",
                        rcvd_feedback.len);
            do_debug_c( 3,
                        ANSI_COLOR_MAGENTA,
                        " bytes\n");
          #endif
        }
      }
      else {
        // rohc_buf is empty
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      "   No feedback received by the decompressor from the remote compressor\n");
        #endif
      }

      // check if the decompressor has generated feedback to be sent by the feedback channel to the other peer
      if ( !rohc_buf_is_empty( feedback_send ) ) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      "   Generated feedback (");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      feedback_send.len);
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      " bytes) to be sent by the feedback channel to the peer\n");

          // dump the RoHC packet on terminal
          if (debug>0) {
            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        "  RoHC feedback packet generated by the local decompressor (");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        feedback_send.len);
            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        " bytes)\n");

            dump_packet (feedback_send.len, feedback_send.data );
          }
        #endif

        // send the feedback packet to the peer
        if (sendto( context->feedback_fd,
                    feedback_send.data,
                    feedback_send.len,
                    0,
                    (struct sockaddr *)&(context->feedback_remote),
                    sizeof(context->feedback_remote)) == -1)
        {
          perror("sendto() failed when sending a RoHC feedback packet");
        }
        else {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        "  The RoHC feedback packet (");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        feedback_send.len);
            do_debug_c( 2,
                        ANSI_COLOR_MAGENTA,
                        " bytes) has been successfully sent to the remote compressor\n");
          #endif
        }
      }
      else {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_MAGENTA,
                      "   No feedback generated by the local decompressor\n");
        #endif
      }
    }

    // check the result of the decompression

    // decompression is successful
    if ( *status == ROHC_STATUS_OK) {
      sendPacket = 1; // this packet has to be sent

      if(!rohc_buf_is_empty(ip_packet_d))  {  // decompressed packet is not empty
  
        // ip_packet.len bytes of decompressed IP data available in ip_packet
        *demuxedPacketLength = ip_packet_d.len;

        #ifdef ASSERT
          // ensure that there is space to copy the packet
          assert(*demuxedPacketLength <= BUFSIZE);
        #endif

        // copy the packet
        memcpy(demuxed_packet, rohc_buf_data_at(ip_packet_d, 0), *demuxedPacketLength);

        #ifdef DEBUG
          //dump the IP packet on the standard output
          do_debug_c( 1,
                      ANSI_COLOR_MAGENTA,
                      "  IP packet resulting from the RoHC decompression: ",
                      *demuxedPacketLength);
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      *demuxedPacketLength);
          do_debug_c( 1,
                      ANSI_COLOR_MAGENTA,
                      " bytes\n");

          if (debug > 1) {
            // dump the decompressed IP packet on terminal
            dump_packet (ip_packet_d.len, ip_packet_d.data );
          }
        #endif
      }
      else {
        // no IP packet was decompressed because of ROHC segmentation or
        // feedback-only packet:
        //  - the ROHC packet was a non-final segment, so at least another
        //    ROHC segment is required to be able to decompress the full
        //    ROHC packet
        //  - the ROHC packet was a feedback-only packet, it contained only
        //    feedback information, so there was nothing to decompress
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "  no IP packet decompressed\n");
        #endif

        #ifdef LOGFILE
          // write the log file
          if ( context->log_file != NULL ) {
            fprintf ( context->log_file,
                      "%"PRIu64"\trec\tROHC_feedback\t%i\t%"PRIu32"\tfrom\t%s\t%d\n",
                      GetTimeStamp(),
                      nread_from_net,
                      context->net2tun,
                      inet_ntoa(context->remote.sin_addr),
                      ntohs(context->remote.sin_port));  // the packet is bad so I add a line
            
            fflush(context->log_file);
          }
        #endif
      }
    }

    else if ( *status == ROHC_STATUS_NO_CONTEXT ) {
      // failure: decompressor failed to decompress the ROHC packet
      sendPacket = 0; // this packet has to be dropped

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    "  decompression of ROHC packet failed. No context\n");
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          // the packet is bad
          fprintf ( context->log_file,
                    "%"PRIu64"\terror\tdecomp_failed\t%i\t%"PRIu32"\n",
                    GetTimeStamp(),
                    nread_from_net, context->net2tun);  
          
          fflush(context->log_file);
        }
      #endif
    }

    else if ( *status == ROHC_STATUS_OUTPUT_TOO_SMALL ) {  // the output buffer is too small for the compressed packet
      // failure: decompressor failed to decompress the ROHC packet 
      sendPacket = 0; // this packet has to be dropped

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    "  decompression of ROHC packet failed. Output buffer is too small\n");
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          // the packet is bad
          fprintf ( context->log_file,
                    "%"PRIu64"\terror\tdecomp_failed. Output buffer is too small\t%i\t%"PRIu32"\n",
                    GetTimeStamp(),
                    nread_from_net,
                    context->net2tun);  
          
          fflush(context->log_file);
        }
      #endif
    }

    else if ( *status == ROHC_STATUS_MALFORMED ) {
      // the decompression failed because the ROHC packet is malformed 
      // failure: decompressor failed to decompress the ROHC packet
      sendPacket = 0; // this packet has to be dropped

      #ifdef DEBUG 
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    "  decompression of ROHC packet failed. No context\n");
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          // the packet is bad
          fprintf ( context->log_file,
                    "%"PRIu64"\terror\tdecomp_failed. No context\t%i\t%"PRIu32"\n",
                    GetTimeStamp(),
                    nread_from_net,
                    context->net2tun);  
          
          fflush(context->log_file);
        }
      #endif
    }

    else if ( *status == ROHC_STATUS_BAD_CRC ) {      // the CRC detected a transmission or decompression problem
      // failure: decompressor failed to decompress the ROHC packet 
      sendPacket = 0; // this packet has to be dropped

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    "  decompression of ROHC packet failed. Bad CRC\n");
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          // the packet is bad
          fprintf ( context->log_file,
                    "%"PRIu64"\terror\tdecomp_failed. Bad CRC\t%i\t%"PRIu32"\n",
                    GetTimeStamp(),
                    nread_from_net,
                    context->net2tun);  
          
          fflush(context->log_file);
        }
      #endif
    }

    else if ( *status == ROHC_STATUS_ERROR ) {        // another problem occurred
      // failure: decompressor failed to decompress the ROHC packet
      sendPacket = 0; // this packet has to be dropped

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    "  decompression of ROHC packet failed. Other error\n");
      #endif

      #ifdef LOGFILE
        // write the log file
        if ( context->log_file != NULL ) {
          // the packet is bad
          fprintf ( context->log_file,
                    "%"PRIu64"\terror\tdecomp_failed. Other error\t%i\t%"PRIu32"\n",
                    GetTimeStamp(),
                    nread_from_net,
                    context->net2tun);  
          
          fflush(context->log_file);
        }
      #endif
    }
  }
  return sendPacket;
}