//#include "commonFunctions.h"
//#include "packetsToSend.c"
#include "buildMuxedPacket.c"

/* Reads a multiplexed packet from the network
 * it returns:
 * 1  a multiplexed packet has been read from the network
 * 0  a correct but not multiplexed packet has been read from the network
 * -1 error. Incorrect read
 */
int readPacketFromNet(struct contextSimplemux* context,
                      uint8_t* buffer_from_net,
                      int* nread_from_net,
                      uint16_t* packet_length )
{
  int is_multiplexed_packet = -1;
  uint8_t buffer_from_net_aux[BUFSIZE];

  if (context->mode == UDP_MODE) {
    // a packet has been received from the network, destined to the multiplexing port
    // 'slen' is the length of the IP address
    // I cannot use 'remote' because it would replace the IP address and port. I use 'received'
    socklen_t slen = sizeof(context->received);  // size of the socket. The type is like an int, but adequate for the size of the socket
    *nread_from_net = recvfrom (context->udp_mode_fd,
                                buffer_from_net,
                                BUFSIZE,
                                0,
                                (struct sockaddr *)&(context->received),
                                &slen );
    if (*nread_from_net == -1) {
      perror ("[readPacketFromNet] recvfrom() UDP error");
    }
    else {
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_YELLOW,
                    "  Read %i bytes from the UDP socket\n",
                    *nread_from_net);
      #endif
    }
    // 'buffer_from_net' now contains the payload
    //(simplemux headers and multiplexled packets/frames)
    //of a full packet or frame.
    // It does not have the IP and UDP headers

    // The destination of the packet MUST BE the multiplexing port, since
    //I have received it in this socket

    // check if the packet comes from the multiplexing port
    if (context->port == ntohs(context->received.sin_port)) 
      is_multiplexed_packet = 1;
    else
      is_multiplexed_packet = 0;
  }

  else if (context->mode  == NETWORK_MODE) {
    // a packet has been received from the network, destined to the local interface for muxed packets
    *nread_from_net = cread ( context->network_mode_fd,
                              buffer_from_net_aux,
                              BUFSIZE);

    if (*nread_from_net==-1) {
      perror ("[readPacketFromNet] cread() error in network mode");
    }
    else {
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_CYAN,
                    "  Read ");
        do_debug_c( 3,
                    ANSI_COLOR_RESET,
                    "%i",
                    *nread_from_net);
        do_debug_c( 3,
                    ANSI_COLOR_CYAN,
                    " bytes from the network socket\n");
      #endif
    }    
    // 'buffer_from_net' now contains the headers
    //(IP and Simplemux) and the payload of
    //a full packet or frame

    // no extensions of the IP header are supported
    #ifdef ASSERT
      assert(sizeof(struct iphdr) == IPv4_HEADER_SIZE);
    #endif

    // copy from 'buffer_from_net_aux' everything except the IP header (usually the first 20 bytes)
    memcpy (buffer_from_net,
            buffer_from_net_aux + sizeof(struct iphdr),
            *nread_from_net - sizeof(struct iphdr));

    // correct the size of 'nread from net', substracting the size of the IP header
    *nread_from_net = *nread_from_net - sizeof(struct iphdr);

    // Get IP Header of received packet
    struct iphdr ipheader;
    GetIpHeader(&ipheader,buffer_from_net_aux);

    // ensure that the IP header size is correct (20 bytes is the only supported option)
    // the length is expressed in the second half of the first byte
    // if it is 0x05, it means that the length is 20 bytes
    if ((ipheader.ihl & 0x0F) != 0x05) {
      perror ("[readPacketFromNet] in network mode, only IP headers of 20 bytes are supported");
      is_multiplexed_packet = 0;
    }
    else {
      // ensure that the protocol is correct
      if (ipheader.protocol == context->ipprotocol)
        is_multiplexed_packet = 1;
      else
        is_multiplexed_packet = 0;      
    }
  }

  else if ((context->mode  == TCP_SERVER_MODE) || (context->mode  == TCP_CLIENT_MODE)) {

    // some bytes have been received from the network, destined to the TCP socket
    
    // TCP mode requires fast flavor
    #ifdef ASSERT
      assert(context->flavor == 'F');
    #endif

    /* Once the sockets are connected, the client can read from it
     * through a normal 'read' call on the socket descriptor.
     * Read 'buffer_from_net' bytes
     * This call returns up to N bytes of data. If there are fewer 
     *bytes available than requested, the call returns the number currently available.
     */
    //*nread_from_net = read(context->tcp_server_fd, buffer_from_net, sizeof(buffer_from_net));
    
    // I only read one packet (at most) each time the program goes through this part

    if (context->pendingBytesMuxedPacket == 0) {

      // I have to start reading a new muxed packet: separator and payload
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_CYAN,
                    "  Reading TCP. No pending bytes of the muxed packet. Start reading a new separator\n");
      #endif

      // read a separator (3 or 4 bytes), or a part of it
      if (context->mode  == TCP_SERVER_MODE) {
        *nread_from_net = read( context->tcp_server_fd,
                                buffer_from_net,
                                context->sizeSeparatorFastMode - context->readTcpSeparatorBytes);
      }
      else {
        *nread_from_net = read( context->tcp_client_fd,
                                buffer_from_net,
                                context->sizeSeparatorFastMode - context->readTcpSeparatorBytes);
      }
      #ifdef DEBUG
        do_debug_c (3,
                    ANSI_COLOR_CYAN,
                    "   ");
        do_debug_c (3,
                    ANSI_COLOR_RESET,
                    "%i",
                    *nread_from_net);
        do_debug_c (3,
                    ANSI_COLOR_CYAN,
                    " bytes of the separator read from the TCP socket");
      #endif

      if(*nread_from_net < 0)  {
        perror("[readPacketFromNet] read() error TCP mode");
      }

      else if(*nread_from_net == 0) {
        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if (*nread_from_net < context->sizeSeparatorFastMode - context->readTcpSeparatorBytes) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      "  (part of the separator. Still %i bytes missing)\n",
                      context->sizeSeparatorFastMode - context->readTcpSeparatorBytes - *nread_from_net);
        #endif

        // I have read part of the separator
        context->readTcpSeparatorBytes = context->readTcpSeparatorBytes + *nread_from_net;

        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if(*nread_from_net == context->sizeSeparatorFastMode - context->readTcpSeparatorBytes) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      " (the complete separator has ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->sizeSeparatorFastMode);
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      " bytes)\n");
        #endif

        // I have read the complete separator

        // I can now obtain the length of the packet
        // the first byte is the Most Significant Byte of the length
        // the second byte is the Less Significant Byte of the length
        context->length_muxed_packet = (buffer_from_net[0] << 8)  + buffer_from_net[1];
        context->pendingBytesMuxedPacket = context->length_muxed_packet;

        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      "Read Fast separator from the TCP socket: Length ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->length_muxed_packet);
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      " (");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x%02x",
                      buffer_from_net[0],
                      buffer_from_net[1]);
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      ")");
        #endif

        // read the Protocol field
        context->protocol_rec = buffer_from_net[2];
        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      ". Protocol ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->protocol_rec);
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      " (");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x",
                      buffer_from_net[2]);
          do_debug_c( 2,
                      ANSI_COLOR_CYAN,
                      ")\n");
        #endif

        // read the packet itself (without the separator)
        // I only read the length of the packet
        if (context->mode  == TCP_SERVER_MODE) {
          *nread_from_net = read( context->tcp_server_fd,
                                  buffer_from_net,
                                  context->pendingBytesMuxedPacket);
        }
        else {
          *nread_from_net = read( context->tcp_client_fd,
                                  buffer_from_net,
                                  context->pendingBytesMuxedPacket);
        }
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      "   ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      *nread_from_net);
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      " bytes of the muxed packet read from the TCP socket");
        #endif

        if(*nread_from_net < 0)  {
          perror("[readPacketFromNet] read() error TCP server mode");
        }

        else if (*nread_from_net < context->pendingBytesMuxedPacket) {
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_CYAN,
                        "  (part of a muxed packet). Pending ");
            do_debug_c( 3,
                        ANSI_COLOR_RESET,
                        "%i",
                        context->pendingBytesMuxedPacket - *nread_from_net);
            do_debug_c( 3,
                        ANSI_COLOR_CYAN,
                        " bytes\n");
          #endif

          // I have not read the whole packet
          // next time I will have to keep on reading
          context->pendingBytesMuxedPacket = context->pendingBytesMuxedPacket - *nread_from_net;
          context->readTcpBytes = context->readTcpBytes + *nread_from_net;

          //do_debug(2,"Read %d bytes from the TCP socket. Total %d\n", *nread_from_net, context->readTcpBytes); 
          // I have not finished reading a muxed packet
          is_multiplexed_packet = -1;
        }
        else if (*nread_from_net == context->pendingBytesMuxedPacket) {
          // I have read a complete packet
          *packet_length = context->readTcpBytes + *nread_from_net;

          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_CYAN,
                        " (complete muxed packet of ");
            do_debug_c( 3,
                        ANSI_COLOR_RESET,
                        "%i",
                        *packet_length);
            do_debug_c( 3,
                        ANSI_COLOR_CYAN,
                        " bytes)\n");
          #endif

          // reset the variables
          context->readTcpSeparatorBytes = 0;
          context->pendingBytesMuxedPacket = 0;
          context->readTcpBytes = 0;

          // I have finished reading a muxed packet
          is_multiplexed_packet = 1;
        }
      }              
    }
    else { // context->pendingBytesMuxedPacket > 0
      // I have to finish reading the TCP payload
      // I try to read 'pendingBytesMuxedPacket' and to put them at position 'context->readTcpBytes'
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_CYAN,
                    "  Reading TCP. %i TCP bytes pending of the previous payload\n",
                    context->pendingBytesMuxedPacket);
      #endif

      if (context->mode  == TCP_SERVER_MODE) {
        *nread_from_net = read( context->tcp_server_fd,
                                &(buffer_from_net[(context->readTcpBytes)]),
                                context->pendingBytesMuxedPacket);
      }
      else {
        *nread_from_net = read( context->tcp_client_fd,
                                &(buffer_from_net[(context->readTcpBytes)]),
                                context->pendingBytesMuxedPacket);
      }
      #ifdef DEBUG
        do_debug_c( 3,
                    ANSI_COLOR_CYAN,
                    "   %i bytes read from the TCP socket ",
                    *nread_from_net);
      #endif

      if(*nread_from_net < 0)  {
        perror("[readPacketFromNet] read() error TCP mode");
      }

      else if(*nread_from_net == 0) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_RED,
                      "  (I have read 0 bytes)\n");
        #endif
        is_multiplexed_packet = -1;
      }

      else if(*nread_from_net < context->pendingBytesMuxedPacket) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      "  (I have not yet read the whole muxed packet: pending ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->length_muxed_packet - *nread_from_net);
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      " bytes)\n");
        #endif

        // I have not read the whole packet
        // next time I will have to keep on reading
        context->pendingBytesMuxedPacket = context->length_muxed_packet - *nread_from_net;
        context->readTcpBytes = context->readTcpBytes + *nread_from_net;

        // I have not finished to read the pending bytes of this packet
        is_multiplexed_packet = -1;
      }
      else if(*nread_from_net == context->pendingBytesMuxedPacket) {
        #ifdef DEBUG
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      "   I have read all the pending bytes (");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      *nread_from_net);
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      ") of this muxed packet. Total ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->length_muxed_packet);
          do_debug_c( 3,
                      ANSI_COLOR_CYAN,
                      " bytes\n",
                      context->length_muxed_packet);
        #endif

        // I have read the pending bytes of this packet
        context->pendingBytesMuxedPacket = 0;
        //context->readTcpBytes = context->readTcpBytes + *nread_from_net;

        *nread_from_net = context->readTcpBytes + *nread_from_net;

        // reset the variables
        context->readTcpSeparatorBytes = 0;
        context->readTcpBytes = 0;
        is_multiplexed_packet = 1;
      }
      
      else /*if(*nread_from_net > context->pendingBytesMuxedPacket) */ {
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "ERROR: I have read all the pending bytes (");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->pendingBytesMuxedPacket);
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      ") of this muxed packet, and some more (");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      *nread_from_net - context->pendingBytesMuxedPacket);
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "). Abort\n");
        #endif

        // I have read the pending bytes of this packet, plus some more bytes
        // it doesn't make sense, because I have only read 'context->pendingBytesMuxedPacket'
        return(-1);
      }              
    }
  } 
  else {
    perror("[readPacketFromNet] Unknown mode");
    return(-1);      
  }

  return is_multiplexed_packet;
}


int demuxPacketFromNet( struct contextSimplemux* context,
                        int nread_from_net,
                        uint16_t packet_length,
                        uint8_t* buffer_from_net,
                        //uint8_t* protocol_rec,
                        rohc_status_t* status )
{
  // increase the counter of the number of packets read from the network
  (context->net2tun)++;

  switch (context->mode) {
    case UDP_MODE:
      #ifdef DEBUG
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
                  " bytes\n",
                  nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );
      #endif

      #ifdef LOGFILE
        // write the log file

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
            struct simplemuxBlastHeader* blastHeader = (struct simplemuxBlastHeader*) (buffer_from_net);

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
      #endif
    break;

    case TCP_CLIENT_MODE:
      #ifdef DEBUG
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
      #endif

      #ifdef LOGFILE
        // write the log file
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
      #endif
    break;

    case TCP_SERVER_MODE:
      #ifdef DEBUG
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
      #endif

      #ifdef LOGFILE
        // write the log file
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
      #endif
    break;

    case NETWORK_MODE:
      #ifdef DEBUG
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
                    ", protocol ");        

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%d",
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
      #endif

      #ifdef LOGFILE
        // write the log file
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
            struct simplemuxBlastHeader* blastHeader = (struct simplemuxBlastHeader*) (buffer_from_net);

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

      #endif
    break;
  }

  #ifdef DEBUG
    if(debug>0) {
      uint64_t now = GetTimeStamp();
      do_debug_c( 3,
                  ANSI_COLOR_YELLOW,
                  "%"PRIu64" Packet arrived from the network\n",
                  now);         
    }
  #endif

  // blast flavor
  if(context->flavor == 'B') {
    // there should be a single packet

    // apply the structure of a blast mode packet
    struct simplemuxBlastHeader* blastHeader = (struct simplemuxBlastHeader*) (buffer_from_net);

    int length = ntohs(blastHeader->packetSize);

    if (length > BUFSIZE) {
      perror("Problem with the length of the received packet\n");
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_RED,
                    " Length is %i, but the maximum allowed size is %i\n",
                    length,
                    BUFSIZE);
      #endif
    }

    // check if this is an ACK or not
    if((blastHeader->ACK & MASK ) == THISISANACK) {

      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " Arrived blast ACK packet ID ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i\n",
                    ntohs(blastHeader->identifier));

        // an ACK has arrived. The corresponding packet can be removed from the list of pending packets
        do_debug_c( 2,
                    ANSI_COLOR_BOLD_GREEN,
                    " Removing packet with ID ");

        do_debug_c( 2,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(blastHeader->identifier));

        do_debug_c( 2,
                    ANSI_COLOR_BOLD_GREEN,
                    " from the list\n");

        if(debug>2)
          printList(&context->unconfirmedPacketsBlast);
      #endif

      if(delete(&context->unconfirmedPacketsBlast,ntohs(blastHeader->identifier))==false) {
        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_BOLD_GREEN,
                      "The packet had already been removed from the list\n");
        #endif
      }
      else {
        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_BOLD_GREEN,
                      " Packet with ID ");

          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      ntohs(blastHeader->identifier));

          do_debug_c( 2,
                      ANSI_COLOR_BOLD_GREEN,
                      " removed from the list\n");
        #endif
      }
    }
    else if((blastHeader->ACK & MASK ) == ACKNEEDED) {
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " Arrived blast packet ID ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(blastHeader->identifier));

        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    ", Length ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    length);

        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " bytes\n");
      #endif

      // if this packet has arrived for the first time, deliver it to the destination
      bool deliverThisPacket=false;

      uint64_t now = GetTimeStamp();

      if(context->blastTimestamps[ntohs(blastHeader->identifier)] == 0) {
        deliverThisPacket=true;
      }
      else {

        if (now - context->blastTimestamps[ntohs(blastHeader->identifier)] < TIME_UNTIL_SENDING_AGAIN_BLAST) {
          // the packet has been sent recently
          // do not send it again
          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_BOLD_GREEN,
                        "The packet with ID %i has been sent recently. Do not send it again\n",
                        ntohs(blastHeader->identifier));

            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        "now (%"PRIu64") - blastTimestamps[%i] (%"PRIu64") < %"PRIu64"\n",
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
                        ANSI_COLOR_BOLD_GREEN,
                        " DEMUXED PACKET with ID ");            
          }
          else {
            // tap mode
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " DEMUXED FRAME with ID ");              
          }

          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      ntohs(blastHeader->identifier));

          if(debug>1) {
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        ":\n");

            dump_packet (length, &buffer_from_net[sizeof(struct simplemuxBlastHeader)]);                    
          }
          else {
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        "\n");
          }
        #endif

        // tun mode
        if(context->tunnelMode == TUN_MODE) {
           // write the demuxed packet to the tun interface
          #ifdef DEBUG
            do_debug_c( 3,
                        ANSI_COLOR_BOLD_GREEN,
                        " %"PRIu64"",
                        now);

            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " Sending packet of ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        length);
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        " bytes to ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%s",
                        context->tun_if_name);
            do_debug_c( 2,
                        ANSI_COLOR_BOLD_GREEN,
                        "\n");
          #endif

          if (cwrite (context->tun_fd,
                      &buffer_from_net[sizeof(struct simplemuxBlastHeader)],
                      length ) != length)
          {
            perror("could not write the packet correctly");
          }
          else {
            #ifdef DEBUG
              do_debug_c( 1,
                          ANSI_COLOR_BOLD_GREEN,
                          "  Packet with ID ");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%i",
                          ntohs(blastHeader->identifier));

              do_debug_c( 1,
                          ANSI_COLOR_BOLD_GREEN,
                          " sent to ");

              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%s\n",
                          context->tun_if_name);

              do_debug_c( 3,
                          ANSI_COLOR_YELLOW,
                          " %"PRIu64" Packet correctly sent to ",
                          now);

              do_debug_c( 3,
                          ANSI_COLOR_RESET,
                          "%s",
                          context->tun_if_name);

              do_debug_c( 3,
                          ANSI_COLOR_YELLOW,
                          "\n",
                          now);
            #endif

            #ifdef LOGFILE
              // write the log file
              if ( context->log_file != NULL ) {
                fprintf ( context->log_file,
                          "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                          GetTimeStamp(),
                          length,
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
                          " Sending frame of ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "%i",
                          length);
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

            if(cwrite ( context->tun_fd, &buffer_from_net[sizeof(struct simplemuxBlastHeader)], length ) != length) {
              perror("could not write the frame correctly");
            }
            else {
              #ifdef DEBUG
                do_debug_c( 1,
                            ANSI_COLOR_YELLOW,
                            " Frame with ID %i sent to ",
                            ntohs(blastHeader->identifier));

                do_debug_c( 1,
                            ANSI_COLOR_RESET,
                            "%s",
                            context->tun_if_name);

                do_debug_c( 1,
                            ANSI_COLOR_YELLOW,
                            "\n");

                do_debug_c( 3,
                            ANSI_COLOR_YELLOW,
                            " %"PRIu64" Frame correctly sent to ",
                            now);

                do_debug_c( 3,
                            ANSI_COLOR_RESET,
                            "%s");

                do_debug_c( 3,
                            ANSI_COLOR_YELLOW,
                            "\n");
              #endif

              #ifdef LOGFILE
                // write the log file
                if ( context->log_file != NULL ) {
                  fprintf ( context->log_file,
                            "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                            GetTimeStamp(),
                            length,
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
        
        #ifdef DEBUG
          //do_debug(2, "\n");
          //do_debug(2, "packet length (without separator): %i\n", packet_length);
        #endif
      }

      // this packet requires an ACK
      #ifdef DEBUG
        do_debug_c( 2,
                    ANSI_COLOR_BOLD_YELLOW,
                    " Sending a blast ACK\n");
      #endif

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
                    "  Sent blast ACK to the network. ID ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(ACK.header.identifier));

        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    ", Length ");

        do_debug_c( 1,
                    ANSI_COLOR_RESET,
                    "%i",
                    ntohs(ACK.header.packetSize));

        do_debug_c( 1,
                    ANSI_COLOR_BOLD_GREEN,
                    " bytes\n");
      #endif

      // no need to add log here because 'sendPacketBlastFlavor()' already does it
    }
    else if((blastHeader->ACK & MASK ) == HEARTBEAT) {
      #ifdef DEBUG
        do_debug_c( 1,
                    ANSI_COLOR_BOLD_YELLOW,
                    " Arrived blast heartbeat\n");
      #endif

      uint64_t now = GetTimeStamp();
      context->lastBlastHeartBeatReceived = now;
    }
    else {
      perror("Unknown blast packet type\n");
    }
  }

  // no blast flavor
  else {
    // if the packet comes from the multiplexing port, I have to demux 
    //it and write each packet to the tun / tap interface
    int position = 0; //this is the index for reading the packet/frame
    int num_demuxed_packets = 0;            // a counter of the number of packets inside a muxed one
    int first_header_read = 0;              // it is 0 when the first header has not been read
    int single_protocol_rec;                // it is the bit Single-Protocol-Bit received in a muxed packet
    int LXT_first_byte;                     // length extension of the first byte
    int maximum_packet_length;              // the maximum length of a packet. It may be 64 (first header) or 128 (non-first header)

    while (position < nread_from_net) {   
      if (context->flavor == 'N') {
        // normal flavor

        // check if this is the first separator or not
        if (first_header_read == 0) {

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
          if  ((0x80 & buffer_from_net[position] ) == 0x80 ) {
            single_protocol_rec = 1;
            //do_debug(2, "single protocol\n");
          }
          else {
            single_protocol_rec = 0;
            //do_debug(2, "multi protocol\n");
          }

          // Read LXT (one bit)
          // as this is a first header
          //  - LXT bit is the second one (0x40) 
          //  - the maximum length of a single-byte packet is 64 bytes                
          if ((0x40 & buffer_from_net[position]) == 0x00)
            LXT_first_byte = 0;
          else
            LXT_first_byte = 1;

          maximum_packet_length = 64;
        }

        else { 
          // this is a non-first header
          //  - There is no SPB bit
          //  - LXT will be stored in the most significant bit (0x80)
          //  - the maximum length of a single-byte packet is 128 bytes
          if ((0x80 & buffer_from_net[position]) == 0x00)
            LXT_first_byte = 0;
          else
            LXT_first_byte = 1;
          
          maximum_packet_length = 128;
        }

        // I have demuxed another packet
        num_demuxed_packets ++;

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
      }
      else {
        // fast flavor
        #ifdef ASSERT
          assert(context->flavor == 'F');
        #endif

        // I have demuxed another packet
        num_demuxed_packets ++;
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
      }


      if (context->flavor == 'N') {
        // normal flavor

        if (LXT_first_byte == 0) {
          // the LXT bit of the first byte is 0 => the separator is one-byte long

          // I have to convert the 6 (or 7) less significant bits to an integer, which means the length of the packet
          // since the two most significant bits are 0, the length is the value of the char
          packet_length = buffer_from_net[position] % maximum_packet_length;
          //packet_length = buffer_from_net[position] & maximum_packet_length;

          #ifdef DEBUG
            if (debug>0) {
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          "  Mux separator of 1 byte: ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "0x%02x",
                          buffer_from_net[position]);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " (");

              bool bits[8];   // used for printing the bits of a byte in debug mode
              FromByte(buffer_from_net[position], bits);
              PrintByte(2, 8, bits);
              do_debug_c(2, ANSI_COLOR_GREEN, ")");
            }
          #endif
          position ++;
        }

        else {
          // the LXT bit of the first byte is 1 => the separator is NOT one-byte

          // check whether this is a 2-byte or a 3-byte length
          // check the bit 7 of the second byte

          // If the LXT bit is 0, this is a two-byte length
          if ((0x80 & buffer_from_net[position+1] ) == 0x00 ) {

            // I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
            // I do the product by 128, because the next byte includes 7 bits of the length
            packet_length = ((buffer_from_net[position] % maximum_packet_length) * 128 );
            #ifdef DEBUG
              do_debug_c( 3,
                          ANSI_COLOR_GREEN,
                          "initial packet_length (only most significant bits): ");
              do_debug_c( 3,
                          ANSI_COLOR_RESET,
                          "%d, ",
                          packet_length);
            #endif
            /*
            uint8_t mask;
            if (maximum_packet_length == 64)
              mask = 0x3F;
            else
              mask = 0x7F;
            packet_length = ((buffer_from_net[position] & maximum_packet_length) << 7 );*/

            // I add the value of the 7 less significant bits of the second byte
            packet_length = packet_length + (buffer_from_net[position + 1] % 128);
            #ifdef DEBUG
              do_debug_c( 3,
                          ANSI_COLOR_GREEN,
                          "packet_length (all the bits): ");
              do_debug_c( 3,
                          ANSI_COLOR_RESET,
                          "%d\n",
                          packet_length);
            #endif
            //packet_length = packet_length + (buffer_from_net[position+1] & 0x7F);

            #ifdef DEBUG
            if (debug>0) {
              bool bits[8];   // used for printing the bits of a byte in debug mode

              // print the first byte
              FromByte(buffer_from_net[position], bits);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          "  Mux separator of 2 bytes: ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "0x%02x",
                          buffer_from_net[position]);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " (");
              PrintByte(2, 8, bits);
              
              // print the second byte
              FromByte(buffer_from_net[position+1], bits);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          ") ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "0x%02x",
                          buffer_from_net[position+1]);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " (");
              PrintByte(2, 8, bits);
              do_debug_c(2, ANSI_COLOR_GREEN, ")");
            }
            #endif

            position = position + 2;
          }

          // If the LXT bit of the second byte is 1, this is a three-byte length
          else {
            // I get the 6 (or 7) less significant bits of the first byte by using modulo maximum_packet_length
            // I do the product by 16384 (2^14), because the next two bytes include 14 bits of the length
            //packet_length = ((buffer_from_net[position] % maximum_packet_length) * 16384 );
            packet_length = ((buffer_from_net[position] % maximum_packet_length) << 14 );

            // I get the 6 (or 7) less significant bits of the second byte by using modulo 128
            // I do the product by 128, because the next byte includes 7 bits of the length
            //packet_length = packet_length + ((buffer_from_net[position+1] % 128) * 128 );
            packet_length = packet_length + ((buffer_from_net[position+1] & 0x7F) << 7 );

            // I add the value of the 7 less significant bits of the second byte
            //packet_length = packet_length + (buffer_from_net[position+2] % 128);
            packet_length = packet_length + (buffer_from_net[position+2] & 0x7F);

            #ifdef DEBUG
            if (debug>0) {
              bool bits[8];   // used for printing the bits of a byte in debug mode

              // print the first byte
              FromByte(buffer_from_net[position], bits);
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          "  Mux separator of 2 bytes: ");
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          "0x%02x ",
                          buffer_from_net[position]);
              PrintByte(2, 8, bits);
              
              // print the second byte
              FromByte(buffer_from_net[position+1], bits);
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          " %02x ",
                          buffer_from_net[position+1]);
              PrintByte(2, 8, bits);  
              
              // print the third byte
              FromByte(buffer_from_net[position+2], bits);
              do_debug_c( 2,
                          ANSI_COLOR_RESET,
                          " %02x ",
                          buffer_from_net[position+2]);
              PrintByte(2, 8, bits);
            }
            #endif

            position = position + 3;
          }
        }

        // read the 'Protocol'

        // check if this is the first separator or not
        if (first_header_read == 0) {    // this is the first separator. The protocol field will always be present
          // the next thing I expect is a 'protocol' field
          context->protocol_rec = buffer_from_net[position];
          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        ". Protocol ");
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "0x%02x",
                        buffer_from_net[position]);

            if(context->protocol_rec == IPPROTO_IP_ON_IP)
              do_debug_c(1, ANSI_COLOR_RESET, " (IP)");
            else if(context->protocol_rec == IPPROTO_ROHC)
              do_debug_c(1, ANSI_COLOR_RESET, " (RoHC)");
            else if(context->protocol_rec == IPPROTO_ETHERNET)
              do_debug_c(1, ANSI_COLOR_RESET, " (Ethernet)");
          #endif
          position ++;

          // if I am here, it means that I have read the first separator
          first_header_read = 1;
        }
        else {      // non-first separator. The protocol field may or may not be present
          if ( single_protocol_rec == 0 ) {
            // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
            context->protocol_rec = buffer_from_net[position];
            if(single_protocol_rec == 0) {
              #ifdef DEBUG
                do_debug_c( 1,
                            ANSI_COLOR_GREEN,
                            ". Protocol ");
                do_debug_c( 1,
                            ANSI_COLOR_RESET,
                            "0x%02x",
                            buffer_from_net[position]);
                
                if(context->protocol_rec == IPPROTO_IP_ON_IP)
                  do_debug_c(1, ANSI_COLOR_RESET, " (IP)");
                else if(context->protocol_rec == IPPROTO_ROHC)
                  do_debug_c(1, ANSI_COLOR_RESET, " (RoHC)");
                else if(context->protocol_rec == IPPROTO_ETHERNET)
                  do_debug_c(1, ANSI_COLOR_RESET, " (Ethernet)");
              #endif
            }
            position ++;
          }
        }
        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_GREEN,
                      ". Length ");
          do_debug_c( 1,
                      ANSI_COLOR_RESET,
                      "%i",
                      packet_length);
          do_debug_c( 1,
                      ANSI_COLOR_GREEN,
                      " bytes\n");
        #endif
      }

      else {
        // fast flavor
        #ifdef ASSERT
          assert(context->flavor == 'F');
        #endif

        if ((context->mode == TCP_SERVER_MODE) || (context->mode == TCP_CLIENT_MODE)) {
          // do nothing, because I have already read the length
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        " Length ");
            do_debug_c( 2,
                        ANSI_COLOR_RESET,
                        "%i",
                        packet_length);
            do_debug_c( 2,
                        ANSI_COLOR_YELLOW,
                        " bytes.\n");
          #endif

          // do nothing, because I have already read the Protocol
        }
        else {
          // I am in fast mode, but not in TCP mode, so I still have to read the length
          // It is in the two first bytes of the buffer
          //do_debug(0,"buffer_from_net[position] << 8: 0x%02x  buffer_from_net[position+1]: 0x%02x\n", buffer_from_net[position] << 8, buffer_from_net[position+1]);

          // apply the structure of a fast mode packet
          struct simplemuxFastHeader* fastHeader = (struct simplemuxFastHeader*) (&buffer_from_net[position]);
          packet_length = ntohs(fastHeader->packetSize);
          //packet_length = (buffer_from_net[position] << 8 ) + buffer_from_net[position+1];

          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_YELLOW,
                        " Length ");
            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "%i",
                        packet_length);
            do_debug_c( 1,
                        ANSI_COLOR_YELLOW,
                        " bytes. ");
          #endif

          // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
          context->protocol_rec = fastHeader->protocolID;

          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_GREEN,
                        "Protocol ");

            do_debug_c( 1,
                        ANSI_COLOR_RESET,
                        "0x%02x",
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
          position = position + sizeof(struct simplemuxFastHeader);
        }
      }

      // copy the packet to a new string 'demuxed_packet'
      uint8_t demuxed_packet[BUFSIZE];          // stores each demultiplexed packet

      memcpy (demuxed_packet, &buffer_from_net[position], packet_length);
      position = position + packet_length;

      // Check if the position has gone beyond the size of the packet (wrong packet)
      if (position > nread_from_net) {
        // The last length read from the separator goes beyond the end of the packet

        #ifdef DEBUG
          do_debug_c( 1,
                      ANSI_COLOR_RED,
                      "  ERROR: The length of the packet does not fit. Packet discarded\n");
        #endif

        // this means that reception is desynchronized
        // in TCP mode, this will never recover, so abort
        if ((context->mode == TCP_CLIENT_MODE) || (context->mode == TCP_CLIENT_MODE)) {
          #ifdef DEBUG
            do_debug_c( 1,
                        ANSI_COLOR_RED,
                        "ERROR: Length problem in TCP mode. Abort\n");
          #endif

          return -1;
        }

        #ifdef LOGFILE
          // write the log file
          if ( context->log_file != NULL ) {
            // the packet is bad so I add a line
            fprintf ( context->log_file,
                      "%"PRIu64"\terror\tdemux_bad_length\t%i\t%"PRIu32"\n",
                      GetTimeStamp(),
                      nread_from_net,
                      context->net2tun );  
            
            fflush(context->log_file);
          }
        #endif     
      }
      
      else {

        /************ decompress the packet if needed ***************/

        // if the number of the protocol is NOT 142 (ROHC) I do not decompress the packet
        if ( context->protocol_rec != IPPROTO_ROHC ) {
          // non-compressed packet
            #ifdef DEBUG
            // dump the received packet on terminal
            if (debug>0) {
              //do_debug_c(1, ANSI_COLOR_RESET, " Received ");
              //do_debug(2, "   ");
              dump_packet ( packet_length, demuxed_packet );
            }
          #endif
        }
        else {
          // ROHC-compressed packet

          // I cannot decompress the packet if I am not in ROHC mode
          if ( context->rohcMode == 0 ) {
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
                          packet_length,
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
            rohc_packet_d.len = packet_length;
      
            // Copy the packet itself
            for (int l = 0; l < packet_length ; l++) {
              rohc_buf_byte_at(rohc_packet_d, l) = demuxed_packet[l];
            }
            // I try to use memcpy instead, but it does not work properly
            // memcpy(demuxed_packet, rohc_buf_data_at(rohc_packet_d, 0), packet_length);

            #ifdef DEBUG
              // dump the ROHC packet on terminal
              if (debug > 1)
                dump_packet (packet_length, demuxed_packet);
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
                              "Feedback received from the remote compressor by the decompressor (");
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
                  }
                #endif

                // deliver the feedback received to the local compressor
                //https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
                if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
                  #ifdef DEBUG
                    do_debug_c( 3,
                                ANSI_COLOR_RED,
                                "Error delivering feedback received from the remote compressor to the compressor\n");
                  #endif
                }
                else {
                  #ifdef DEBUG
                    do_debug_c( 3,
                                ANSI_COLOR_MAGENTA,
                                "Feedback from the remote compressor delivered to the compressor: ");
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
                #ifdef DEBUG
                  do_debug_c( 3,
                              ANSI_COLOR_RED,
                              "No feedback received by the decompressor from the remote compressor\n");
                #endif
              }

              // check if the decompressor has generated feedback to be sent by the feedback channel to the other peer
              if ( !rohc_buf_is_empty( feedback_send ) ) {
                #ifdef DEBUG
                  do_debug_c( 3,
                              ANSI_COLOR_MAGENTA,
                              "Generated feedback (");
                  do_debug_c( 3,
                              ANSI_COLOR_RESET,
                              "%i",
                              feedback_send.len);
                  do_debug_c( 3,
                              ANSI_COLOR_MAGENTA,
                              " bytes) to be sent by the feedback channel to the peer\n");

                  // dump the ROHC packet on terminal
                  if (debug>0) {
                    do_debug_c( 2,
                                ANSI_COLOR_MAGENTA,
                                "  ROHC feedback packet generated\n");

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
                  perror("sendto() failed when sending a ROHC packet");
                }
                else {
                  #ifdef DEBUG
                    do_debug_c( 3,
                                ANSI_COLOR_MAGENTA,
                                "Feedback generated by the decompressor (");
                    do_debug_c( 3,
                                ANSI_COLOR_RESET,
                                "%i",
                                feedback_send.len);
                    do_debug_c( 3,
                                ANSI_COLOR_MAGENTA,
                                " bytes), sent to the compressor\n");
                  #endif
                }
              }
              else {
                #ifdef DEBUG
                  do_debug_c( 3,
                              ANSI_COLOR_MAGENTA,
                              "No feedback generated by the decompressor\n");
                #endif
              }
            }

            // check the result of the decompression

            // decompression is successful
            if ( *status == ROHC_STATUS_OK) {

              if(!rohc_buf_is_empty(ip_packet_d))  {  // decompressed packet is not empty
          
                // ip_packet.len bytes of decompressed IP data available in ip_packet
                packet_length = ip_packet_d.len;

                // copy the packet
                memcpy(demuxed_packet, rohc_buf_data_at(ip_packet_d, 0), packet_length);

                #ifdef DEBUG
                  //dump the IP packet on the standard output
                  do_debug_c( 1,
                              ANSI_COLOR_MAGENTA,
                              "  IP packet resulting from the ROHC decompression: ",
                              packet_length);
                  do_debug_c( 1,
                              ANSI_COLOR_RESET,
                              "%i",
                              packet_length);
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
                /* no IP packet was decompressed because of ROHC segmentation or
                 * feedback-only packet:
                 *  - the ROHC packet was a non-final segment, so at least another
                 *    ROHC segment is required to be able to decompress the full
                 *    ROHC packet
                 *  - the ROHC packet was a feedback-only packet, it contained only
                 *    feedback information, so there was nothing to decompress */
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
        }
        /*********** end decompression **************/

        // write the demuxed (and perhaps decompressed) packet to the tun interface
        // if compression is used, check that ROHC has decompressed correctly
        if ( ( context->protocol_rec != IPPROTO_ROHC ) || ((context->protocol_rec == IPPROTO_ROHC) && ( *status == ROHC_STATUS_OK))) {

          // tun mode
          if(context->tunnelMode == TUN_MODE) {
             // write the demuxed packet to the tun interface
            #ifdef DEBUG
              do_debug_c( 1,
                          ANSI_COLOR_YELLOW,
                          " Sending packet of ");
              do_debug_c( 1,
                          ANSI_COLOR_RESET,
                          "%i",
                          packet_length);
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

            cwrite ( context->tun_fd, demuxed_packet, packet_length );
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
                            " Sending frame of ");
                do_debug_c( 1,
                            ANSI_COLOR_RESET,
                            "%i",
                            packet_length);
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

              cwrite ( context->tun_fd, demuxed_packet, packet_length );
            }
          }
          else {
            perror ("wrong value of 'tunnelMode'");
            exit (EXIT_FAILURE);
          }
          
          #ifdef DEBUG
            do_debug(2, "\n");
            //do_debug(2, "packet length (without separator): %i\n", packet_length);
          #endif

          #ifdef LOGFILE
            // write the log file
            if ( context->log_file != NULL ) {
              fprintf ( context->log_file,
                        "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n",
                        GetTimeStamp(),
                        packet_length,
                        context->net2tun);  // the packet is good
              
              fflush(context->log_file);
            }
          #endif
        }
      }
    }              
  }
  return 1;
}