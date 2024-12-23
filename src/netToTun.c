#include "netToTun.h"

/* Reads a multiplexed packet from the network
 * it returns:
 * 1  a multiplexed packet has been read from the network
 * 0  a correct but not multiplexed packet has been read from the network
 * -1 error. Incorrect read
 */
int readPacketFromNet(contextSimplemux* context,
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
                    "Read %i bytes from the UDP socket\n",
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
                    ANSI_COLOR_YELLOW,
                    "Read ");
        do_debug_c( 3,
                    ANSI_COLOR_RESET,
                    "%i",
                    *nread_from_net);
        do_debug_c( 3,
                    ANSI_COLOR_YELLOW,
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
                    ANSI_COLOR_YELLOW,
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
                    ANSI_COLOR_YELLOW,
                    "   ");
        do_debug_c (3,
                    ANSI_COLOR_RESET,
                    "%i",
                    *nread_from_net);
        do_debug_c (3,
                    ANSI_COLOR_YELLOW,
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
                      ANSI_COLOR_YELLOW,
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
                      ANSI_COLOR_YELLOW,
                      " (the complete separator has ");
          do_debug_c( 3,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->sizeSeparatorFastMode);
          do_debug_c( 3,
                      ANSI_COLOR_YELLOW,
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
                      ANSI_COLOR_YELLOW,
                      "Read Fast separator from the TCP socket: Length ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->length_muxed_packet);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      " (");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x%02x",
                      buffer_from_net[0],
                      buffer_from_net[1]);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      ")");
        #endif

        // read the Protocol field
        context->protocol_rec = buffer_from_net[2];
        #ifdef DEBUG
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      ". Protocol ");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "%i",
                      context->protocol_rec);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
                      " (");
          do_debug_c( 2,
                      ANSI_COLOR_RESET,
                      "0x%02x",
                      buffer_from_net[2]);
          do_debug_c( 2,
                      ANSI_COLOR_YELLOW,
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

// demux and decompress a Simplemux bundle and extract each of the
//packets/frames it contains
// returns 1 if everything is correct
//        -1 otherwise
#ifdef USINGROHC
int demuxBundleFromNet( contextSimplemux* context,
                        int nread_from_net,
                        uint16_t bundleLength,
                        uint8_t* buffer_from_net,
                        rohc_status_t* status)
#else
int demuxBundleFromNet( contextSimplemux* context,
                        int nread_from_net,
                        uint16_t bundleLength,
                        uint8_t* buffer_from_net)
#endif
{
  // increase the counter of the number of packets read from the network
  (context->net2tun)++;

  #ifdef DEBUG
    showDebugInfoFromNet(context, nread_from_net);
  #endif

  #ifdef LOGFILE
    logInfoFromNet(context, nread_from_net, buffer_from_net);
  #endif

  // 'blast' flavor
  if(context->flavor == 'B') {
    demuxPacketBlast(context, nread_from_net, buffer_from_net);
  }

  // no blast flavor (i.e. 'normal' or 'fast')
  else {
    // if the packet comes from the multiplexing port, I have to demux 
    //it and write the packets/frames it contains, to the tun / tap interface

    int position = 0;               // the index for reading the packet/frame
    int num_demuxed_packets = 0;    // a counter of the number of packets inside a muxed one
    int first_header_read = 0;      // it is 0 when the first header has not been read
    int single_protocol_rec;        // it is the bit Single-Protocol-Bit received in a muxed packet
    int LXT_first_byte;             // length extension of the first byte
    int maximum_packet_length;      // the maximum length of a packet. It may be 64 (first header) or 128 (non-first header)

    while (position < nread_from_net) {
      num_demuxed_packets ++;   // I have demuxed another packet
      int demuxedPacketLength;  // to store the length of the packet/frame extracted from the bundle

      if (context->flavor == 'N') {
        // normal flavor
        demuxedPacketLength = demuxPacketNormal(context,
                                                buffer_from_net,
                                                &position,
                                                num_demuxed_packets,
                                                &first_header_read,
                                                &single_protocol_rec,
                                                &LXT_first_byte,
                                                &maximum_packet_length);
      }
      else {
        // fast flavor
        #ifdef ASSERT
          assert(context->flavor == 'F');
        #endif

        demuxedPacketLength = demuxPacketFast(context,
                                              bundleLength,
                                              buffer_from_net,
                                              &position,
                                              num_demuxed_packets);

        if((context->mode == TCP_SERVER_MODE) || (context->mode == TCP_CLIENT_MODE) ) {
          // for TCP, demuxedPacketLength will return 0
          // in this case, the length of the bundle is
          //the same as the length of the demuxed packet
          //because it is seen as a continuous flow of bytes      
          demuxedPacketLength = bundleLength;   
        }
      }

      // this part is used by both Normal and Fast flavors

      #ifdef ASSERT
        // ensure that there is space to copy the packet
        assert(demuxedPacketLength <= BUFSIZE);
      #endif

      // copy the demultiplexed packet to a new string 'demuxed_packet'
      uint8_t demuxed_packet[BUFSIZE];
      memcpy (demuxed_packet, &buffer_from_net[position], demuxedPacketLength);

      // at this point, I have extracted one packet/frame from the arrived muxed one
      // the demuxed packet is in 'demuxed_packet'

      // move the pointer
      position = position + demuxedPacketLength;

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

        // check if the demuxed packet/frame has to be decompressed

        // set to 0 if this demuxed packet/frame has to be dropped
        int sendPacket = 1;

        #ifdef USINGROHC
          // if the number of the protocol is NOT 142 (RoHC) I do not decompress the packet
          if ( context->protocol_rec != IPPROTO_ROHC ) {
            // This packet/frame can be sent
            sendPacket = 1;

            // non-compressed packet
            #ifdef DEBUG
              // the length and the protocol of this packet have already been shown in the debug info
              // dump the received packet on terminal
              dump_packet ( demuxedPacketLength, demuxed_packet );
            #endif
          }
          else {
            // the demuxed packet is a RoHC-compressed packet. Decompress it
            sendPacket = decompressRohcPacket(context,
                                              demuxed_packet,
                                              &demuxedPacketLength,
                                              status,
                                              nread_from_net);
          }
        #endif

        if (sendPacket) {
          // write the demuxed (and perhaps decompressed) packet/frame to the tun/tap interface
          sendPacketToTun(context, demuxed_packet, demuxedPacketLength);
        }
        else {
          // the packet has to be dropped. Do nothing
          #ifdef DEBUG
            if (context->tunnelMode == TUN_MODE)
              do_debug_c( 2,
                          ANSI_COLOR_RED,
                          " The demuxed packet has been dropped\n\n");
            else
              do_debug_c( 2,
                          ANSI_COLOR_RED,
                          " The demuxed frame has been dropped\n\n");              
          #endif
        }
      }
    }              
  }
  return 1;
}