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
                      socklen_t slen,
                      //uint16_t port,
                      struct iphdr ipheader,
                      //uint8_t ipprotocol,
                      uint8_t* protocol_rec,
                      int* nread_from_net,
                      uint16_t* packet_length,
                      uint16_t* pending_bytes_muxed_packet,
                      int size_separator_fast_mode,
                      uint8_t* read_tcp_bytes_separator,
                      uint16_t* read_tcp_bytes )

{
  int is_multiplexed_packet = -1;
  uint8_t buffer_from_net_aux[BUFSIZE];

  if (context->mode == UDP_MODE) {
    // a packet has been received from the network, destined to the multiplexing port
    // 'slen' is the length of the IP address
    // I cannot use 'remote' because it would replace the IP address and port. I use 'received'

    *nread_from_net = recvfrom ( context->udp_mode_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&(context->received), &slen );
    if (*nread_from_net==-1) {
      perror ("[readPacketFromNet] recvfrom() UDP error");
    }
    else {
      do_debug(3, "[readPacketFromNet] Read %i bytes from the UDP socket\n");
    }
    // now buffer_from_net contains the payload (simplemux headers and multiplexled packets/frames) of a full packet or frame.
    // I don't have the IP and UDP headers

    // check if the packet comes from the multiplexing port (default 55555). (Its destination IS the multiplexing port)
    if (context->port == ntohs(context->received.sin_port)) 
      is_multiplexed_packet = 1;
    else
      is_multiplexed_packet = 0;
  }

  else if (context->mode  == NETWORK_MODE) {
    // a packet has been received from the network, destined to the local interface for muxed packets
    *nread_from_net = cread ( context->network_mode_fd, buffer_from_net_aux, BUFSIZE);

    if (*nread_from_net==-1) {
      perror ("[readPacketFromNet] cread error in network mode");
    }
    else {
      do_debug(3, "[readPacketFromNet] Read %i bytes from the network socket\n");
    }    
    // now buffer_from_net contains the headers (IP and Simplemux) and the payload of a full packet or frame.

    // copy from "buffer_from_net_aux" everything except the IP header (usually the first 20 bytes)
    memcpy ( buffer_from_net, buffer_from_net_aux + sizeof(struct iphdr), *nread_from_net - sizeof(struct iphdr));
    // correct the size of "nread from net"
    *nread_from_net = *nread_from_net - sizeof(struct iphdr);

    // Get IP Header of received packet
    GetIpHeader(&ipheader,buffer_from_net_aux);
    if (ipheader.protocol == context->ipprotocol )
      is_multiplexed_packet = 1;
    else
      is_multiplexed_packet = 0;
  }

  else if ((context->mode  == TCP_SERVER_MODE) || (context->mode  == TCP_CLIENT_MODE)) {

    // some bytes have been received from the network, destined to the TCP socket
    
    /* Once the sockets are connected, the client can read it
     * through a normal 'read' call on the socket descriptor.
     * Read 'buffer_from_net' bytes
     * This call returns up to N bytes of data. If there are fewer 
     *bytes available than requested, the call returns the number currently available.
     */
    //*nread_from_net = read(context->tcp_server_fd, buffer_from_net, sizeof(buffer_from_net));
    
    // I only read one packet (at most) each time the program goes through this part

    if (*pending_bytes_muxed_packet == 0) {
      // I have to start reading a new muxed packet: separator and payload
      do_debug(3, "[readPacketFromNet] Reading TCP. No pending bytes of the muxed packet. Start reading a new separator\n");

      // read a separator (3 or 4 bytes), or a part of it
      if (context->mode  == TCP_SERVER_MODE) {
        *nread_from_net = read(context->tcp_server_fd, buffer_from_net, size_separator_fast_mode - *read_tcp_bytes_separator);
      }
      else {
        *nread_from_net = read(context->tcp_client_fd, buffer_from_net, size_separator_fast_mode - *read_tcp_bytes_separator);
      }
      do_debug(3, "[readPacketFromNet]  %i bytes of the separator read from the TCP socket", *nread_from_net);

      if(*nread_from_net < 0)  {
        perror("[readPacketFromNet] read() error TCP mode");
      }

      else if(*nread_from_net == 0) {
        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if (*nread_from_net < size_separator_fast_mode - *read_tcp_bytes_separator) {
        do_debug(3, "[readPacketFromNet] (part of the separator. Still %i bytes missing)\n", size_separator_fast_mode - *read_tcp_bytes_separator - *nread_from_net);
        // I have read part of the separator
        *read_tcp_bytes_separator = *read_tcp_bytes_separator + *nread_from_net;

        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if(*nread_from_net == size_separator_fast_mode - *read_tcp_bytes_separator) {
        do_debug(3, "[readPacketFromNet] (the complete separator of %i bytes)\n", size_separator_fast_mode);
        // I have read the complete separator

        // I can now obtain the length of the packet
        // the first byte is the Most Significant Byte of the length
        // the second byte is the Less Significant Byte of the length
        context->length_muxed_packet = (buffer_from_net[0] << 8)  + buffer_from_net[1];
        *pending_bytes_muxed_packet = context->length_muxed_packet;

        do_debug(2, " Read separator: Length %i (0x%02x%02x)", context->length_muxed_packet, buffer_from_net[0], buffer_from_net[1]);

        // read the Protocol field
        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          *protocol_rec = buffer_from_net[2];
          do_debug(2, ". Protocol %i (0x%02x)\n", *protocol_rec, buffer_from_net[2]);
        }
        else {  // SIZE_PROTOCOL_FIELD == 2
          *protocol_rec = (buffer_from_net[2] << 8) + buffer_from_net[3];
          do_debug(2, ". Protocol %i (0x%02x%02x)\n", *protocol_rec, buffer_from_net[2], buffer_from_net[3]);
        }

        // read the packet itself (without the separator)
        // I only read the length of the packet
        if (context->mode  == TCP_SERVER_MODE) {
          *nread_from_net = read(context->tcp_server_fd, buffer_from_net, *pending_bytes_muxed_packet);
        }
        else {
          *nread_from_net = read(context->tcp_client_fd, buffer_from_net, *pending_bytes_muxed_packet);
        }
        do_debug(3, "[readPacketFromNet]  %i bytes of the muxed packet read from the TCP socket", *nread_from_net);

        if(*nread_from_net < 0)  {
          perror("[readPacketFromNet] read() error TCP server mode");
        }

        else if (*nread_from_net < *pending_bytes_muxed_packet) {
          do_debug(3, "  (part of a muxed packet). Pending %i bytes\n", *pending_bytes_muxed_packet - *nread_from_net);
          // I have not read the whole packet
          // next time I will have to keep on reading
          *pending_bytes_muxed_packet = *pending_bytes_muxed_packet - *nread_from_net;
          *read_tcp_bytes = *read_tcp_bytes + *nread_from_net;

          //do_debug(2,"Read %d bytes from the TCP socket. Total %d\n", *nread_from_net, *read_tcp_bytes); 
          // I have not finished reading a muxed packet
          is_multiplexed_packet = -1;
        }
        else if (*nread_from_net == *pending_bytes_muxed_packet) {
          // I have read a complete packet
          *packet_length = *read_tcp_bytes + *nread_from_net;
          do_debug(3, " (complete muxed packet of %i bytes)\n", packet_length);

          // reset the variables
          *read_tcp_bytes_separator = 0;
          *pending_bytes_muxed_packet = 0;
          *read_tcp_bytes = 0;

          // I have finished reading a muxed packet
          is_multiplexed_packet = 1;
        }
      }              
    }
    else { // *pending_bytes_muxed_packet > 0
      // I have to finish reading the TCP payload
      // I try to read 'pending_bytes_muxed_packet' and to put them at position '*read_tcp_bytes'
      do_debug(3, "[readPacketFromNet] Reading TCP. %i TCP bytes pending of the previous payload\n", *pending_bytes_muxed_packet);

      if (context->mode  == TCP_SERVER_MODE) {
        *nread_from_net = read(context->tcp_server_fd, &(buffer_from_net[(*read_tcp_bytes)]), *pending_bytes_muxed_packet);
      }
      else {
        *nread_from_net = read(context->tcp_client_fd, &(buffer_from_net[(*read_tcp_bytes)]), *pending_bytes_muxed_packet);
      }
      do_debug(3, "[readPacketFromNet]  %i bytes read from the TCP socket ", *nread_from_net);

      if(*nread_from_net < 0)  {
        perror("[readPacketFromNet] read() error TCP mode");
      }

      else if(*nread_from_net == 0) {
        do_debug(3, "[readPacketFromNet] (I have read 0 bytes)\n");
        is_multiplexed_packet = -1;
      }

      else if(*nread_from_net < *pending_bytes_muxed_packet) {
        do_debug(3, "[readPacketFromNet] (I have not yet read the whole muxed packet: pending %i bytes)\n", context->length_muxed_packet - *nread_from_net);
        // I have not read the whole packet
        // next time I will have to keep on reading
        *pending_bytes_muxed_packet = context->length_muxed_packet - *nread_from_net;
        *read_tcp_bytes = *read_tcp_bytes + *nread_from_net;

        //do_debug(2,"Read %d bytes from the TCP socket. Accum %d. Pending %d\n", *nread_from_net, *read_tcp_bytes, *pending_bytes_muxed_packet);

        // I have not finishing read the pending bytes of this packet
        is_multiplexed_packet = -1;
      }
      else if(*nread_from_net == *pending_bytes_muxed_packet) {
        do_debug(3, "[readPacketFromNet]  I have read all the pending bytes (%i) of this muxed packet. Total %i bytes\n", *nread_from_net, context->length_muxed_packet);
        // I have read the pending bytes of this packet
        *pending_bytes_muxed_packet = 0;
        //*read_tcp_bytes = *read_tcp_bytes + *nread_from_net;

        *nread_from_net = *read_tcp_bytes + *nread_from_net;

        // reset the variables
        *read_tcp_bytes_separator = 0;
        *read_tcp_bytes = 0;
        is_multiplexed_packet = 1;
      }
      
      else /*if(*nread_from_net > *pending_bytes_muxed_packet) */ {
        do_debug(1, "ERROR: I have read all the pending bytes (%i) of this muxed packet, and some more. Abort\n", *pending_bytes_muxed_packet, *nread_from_net - *pending_bytes_muxed_packet);
        // I have read the pending bytes of this packet, plus some more bytes
        // it doesn't make sense, because I have only read '*pending_bytes_muxed_packet'
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
                        FILE *log_file,
                        uint8_t* buffer_from_net,
                        uint8_t* protocol_rec,
                        rohc_status_t* status,
                        int debug )
{
  /* increase the counter of the number of packets read from the network */
  (context->net2tun)++;
  switch (context->mode) {
    case UDP_MODE:
      do_debug(1, "SIMPLEMUX PACKET #%"PRIu32" arrived: Read UDP muxed packet from %s:%d: %i bytes\n", context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port), nread_from_net + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );        

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
      }
    break;

    case TCP_CLIENT_MODE:
      do_debug(1, "SIMPLEMUX PACKET #%"PRIu32" arrived: Read TCP info from %s:%d: %i bytes\n", context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port), nread_from_net );        

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
      }
    break;

    case TCP_SERVER_MODE:
      do_debug(1, "SIMPLEMUX PACKET #%"PRIu32" arrived: Read TCP info from %s:%d: %i bytes\n", context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port), nread_from_net );        

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
      }
    break;

    case NETWORK_MODE:
      do_debug(1, "SIMPLEMUX PACKET #%"PRIu32" arrived: Read IP muxed packet from %s: %i bytes\n", context->net2tun, inet_ntoa(context->remote.sin_addr), nread_from_net + IPv4_HEADER_SIZE );        

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\trec\tmuxed\t%i\t%"PRIu32"\tfrom\t%s\t\n", GetTimeStamp(), nread_from_net  + IPv4_HEADER_SIZE, context->net2tun, inet_ntoa(context->remote.sin_addr));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing Ctrl+C.
      }
    break;
  }

  if(debug>0) {
    uint64_t now = GetTimeStamp();
    do_debug(3, "%"PRIu64" Packet arrived from the network\n",now);         
  }

  if(context->flavor == 'B') {
    // there should be a single packet

    // apply the structure of a blast mode packet
    struct simplemuxBlastHeader* blastHeader = (struct simplemuxBlastHeader*) (buffer_from_net);

    int length = ntohs(blastHeader->packetSize);

    if (length > BUFSIZE) {
      perror("Problem with the length of the received packet\n");
      do_debug(1," Length is %i, but the maximum allowed size is %i\n", length, BUFSIZE);
    }

    // check if this is an ACK or not
    if((blastHeader->ACK & MASK ) == THISISANACK) {

      do_debug(1," Arrived blast ACK packet ID %i\n", ntohs(blastHeader->identifier));

      // an ACK has arrived. The corresponding packet can be removed from the list of pending packets
      do_debug(2," Removing packet with ID %i from the list\n", ntohs(blastHeader->identifier));
      if(debug>2)
        printList(&context->unconfirmedPacketsBlast);
      if(delete(&context->unconfirmedPacketsBlast,ntohs(blastHeader->identifier))==false) {
        do_debug(2,"The packet had already been removed from the list\n");
      }
      else {
        do_debug(2," Packet with ID %i removed from the list\n", ntohs(blastHeader->identifier));
      }
    }
    else if((blastHeader->ACK & MASK ) == ACKNEEDED) {

      do_debug(1," Arrived blast packet ID %i, Length %i\n", ntohs(blastHeader->identifier), length);

      // if this packet has arrived for the first time, deliver it to the destination
      bool deliverThisPacket=false;

      uint64_t now = GetTimeStamp();

      if(context->blastTimestamps[ntohs(blastHeader->identifier)] == 0){
        deliverThisPacket=true;
      }
      else {

        if (now - context->blastTimestamps[ntohs(blastHeader->identifier)] < TIME_UNTIL_SENDING_AGAIN_BLAST) {
          // the packet has been sent recently
          // do not send it again
          do_debug(1,"The packet with ID %i has been sent recently. Do not send it again\n", ntohs(blastHeader->identifier));
          do_debug(2,"now (%"PRIu64") - blastTimestamps[%i] (%"PRIu64") < %"PRIu64"\n",
                    now,
                    ntohs(blastHeader->identifier),
                    context->blastTimestamps[ntohs(blastHeader->identifier)],
                    TIME_UNTIL_SENDING_AGAIN_BLAST);
        }
        else {
          deliverThisPacket=true;
        }
      }

      if(deliverThisPacket) {

        do_debug(2, " DEMUXED PACKET: ID %i", ntohs(blastHeader->identifier));
        if(debug>1) {
          do_debug(2, ":");
          dump_packet (length, &buffer_from_net[sizeof(struct simplemuxBlastHeader)]);                    
        }
        else {
          do_debug(2, "\n");
        }
        
        // tun mode
        if(context->tunnelMode == TUN_MODE) {
           // write the demuxed packet to the tun interface
          do_debug (2, "%"PRIu64" Sending packet of %i bytes to the tun interface\n", now, length);
          if (cwrite ( context->tun_fd, &buffer_from_net[sizeof(struct simplemuxBlastHeader)], length ) != length) {
            perror("could not write the packet correctly");
          }
          else {
            do_debug(1, " Packet with ID %i sent to the tun interface\n", ntohs(blastHeader->identifier));
            do_debug(2, "%"PRIu64" Packet correctly sent to the tun interface\n", now);
          }

          // update the timestamp when a packet with this identifier has been sent
          uint64_t now = GetTimeStamp();
          context->blastTimestamps[ntohs(blastHeader->identifier)] = now;
        }
        // tap mode
        else if(context->tunnelMode == TAP_MODE) {
          if (blastHeader->protocolID != IPPROTO_ETHERNET) {
            do_debug (2, "wrong value of 'Protocol' field received. It should be 143, but it is %i", blastHeader->protocolID);              
          }
          else {
             // write the demuxed packet to the tap interface
            do_debug (2, " Sending frame of %i bytes to the tap interface\n", length);
            if(cwrite ( context->tun_fd, &buffer_from_net[sizeof(struct simplemuxBlastHeader)], length ) != length) {
              perror("could not write the packet correctly");
            }
            else {
              do_debug(1, " Packet with ID %i sent to the tun interface", ntohs(blastHeader->identifier));
              do_debug(2, "%"PRIu64" Packet correctly sent to the tun interface\n", now);
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
        
        do_debug(2, "\n");
        //do_debug(2, "packet length (without separator): %i\n", packet_length);
      }

      do_debug(2," Sending a blast ACK\n");
      // this packet requires an ACK
      // send the ACK as soon as the packet arrives
      // send an ACK per arrived packet. Do not check if this is the first time it has arrived
      struct packet ACK;
      ACK.header.packetSize = 0; // htons(sizeof(struct simplemuxBlastHeader)); The length is only that of the payload
      //ACK.header.protocolID = blastHeader->protocolID;  // the ACK does not have a payload, so no protocolID is needed
      ACK.header.protocolID = 0;
      ACK.header.identifier = blastHeader->identifier;
      ACK.header.ACK = THISISANACK;

      int fd;
      if(context->mode==UDP_MODE)
        fd = context->udp_mode_fd;
      else if(context->mode==NETWORK_MODE)
        fd = context->network_mode_fd;

      sendPacketBlastFlavor(fd,
                          context->mode,
                          &ACK,
                          context->remote,
                          context->local);

      do_debug(1," Sent blast ACK to the network. ID %i, length %i\n", ntohs(ACK.header.identifier), ntohs(ACK.header.packetSize));
    }
    else if((blastHeader->ACK & MASK ) == HEARTBEAT) {
      do_debug(1," Arrived blast heartbeat\n");
      uint64_t now = GetTimeStamp();
      context->lastBlastHeartBeatReceived = now;
    }
    else {
      perror("Unknown blast packet type\n");
    }
  }
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

        do_debug(1, " DEMUXED PACKET #%i", num_demuxed_packets);
        do_debug(2, ": ");
      }
      else {
        // fast flavor
        assert(context->flavor == 'F');

        // I have demuxed another packet
        num_demuxed_packets ++;

        do_debug(1, " DEMUXED PACKET #%i", num_demuxed_packets);
        do_debug(2, ":");   
      }


      if (context->flavor == 'N') {
        // normal flavor

        if (LXT_first_byte == 0) {
          // the LXT bit of the first byte is 0 => the separator is one-byte long

          // I have to convert the 6 (or 7) less significant bits to an integer, which means the length of the packet
          // since the two most significant bits are 0, the length is the value of the char
          packet_length = buffer_from_net[position] % maximum_packet_length;
          //packet_length = buffer_from_net[position] & maximum_packet_length;

          if (debug>0) {
            do_debug(2, " buffer from net: %d\n", buffer_from_net[position]);
            do_debug(2, "max packet length: %d\n", maximum_packet_length);
            do_debug(2, " Mux separator of 1 byte: 0x%02x (", buffer_from_net[position]);

            bool bits[8];   // used for printing the bits of a byte in debug mode
            FromByte(buffer_from_net[position], bits);
            PrintByte(2, 8, bits);
            do_debug(2, ")");
          }
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
            do_debug(3, "initial packet_length (only most significant bits): %d\n", packet_length);
            /*
            uint8_t mask;
            if (maximum_packet_length == 64)
              mask = 0x3F;
            else
              mask = 0x7F;
            packet_length = ((buffer_from_net[position] & maximum_packet_length) << 7 );*/

            // I add the value of the 7 less significant bits of the second byte
            packet_length = packet_length + (buffer_from_net[position + 1] % 128);
            do_debug(3, "packet_length (all the bits): %d\n", packet_length);
            //packet_length = packet_length + (buffer_from_net[position+1] & 0x7F);

            if (debug>0) {
              bool bits[8];   // used for printing the bits of a byte in debug mode

              // print the first byte
              FromByte(buffer_from_net[position], bits);
              do_debug(2, " Mux separator of 2 bytes: 0x%02x (", buffer_from_net[position]);
              PrintByte(2, 8, bits);
              
              // print the second byte
              FromByte(buffer_from_net[position+1], bits);
              do_debug(2, ") 0x%02x (",buffer_from_net[position+1]);
              PrintByte(2, 8, bits);
              do_debug(2,")");
            }          
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

            if (debug>0) {
              bool bits[8];   // used for printing the bits of a byte in debug mode

              // print the first byte
              FromByte(buffer_from_net[position], bits);
              do_debug(2, " Mux separator of 2 bytes: 0x%02x ", buffer_from_net[position]);
              PrintByte(2, 8, bits);
              
              // print the second byte
              FromByte(buffer_from_net[position+1], bits);
              do_debug(2, " %02x ",buffer_from_net[position+1]);
              PrintByte(2, 8, bits);  
              
              // print the third byte
              FromByte(buffer_from_net[position+2], bits);
              do_debug(2, " %02x ",buffer_from_net[position+2]);
              PrintByte(2, 8, bits);
            }          
            position = position + 3;
          }
        }

        // read the 'Protocol'

        // check if this is the first separator or not
        if (first_header_read == 0) {    // this is the first separator. The protocol field will always be present
          // the next thing I expect is a 'protocol' field
          if ( SIZE_PROTOCOL_FIELD == 1 ) {
            *protocol_rec = buffer_from_net[position];
            do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
            position ++;
          }
          else {  // SIZE_PROTOCOL_FIELD == 2
            *protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
            do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
            position = position + 2;
          }

          // if I am here, it means that I have read the first separator
          first_header_read = 1;

        }
        else {      // non-first separator. The protocol field may or may not be present
          if ( single_protocol_rec == 0 ) {
            // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
            if ( SIZE_PROTOCOL_FIELD == 1 ) {
              *protocol_rec = buffer_from_net[position];
              if(single_protocol_rec == 0)
                do_debug(2, ". Protocol 0x%02x", buffer_from_net[position]);
              position ++;
            }
            else {  // SIZE_PROTOCOL_FIELD == 2
              *protocol_rec = 256 * (buffer_from_net[position]) + buffer_from_net[position + 1];
              if(single_protocol_rec == 0)
                do_debug(2, ". Protocol 0x%02x%02x", buffer_from_net[position], buffer_from_net[position + 1]);
              position = position + 2;
            }
          }
        }
        do_debug(1, ". Length %i bytes\n", packet_length);
      }

      else {
        // fast flavor
        assert(context->flavor == 'F');

        if ((context->mode == TCP_SERVER_MODE) || (context->mode == TCP_CLIENT_MODE)) {
          // do nothing, because I have already read the length
          do_debug(1, " Length %i bytes\n", packet_length);

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

          //position = position + 2;
          do_debug(1, " Length %i bytes. ", packet_length);

          // each packet may belong to a different protocol, so the first thing is the 'Protocol' field
          *protocol_rec = fastHeader->protocolID;
          do_debug(1, "Protocol 0x%02x\n", protocol_rec);

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
        do_debug (1, "  ERROR: The length of the packet does not fit. Packet discarded\n");

        // this means that reception is desynchronized
        // in TCP mode, this will never recover, so abort
        if ((context->mode == TCP_CLIENT_MODE) || (context->mode == TCP_CLIENT_MODE)) {
          do_debug (1, "ERROR: Length problem in TCP mode. Abort\n");
          return -1;
        }

        // write the log file
        if ( log_file != NULL ) {
          // the packet is bad so I add a line
          fprintf (log_file, "%"PRIu64"\terror\tdemux_bad_length\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun );  
          fflush(log_file);
        }            
      }
      
      else {

        /************ decompress the packet if needed ***************/

        // if the number of the protocol is NOT 142 (ROHC) I do not decompress the packet
        if ( *protocol_rec != IPPROTO_ROHC ) {
          // non-compressed packet
          // dump the received packet on terminal
          if (debug>0) {
            //do_debug(1, " Received ");
            //do_debug(2, "   ");
            dump_packet ( packet_length, demuxed_packet );
          }
        }
        else {
          // ROHC-compressed packet

          // I cannot decompress the packet if I am not in ROHC mode
          if ( context->rohcMode == 0 ) {
            do_debug(1," ROHC packet received, but not in ROHC mode. Packet dropped\n");

            // write the log file
            if ( log_file != NULL ) {
              fprintf (log_file, "%"PRIu64"\tdrop\tno_ROHC_mode\t%i\t%"PRIu32"\n", GetTimeStamp(), packet_length, context->net2tun);  // the packet may be good, but the decompressor is not in ROHC mode
              fflush(log_file);
            }
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

            // dump the ROHC packet on terminal
            if (debug>0) {
              do_debug(1, " ROHC. ");
            }
            if (debug == 2) {
              do_debug(2, " ");
              do_debug(2, " ROHC packet\n");
              dump_packet (packet_length, demuxed_packet);
            }

            // decompress the packet
            *status = rohc_decompress3 (decompressor, rohc_packet_d, &ip_packet_d, &rcvd_feedback, &feedback_send);

            // if bidirectional mode has been set, check the feedback
            if ( context->rohcMode > 1 ) {

              // check if the decompressor has received feedback, and it has to be delivered to the local compressor
              if ( !rohc_buf_is_empty( rcvd_feedback) ) { 
                do_debug(3, "Feedback received from the remote compressor by the decompressor (%i bytes), to be delivered to the local compressor\n", rcvd_feedback.len);
                // dump the feedback packet on terminal
                if (debug>0) {
                  do_debug(2, "  ROHC feedback packet received\n");

                  dump_packet (rcvd_feedback.len, rcvd_feedback.data );
                }

                // deliver the feedback received to the local compressor
                //https://rohc-lib.org/support/documentation/API/rohc-doc-1.7.0/group__rohc__comp.html
                if ( rohc_comp_deliver_feedback2 ( compressor, rcvd_feedback ) == false ) {
                  do_debug(3, "Error delivering feedback received from the remote compressor to the compressor\n");
                }
                else {
                  do_debug(3, "Feedback from the remote compressor delivered to the compressor: %i bytes\n", rcvd_feedback.len);
                }
              }
              else {
                do_debug(3, "No feedback received by the decompressor from the remote compressor\n");
              }

              // check if the decompressor has generated feedback to be sent by the feedback channel to the other peer
              if ( !rohc_buf_is_empty( feedback_send ) ) { 
                do_debug(3, "Generated feedback (%i bytes) to be sent by the feedback channel to the peer\n", feedback_send.len);

                // dump the ROHC packet on terminal
                if (debug>0) {
                  do_debug(2, "  ROHC feedback packet generated\n");
                  dump_packet (feedback_send.len, feedback_send.data );
                }


                // send the feedback packet to the peer
                if (sendto(context->feedback_fd, feedback_send.data, feedback_send.len, 0, (struct sockaddr *)&(context->feedback_remote), sizeof(context->feedback_remote))==-1) {
                  perror("sendto() failed when sending a ROHC packet");
                }
                else {
                  do_debug(3, "Feedback generated by the decompressor (%i bytes), sent to the compressor\n", feedback_send.len);
                }
              }
              else {
                do_debug(3, "No feedback generated by the decompressor\n");
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

                //dump the IP packet on the standard output
                do_debug(2, "  ");
                do_debug(1, "IP packet resulting from the ROHC decompression: %i bytes\n", packet_length);
                //do_debug(2, "   ");

                if (debug>0) {
                  // dump the decompressed IP packet on terminal
                  dump_packet (ip_packet_d.len, ip_packet_d.data );
                }
              }
              else {
                /* no IP packet was decompressed because of ROHC segmentation or
                 * feedback-only packet:
                 *  - the ROHC packet was a non-final segment, so at least another
                 *    ROHC segment is required to be able to decompress the full
                 *    ROHC packet
                 *  - the ROHC packet was a feedback-only packet, it contained only
                 *    feedback information, so there was nothing to decompress */
                do_debug(1, "  no IP packet decompressed\n");

                // write the log file
                if ( log_file != NULL ) {
                  fprintf (log_file, "%"PRIu64"\trec\tROHC_feedback\t%i\t%"PRIu32"\tfrom\t%s\t%d\n", GetTimeStamp(), nread_from_net, context->net2tun, inet_ntoa(context->remote.sin_addr), ntohs(context->remote.sin_port));  // the packet is bad so I add a line
                  fflush(log_file);
                }
              }
            }

            else if ( *status == ROHC_STATUS_NO_CONTEXT ) {

              // failure: decompressor failed to decompress the ROHC packet 
              do_debug(1, "  decompression of ROHC packet failed. No context\n");
              //fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

              // write the log file
              if ( log_file != NULL ) {
                // the packet is bad
                fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun);  
                fflush(log_file);
              }
            }

            else if ( *status == ROHC_STATUS_OUTPUT_TOO_SMALL ) {  // the output buffer is too small for the compressed packet

              // failure: decompressor failed to decompress the ROHC packet 
              do_debug(1, "  decompression of ROHC packet failed. Output buffer is too small\n");
              //fprintf(stderr, "  decompression of ROHC packet failed. Output buffer is too small\n");

              // write the log file
              if ( log_file != NULL ) {
                // the packet is bad
                fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Output buffer is too small\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun);  
                fflush(log_file);
              }
            }

            else if ( *status == ROHC_STATUS_MALFORMED ) {      // the decompression failed because the ROHC packet is malformed 

              // failure: decompressor failed to decompress the ROHC packet 
              do_debug(1, "  decompression of ROHC packet failed. No context\n");
              //fprintf(stderr, "  decompression of ROHC packet failed. No context\n");

              // write the log file
              if ( log_file != NULL ) {
                // the packet is bad
                fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. No context\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun);  
                fflush(log_file);
              }
            }

            else if ( *status == ROHC_STATUS_BAD_CRC ) {      // the CRC detected a transmission or decompression problem

              // failure: decompressor failed to decompress the ROHC packet 
              do_debug(1, "  decompression of ROHC packet failed. Bad CRC\n");
              //fprintf(stderr, "  decompression of ROHC packet failed. Bad CRC\n");

              // write the log file
              if ( log_file != NULL ) {
                // the packet is bad
                fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Bad CRC\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun);  
                fflush(log_file);
              }
            }

            else if ( *status == ROHC_STATUS_ERROR ) {        // another problem occurred

              // failure: decompressor failed to decompress the ROHC packet 
              do_debug(1, "  decompression of ROHC packet failed. Other error\n");
              //fprintf(stderr, "  decompression of ROHC packet failed. Other error\n");

              // write the log file
              if ( log_file != NULL ) {
                // the packet is bad
                fprintf (log_file, "%"PRIu64"\terror\tdecomp_failed. Other error\t%i\t%"PRIu32"\n", GetTimeStamp(), nread_from_net, context->net2tun);  
                fflush(log_file);
              }
            }
          }
        }
        /*********** end decompression **************/

        // write the demuxed (and perhaps decompressed) packet to the tun interface
        // if compression is used, check that ROHC has decompressed correctly
        if ( ( *protocol_rec != IPPROTO_ROHC ) || ((*protocol_rec == IPPROTO_ROHC) && ( *status == ROHC_STATUS_OK))) {

          // tun mode
          if(context->tunnelMode == TUN_MODE) {
             // write the demuxed packet to the tun interface
            do_debug (2, " Sending packet of %i bytes to the tun interface\n", packet_length);
            cwrite ( context->tun_fd, demuxed_packet, packet_length );
          }
          // tap mode
          else if(context->tunnelMode == TAP_MODE) {
            if (*protocol_rec != IPPROTO_ETHERNET) {
              do_debug (2, "wrong value of 'Protocol' field received. It should be 143, but it is %i", protocol_rec);              
            }
            else {
               // write the demuxed packet to the tap interface
              do_debug (2, " Sending frame of %i bytes to the tap interface\n", packet_length);
              cwrite ( context->tun_fd, demuxed_packet, packet_length );
            }
          }
          else {
            perror ("wrong value of 'tunnelMode'");
            exit (EXIT_FAILURE);
          }
          
          do_debug(2, "\n");
          //do_debug(2, "packet length (without separator): %i\n", packet_length);

          // write the log file
          if ( log_file != NULL ) {
            fprintf (log_file, "%"PRIu64"\tsent\tdemuxed\t%i\t%"PRIu32"\n", GetTimeStamp(), packet_length, context->net2tun);  // the packet is good
            fflush(log_file);
          }
        }
      }
    }              
  }
  return 1;
}