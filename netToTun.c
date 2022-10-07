/* Reads a multiplexed packet from the network
 * it returns:
 * 1  a multiplexed packet has been read from the network
 * 0  a correct but not multiplexed packet has been read from the network
 * -1 error. Incorrect read
 */
int readPacketFromNet(char mode,
              int udp_mode_fd,
              int network_mode_fd,
              uint8_t* buffer_from_net,
              uint8_t* buffer_from_net_aux,
              struct sockaddr_in received,
              socklen_t slen,
              uint16_t port,
              struct iphdr ipheader,
              uint8_t ipprotocol,
              uint8_t* protocol_rec,
              uint16_t* pending_bytes_muxed_packet,
              int tcp_server_fd,
              int tcp_client_fd,
              int size_separator_fast_mode,
              uint8_t* read_tcp_bytes_separator,
              uint16_t* read_tcp_bytes,
              uint16_t* length_muxed_packet,
              uint16_t* packet_length )

{
  int is_multiplexed_packet = -1;
  uint16_t nread_from_net;  // number of bytes read from network which will be demultiplexed

  if (mode == UDP_MODE) {
    // a packet has been received from the network, destined to the multiplexing port
    // 'slen' is the length of the IP address
    // I cannot use 'remote' because it would replace the IP address and port. I use 'received'

    nread_from_net = recvfrom ( udp_mode_fd, buffer_from_net, BUFSIZE, 0, (struct sockaddr *)&received, &slen );
    if (nread_from_net==-1) {
      perror ("recvfrom() UDP error");
    }
    // now buffer_from_net contains the payload (simplemux headers and multiplexled packets/frames) of a full packet or frame.
    // I don't have the IP and UDP headers

    // check if the packet comes from the multiplexing port (default 55555). (Its destination IS the multiplexing port)
    if (port == ntohs(received.sin_port)) 
      is_multiplexed_packet = 1;
    else
      is_multiplexed_packet = 0;
  }

  else if (mode == NETWORK_MODE) {
    // a packet has been received from the network, destined to the local interface for muxed packets
    nread_from_net = cread ( network_mode_fd, buffer_from_net_aux, BUFSIZE);

    if (nread_from_net==-1) perror ("cread demux()");
    // now buffer_from_net contains the headers (IP and Simplemux) and the payload of a full packet or frame.

    // copy from "buffer_from_net_aux" everything except the IP header (usually the first 20 bytes)
    memcpy ( buffer_from_net, buffer_from_net_aux + sizeof(struct iphdr), nread_from_net - sizeof(struct iphdr));
    // correct the size of "nread from net"
    nread_from_net = nread_from_net - sizeof(struct iphdr);

    // Get IP Header of received packet
    GetIpHeader(&ipheader,buffer_from_net_aux);
    if (ipheader.protocol == ipprotocol )
      is_multiplexed_packet = 1;
    else
      is_multiplexed_packet = 0;
  }

  else if ((mode == TCP_SERVER_MODE) || (mode == TCP_CLIENT_MODE)) {

    // some bytes have been received from the network, destined to the TCP socket
    
    /* Once the sockets are connected, the client can read it
     * through a normal 'read' call on the socket descriptor.
     * Read 'buffer_from_net' bytes
     * This call returns up to N bytes of data. If there are fewer 
     *bytes available than requested, the call returns the number currently available.
     */
    //nread_from_net = read(tcp_server_fd, buffer_from_net, sizeof(buffer_from_net));
    
    // I only read one packet (at most) each time the program goes through this part

    if (*pending_bytes_muxed_packet == 0) {
      // I have to start reading a new muxed packet: separator and payload
      do_debug(3, " Reading TCP. No pending bytes of the muxed packet. Start reading a new separator\n");

      // read a separator (3 or 4 bytes), or a part of it
      if (mode == TCP_SERVER_MODE) {
        nread_from_net = read(tcp_server_fd, buffer_from_net, size_separator_fast_mode - *read_tcp_bytes_separator);
      }
      else {
        nread_from_net = read(tcp_client_fd, buffer_from_net, size_separator_fast_mode - *read_tcp_bytes_separator);
      }
      do_debug(3, "  %i bytes of the separator read from the TCP socket", nread_from_net);

      if(nread_from_net < 0)  {
        perror("read() error TCP mode");
      }

      else if(nread_from_net == 0) {
        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if (nread_from_net < size_separator_fast_mode - *read_tcp_bytes_separator) {
        do_debug(3, " (part of the separator. Still %i bytes missing)\n", size_separator_fast_mode - *read_tcp_bytes_separator - nread_from_net);
        // I have read part of the separator
        *read_tcp_bytes_separator = *read_tcp_bytes_separator + nread_from_net;

        // I have not read a multiplexed packet yet
        is_multiplexed_packet = -1;
      }

      else if(nread_from_net == size_separator_fast_mode - *read_tcp_bytes_separator) {
        do_debug(3, " (the complete separator of %i bytes)\n", size_separator_fast_mode);
        // I have read the complete separator

        // I can now obtain the length of the packet
        // the first byte is the Most Significant Byte of the length
        // the second byte is the Less Significant Byte of the length
        *length_muxed_packet = (buffer_from_net[0] << 8)  + buffer_from_net[1];
        *pending_bytes_muxed_packet = *length_muxed_packet;

        do_debug(2, " Read separator: Length %i (0x%02x%02x)", *length_muxed_packet, buffer_from_net[0], buffer_from_net[1]);

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
        if (mode == TCP_SERVER_MODE) {
          nread_from_net = read(tcp_server_fd, buffer_from_net, *pending_bytes_muxed_packet);
        }
        else {
          nread_from_net = read(tcp_client_fd, buffer_from_net, *pending_bytes_muxed_packet);
        }
        do_debug(3, "  %i bytes of the muxed packet read from the TCP socket", nread_from_net);

        if(nread_from_net < 0)  {
          perror("read() error TCP server mode");
        }

        else if (nread_from_net < *pending_bytes_muxed_packet) {
          do_debug(3, "  (part of a muxed packet). Pending %i bytes\n", *pending_bytes_muxed_packet - nread_from_net);
          // I have not read the whole packet
          // next time I will have to keep on reading
          *pending_bytes_muxed_packet = *pending_bytes_muxed_packet - nread_from_net;
          *read_tcp_bytes = *read_tcp_bytes + nread_from_net;

          //do_debug(2,"Read %d bytes from the TCP socket. Total %d\n", nread_from_net, *read_tcp_bytes); 
          // I have not finished reading a muxed packet
          is_multiplexed_packet = -1;
        }
        else if (nread_from_net == *pending_bytes_muxed_packet) {
          // I have read a complete packet
          *packet_length = *read_tcp_bytes + nread_from_net;
          do_debug(3, " (complete muxed packet of %i bytes)\n", *packet_length);

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
      do_debug(3, " Reading TCP. %i TCP bytes pending of the previous payload\n", *pending_bytes_muxed_packet);

      if (mode == TCP_SERVER_MODE) {
        nread_from_net = read(tcp_server_fd, &(buffer_from_net[(*read_tcp_bytes)]), *pending_bytes_muxed_packet);
      }
      else {
        nread_from_net = read(tcp_client_fd, &(buffer_from_net[(*read_tcp_bytes)]), *pending_bytes_muxed_packet);
      }
      do_debug(3, "  %i bytes read from the TCP socket ", nread_from_net);

      if(nread_from_net < 0)  {
        perror("read() error TCP mode");
      }

      else if(nread_from_net == 0) {
        do_debug(3, " (I have read 0 bytes)\n");
        is_multiplexed_packet = -1;
      }

      else if(nread_from_net < *pending_bytes_muxed_packet) {
        do_debug(3, " (I have not yet read the whole muxed packet: pending %i bytes)\n", *length_muxed_packet - nread_from_net);
        // I have not read the whole packet
        // next time I will have to keep on reading
        *pending_bytes_muxed_packet = *length_muxed_packet - nread_from_net;
        *read_tcp_bytes = *read_tcp_bytes + nread_from_net;

        //do_debug(2,"Read %d bytes from the TCP socket. Accum %d. Pending %d\n", nread_from_net, *read_tcp_bytes, *pending_bytes_muxed_packet);

        // I have not finishing read the pending bytes of this packet
        is_multiplexed_packet = -1;
      }
      else if(nread_from_net == *pending_bytes_muxed_packet) {
        do_debug(3, "  I have read all the pending bytes (%i) of this muxed packet. Total %i bytes\n", nread_from_net, *length_muxed_packet);
        // I have read the pending bytes of this packet
        *pending_bytes_muxed_packet = 0;
        //*read_tcp_bytes = *read_tcp_bytes + nread_from_net;

        nread_from_net = *read_tcp_bytes + nread_from_net;

        // reset the variables
        *read_tcp_bytes_separator = 0;
        *read_tcp_bytes = 0;
        is_multiplexed_packet = 1;
      }
      
      else /*if(nread_from_net > *pending_bytes_muxed_packet) */ {
        do_debug(1, "ERROR: I have read all the pending bytes (%i) of this muxed packet, and some more. Abort\n", *pending_bytes_muxed_packet, nread_from_net - *pending_bytes_muxed_packet);
        // I have read the pending bytes of this packet, plus some more bytes
        // it doesn't make sense, because I have only read '*pending_bytes_muxed_packet'
        return(-1);
      }              
    }
  } 
  else {
    perror("Unknown mode");
    return(-1);      
  }

  return is_multiplexed_packet;
}