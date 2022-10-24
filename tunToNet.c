#include "netToTun.c"

// packet/frame arrived at tun: read it, and send a blast packet to the network
void tunToNetBlastFlavor (struct context* contextSimplemux,
                        uint32_t tun2net,
                        struct packet **unconfirmedPacketsBlastFlavor,
                        uint64_t* lastHeartBeatReceived )
{
  uint64_t now = GetTimeStamp();

  do_debug(3, "%"PRIu64": Packet arrived from tun\n", now);             

  // add a new empty packet to the list
  struct packet* thisPacket = insertLast(unconfirmedPacketsBlastFlavor,0,NULL);

  // read the packet from contextSimplemux->tun_fd and add the data
  // use 'htons()' because these fields will be sent through the network
  thisPacket->header.packetSize = htons(cread (contextSimplemux->tun_fd, thisPacket->tunneledPacket, BUFSIZE));
  thisPacket->header.identifier = htons((uint16_t)tun2net); // the ID is the 16 LSBs of 'tun2net'

  do_debug(1, "NATIVE PACKET arrived from tun: ID %i, length %i bytes\n", ntohs(thisPacket->header.identifier), ntohs(thisPacket->header.packetSize));

  assert ( SIZE_PROTOCOL_FIELD == 1 );

  if (contextSimplemux->tunnelMode == TAP_MODE) {
    thisPacket->header.protocolID = IPPROTO_ETHERNET;
  }
  else if (contextSimplemux->tunnelMode == TUN_MODE) {
    thisPacket->header.protocolID = IPPROTO_IP_ON_IP;
  }

  // this packet will require an ACK
  thisPacket->header.ACK = ACKNEEDED;

  // send the packet to the network
  int fd;
  if(contextSimplemux->mode==UDP_MODE)
    fd = contextSimplemux->udp_mode_fd;
  else if(contextSimplemux->mode==NETWORK_MODE)
    fd = contextSimplemux->network_mode_fd;

  sendPacketBlastFlavor(fd,
                      contextSimplemux->mode,
                      thisPacket,
                      contextSimplemux->remote,
                      contextSimplemux->local);

  do_debug(1, " Sent blast packet to the network. ID %i, Length %i\n", ntohs(thisPacket->header.identifier), ntohs(thisPacket->header.packetSize));

  /*
  // write in the log file
  switch (contextSimplemux->mode) {
    case UDP_MODE:        
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    break;
   
    case NETWORK_MODE:
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), contextSimplemux->num_pkts_stored_from_tun);
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    break;
  }*/

  // the packet has been sent. Store the timestamp
  thisPacket->sentTimestamp = now;

  if(now - (*lastHeartBeatReceived) > HEARTBEATDEADLINE) {
    // heartbeat from the other side not received recently
    if(delete(unconfirmedPacketsBlastFlavor,ntohs(thisPacket->header.identifier))==false) {
      do_debug(2," The packet had already been removed from the list\n");
    }
    else {
      do_debug(2," Packet with ID %i removed from the list\n", tun2net);
    }              
    do_debug(2, "%"PRIu64" The arrived packet has not been stored because the last heartbeat was received %"PRIu64" us ago. Total %i pkts stored\n", now, now - (*lastHeartBeatReceived), length(unconfirmedPacketsBlastFlavor));
  }
  else {
    do_debug(2, "%"PRIu64" The arrived packet has been stored. Total %i pkts stored\n", thisPacket->sentTimestamp, length(unconfirmedPacketsBlastFlavor));
    if(debug > 1)
      dump_packet ( ntohs(thisPacket->header.packetSize), thisPacket->tunneledPacket );              
  }
}

// packet/frame arrived at tun: read it, and check if:
// - the packet has to be stored
// - a multiplexed packet has to be sent through the network
void tunToNetNoBlastFlavor (struct context* contextSimplemux,
                            uint32_t tun2net,
                            bool accepting_tcp_connections,
                            struct iphdr* ipheader,
                            uint8_t ipprotocol,
                            int selected_mtu,
                            int* first_header_written,
                            int size_separator_fast_mode,
                            int size_max,
                            uint64_t* time_last_sent_in_microsec,
                            int limit_numpackets_tun,
                            int size_threshold,
                            uint64_t timeout,
                            FILE *log_file)
{

  /* read the packet from contextSimplemux->tun_fd, store it in the array, and store its size */
  contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = cread (contextSimplemux->tun_fd, contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], BUFSIZE);
  uint16_t size = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];  

  // print the native packet/frame received
  if (debug>0) {
    if (contextSimplemux->tunnelMode == TUN_MODE)
      do_debug(1, "NATIVE PACKET #%"PRIu32": Read packet from tun: %i bytes\n", tun2net, size);
    else if (contextSimplemux->tunnelMode == TAP_MODE)
      do_debug(1, "NATIVE PACKET #%"PRIu32": Read packet from tap: %i bytes\n", tun2net, size);

    //do_debug(2, "   ");
    // dump the newly-created IP packet on terminal
    dump_packet ( contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] );
  }

  // write in the log file
  if ( log_file != NULL ) {
    fprintf (log_file, "%"PRIu64"\trec\tnative\t%i\t%"PRIu32"\n", GetTimeStamp(), size, tun2net);
    fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
  }


  // check if this packet (plus the tunnel and simplemux headers ) is bigger than the MTU. Drop it in that case
  bool drop_packet = false;
  if (contextSimplemux->mode == UDP_MODE) {

    if ( size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3 > selected_mtu ) {
      drop_packet = true;
      do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, selected_mtu);

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\n", GetTimeStamp(), size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    }
  }
  
  // TCP client mode or TCP server mode
  else if ((contextSimplemux->mode == TCP_CLIENT_MODE) || (contextSimplemux->mode == TCP_SERVER_MODE)) {          
    if ( size + IPv4_HEADER_SIZE + TCP_HEADER_SIZE + 3 > selected_mtu ) {
      drop_packet = true;
      do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, selected_mtu);

      // write the log file
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\n", GetTimeStamp(), size + IPv4_HEADER_SIZE + UDP_HEADER_SIZE + 3, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port));
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    }
  }
  
  // network mode
  else {
    if ( size + IPv4_HEADER_SIZE + 3 > selected_mtu ) {
      drop_packet = true;
      do_debug(1, " Warning: Packet dropped (too long). Size when tunneled %i. Selected MTU %i\n", size + IPv4_HEADER_SIZE + 3, selected_mtu);

      // write the log file
      if ( log_file != NULL ) {
        // FIXME: remove 'nun_packets_stored_from_tun' from the expression
        fprintf (log_file, "%"PRIu64"\tdrop\ttoo_long\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\n", GetTimeStamp(), size + IPv4_HEADER_SIZE + 3, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    }
  }

  // the length of the packet is adequate
  if ( drop_packet == false ) {

    /******************** compress the headers if the ROHC option has been set ****************/
    if ( contextSimplemux->rohcMode > 0 ) {
      // header compression has been selected by the user

      // copy the length read from tun to the buffer where the packet to be compressed is stored
      ip_packet.len = size;

      // copy the packet
      memcpy(rohc_buf_data_at(ip_packet, 0), contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], size);

      // reset the buffer where the rohc packet is to be stored
      rohc_buf_reset (&rohc_packet);

      // compress the IP packet
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
        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = IPPROTO_ROHC;
        }
        else {  // SIZE_PROTOCOL_FIELD == 2 
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = 0;
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][1] = IPPROTO_ROHC;
        }

        // Copy the compressed length and the compressed packet over the packet read from tun
        contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = rohc_packet.len;
        for (uint16_t l = 0; l < contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] ; l++) {
          contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][l] = rohc_buf_byte_at(rohc_packet, l);
        }
        // I try to use memcpy instead, but it does not work properly
        // memcpy(contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], rohc_buf_byte_at(rohc_packet, 0), contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun]);

        // dump the ROHC packet on terminal
        if (debug >= 1 ) {
          do_debug(1, " ROHC-compressed to %i bytes\n", rohc_packet.len);
        }
        if (debug == 2) {
          //do_debug(2, "   ");
          dump_packet ( rohc_packet.len, rohc_packet.data );
        }

      }
      else {
        /* compressor failed to compress the IP packet */
        /* Send it in its native form */

        // I don't have to copy the native length and the native packet, because they
        // have already been stored in 'contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun]' and 'contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun]'

        // since this packet is NOT compressed, its protocol number has to be 4: 'IP on IP'
        // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = IPPROTO_IP_ON_IP;
        }
        else {  // SIZE_PROTOCOL_FIELD == 2 
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = 0;
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][1] = IPPROTO_IP_ON_IP;
        }

        fprintf(stderr, "compression of IP packet failed\n");

        // print in the log file
        if ( log_file != NULL ) {
          fprintf (log_file, "%"PRIu64"\terror\tcompr_failed. Native packet sent\t%i\t%"PRIu32"\\n", GetTimeStamp(), size, tun2net);
          fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
        }

        do_debug(2, "  ROHC did not work. Native packet sent: %i bytes:\n   ", size);
        //goto release_compressor;
      }
    }
    else {
      // header compression has not been selected by the user

      if (contextSimplemux->tunnelMode == TAP_MODE) {
        // tap mode
        
        // since this frame CANNOT be compressed, its protocol number has to be 143: 'Ethernet on IP' 
        // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = IPPROTO_ETHERNET;
        }
        else {  // SIZE_PROTOCOL_FIELD == 2 
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = 0;
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][1] = IPPROTO_ETHERNET;
        }               
      }
      else if (contextSimplemux->tunnelMode == TUN_MODE) {
        // tun mode
      
        // since this IP packet is NOT compressed, its protocol number has to be 4: 'IP on IP' 
        // (IANA protocol numbers, http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = IPPROTO_IP_ON_IP;
        }
        else {  // SIZE_PROTOCOL_FIELD == 2 
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0] = 0;
          contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][1] = IPPROTO_IP_ON_IP;
        }
      }

      else {
        perror ("wrong value of 'tunnelMode'");
        exit (EXIT_FAILURE);
      }
    }


    /*** Calculate if the size limit will be reached when multiplexing the present packet ***/
    // if the addition of the present packet will imply a multiplexed packet bigger than the size limit:
    // - I send the previously stored packets
    // - I store the present one
    // - I reset the period

    int single_protocol;

    // in fast flavor I will send the protocol in every packet
    // in normal flavor I may avoid the protocol field in many packets

    if (contextSimplemux->flavor == 'N') {
      // normal flavor
      // calculate if all the packets belong to the same protocol (single_protocol = 1) 
      //or they belong to different protocols (single_protocol = 0)
      single_protocol = 1;
      for (int k = 1; k < contextSimplemux->num_pkts_stored_from_tun ; k++) {
        for (int l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
          if (contextSimplemux->protocol[k][l] != contextSimplemux->protocol[k-1][l])
            single_protocol = 0;
        }
      }              
    } 
    else {
      // fast mode
      assert(contextSimplemux->flavor == 'F');
      // single_protocol does not make sense in fast mode because
      //all the separators have a Protocol field
      single_protocol = -1;
    }


    // calculate the size without the present packet
    int predicted_size_muxed_packet;        // size of the muxed packet if the arrived packet was added to it

    predicted_size_muxed_packet = predict_size_multiplexed_packet ( contextSimplemux,
                                                                    single_protocol);

    // I add the length of the present packet:

    // separator and length of the present packet
    if (contextSimplemux->flavor == 'N') {
      // normal flavor

      if ((*first_header_written) == 0) {
        // this is the first header, so the maximum length to be expressed in 1 byte is 64
        if (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] < 64 ) {
          predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];
        }
        else {
          predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];
        }
      }
      else {
        // this is not the first header, so the maximum length to be expressed in 1 byte is 128
        if (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] < 128 ) {
          predicted_size_muxed_packet = predicted_size_muxed_packet + 1 + contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];
        }
        else {
          predicted_size_muxed_packet = predicted_size_muxed_packet + 2 + contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];
        }
      }
    }
    else {
      // fast mode
      assert(contextSimplemux->flavor == 'F');

      // the header is always fixed: the size of the length field + the size of the protocol field 
      predicted_size_muxed_packet = predicted_size_muxed_packet +
                                    size_separator_fast_mode +
                                    contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];
    }


    if (predicted_size_muxed_packet > size_max ) {
      // if the present packet is muxed, the max size of the packet will be overriden. So I first empty the buffer
      //i.e. I build and send a multiplexed packet not including the current one

      //do_debug(2, "\n");

      switch (contextSimplemux->mode) {
        case UDP_MODE:
          do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE + UDP_HEADER_SIZE );
        case TCP_CLIENT_MODE:
          do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE + TCP_HEADER_SIZE );
        case NETWORK_MODE:
          do_debug(1, "SENDING TRIGGERED: MTU size reached. Predicted size: %i bytes (over MTU)\n", predicted_size_muxed_packet + IPv4_HEADER_SIZE );
        break;
      }

      // add the length corresponding to the Protocol field
      if (contextSimplemux->flavor == 'N') {
        // normal flavor

        // add the Single Protocol Bit in the first header (the most significant bit)
        // it is '1' if all the multiplexed packets belong to the same protocol
        if (single_protocol == 1) {
          contextSimplemux->separators_to_multiplex[0][0] = contextSimplemux->separators_to_multiplex[0][0] + 0x80;  // this puts a 1 in the most significant bit position
          (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + 1;                // one byte corresponding to the 'protocol' field of the first header
        }
        else {
          (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + contextSimplemux->num_pkts_stored_from_tun;    // one byte per packet, corresponding to the 'protocol' field
        }
      }
      else { 
        // fast mode
        assert(contextSimplemux->flavor == 'F');

        contextSimplemux->size_muxed_packet = contextSimplemux->size_muxed_packet + (contextSimplemux->num_pkts_stored_from_tun * SIZE_PROTOCOL_FIELD);
      }

      // build the multiplexed packet without the current one
      uint16_t total_length;          // total length of the built multiplexed packet
      uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

      total_length = build_multiplexed_packet ( contextSimplemux,
                                                single_protocol,
                                                muxed_packet);

      if (contextSimplemux->flavor == 'N') {
        // normal flavor

        if (single_protocol) {
          if (SIZE_PROTOCOL_FIELD == 1)
            do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte in the first separator\n");
          else
            do_debug(2, "   All packets belong to the same protocol. Added 2 Protocol bytes in the first separator\n");
        }
        else {
          if (SIZE_PROTOCOL_FIELD == 1)
            do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n", contextSimplemux->num_pkts_stored_from_tun);
          else
            do_debug(2, "   Not all packets belong to the same protocol. Added 2 Protocol bytes in each separator. Total %i bytes\n", 2 * contextSimplemux->num_pkts_stored_from_tun);
        }                
      }
      else {
        // fast mode
        assert(contextSimplemux->flavor == 'F');

        do_debug(2, "   Fast mode. Added 1 Protocol byte to each separator. Total %i bytes", contextSimplemux->num_pkts_stored_from_tun);
      }
      
      switch(contextSimplemux->tunnelMode) {
        case TUN_MODE:
          switch (contextSimplemux->mode) {
            case UDP_MODE:
              do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
              do_debug(1, " Sending to the network a UDP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;
            case TCP_CLIENT_MODE:
              //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
              //do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(1, " Sending to the network a TCP packet containing: %i native packet(s) (not this one) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
            break;
            case TCP_SERVER_MODE:
              //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
              //do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(1, " Sending to the network a TCP packet containing: %i native packet(s) (not this one) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
            break;
            case NETWORK_MODE:
              do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
              do_debug(1, " Sending to the network an IP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE );
            break;
          }
        break;

        case TAP_MODE:
          switch (contextSimplemux->mode) {
            case UDP_MODE:
              do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
              do_debug(1, " Sending to the network a UDP packet without this Eth frame: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
            break;
            case TCP_CLIENT_MODE:
              //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
              //do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(1, " Sending to the network a TCP packet containing: %i native Eth frame(s) (not this one) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
            break;
            case TCP_SERVER_MODE:
              //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
              //do_debug(1, " Sending to the network a TCP muxed packet without this one: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
              do_debug(1, " Sending to the network a TCP packet containing: %i native Eth frame(s) (not this one) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
            break;
            case NETWORK_MODE:
              do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
              do_debug(1, " Sending to the network an IP packet without this Eth frame: %i bytes\n", (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE );
            break;
          }
        break;
      }  


      // send the multiplexed packet without the current one
      switch (contextSimplemux->mode) {
        case UDP_MODE:
          // send the packet
          if (sendto(contextSimplemux->udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&(contextSimplemux->remote), sizeof(contextSimplemux->remote))==-1) {
            perror("sendto() in UDP mode failed");
            exit (EXIT_FAILURE);
          }
          
          // write in the log file
          if ( log_file != NULL ) {
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
            fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
          }
        break;

        case TCP_CLIENT_MODE:
          // send the packet
          if (write(contextSimplemux->tcp_client_fd, muxed_packet, total_length)==-1) {
            perror("write() in TCP client mode failed");
            exit (EXIT_FAILURE);
          }
          
          // write in the log file
          if ( log_file != NULL ) {
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
            fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
          }
        break;

        case TCP_SERVER_MODE:  
          if(accepting_tcp_connections == 1) {
            do_debug(1," The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
          }
          else {
            // send the packet
            //if (sendto(tcp_welcoming_fd, muxed_packet, total_length, 0, (struct sockaddr *)&(contextSimplemux->remote), sizeof(contextSimplemux->remote))==-1) {
            if (write(contextSimplemux->tcp_server_fd, muxed_packet, total_length)==-1) {
              perror("write() in TCP server mode failed");
              exit (EXIT_FAILURE);
            }
            // write in the log file
            if ( log_file != NULL ) {
              fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
              fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
            }              
          }
        break;
        
        case NETWORK_MODE:
          // build the header
          BuildIPHeader(ipheader, total_length, ipprotocol, contextSimplemux->local, contextSimplemux->remote);

          // build the full IP multiplexed packet
          uint8_t full_ip_packet[BUFSIZE];
          BuildFullIPPacket(*ipheader, muxed_packet, total_length, full_ip_packet);

          // send the packet
          if (sendto (contextSimplemux->network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&(contextSimplemux->remote), sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() in Network mode failed");
            exit (EXIT_FAILURE);
          }
          // write in the log file
          if ( log_file != NULL ) {
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), contextSimplemux->num_pkts_stored_from_tun);
            fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
          }
        break;
      }


      // I have sent a packet, so I restart the period: update the time of the last packet sent
      uint64_t now_microsec = GetTimeStamp();
      *time_last_sent_in_microsec = now_microsec;

      // I have emptied the buffer, so I have to
      //move the current packet to the first position of the 'packets_to_multiplex' array
      memcpy(contextSimplemux->packets_to_multiplex[0], contextSimplemux->packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], BUFSIZE);

      // move the current separator to the first position of the array
      memcpy(contextSimplemux->separators_to_multiplex[0], contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun], 2);

      // move the size of the packet to the first position of the array
      contextSimplemux->size_packets_to_multiplex[0] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];

      // set the rest of the values of the size to 0
      // note: it starts with 1, not with 0
      for (int j=1; j < MAXPKTS; j++)
        contextSimplemux->size_packets_to_multiplex[j] = 0;

      // move the size of the separator to the first position of the array
      contextSimplemux->size_separators_to_multiplex[0] = contextSimplemux->size_separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];

      // I have sent a packet, so I set to 0 the "(*first_header_written)" bit
      (*first_header_written) = 0;

      // reset the length and the number of packets
      (contextSimplemux->size_muxed_packet) = 0;
      contextSimplemux->num_pkts_stored_from_tun = 0;
    }
    /*** end check if size limit would be reached ***/


    // update the size of the muxed packet, adding the size of the current one
    (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];

    if (contextSimplemux->flavor == 'N') {
      // normal flavor

      // I have to add the multiplexing separator.
      //   - It is 1 byte if the length is smaller than 64 (or 128 for non-first separators) 
      //   - It is 2 bytes if the length is 64 (or 128 for non-first separators) or more
      //   - It is 3 bytes if the length is 8192 (or 16384 for non-first separators) or more

      int maximum_packet_length;  // the maximum length of a packet. It may be 64 (first header) or 128 (non-first header)
      int limit_length_two_bytes;             // the maximum length of a packet in order to express it in 2 bytes. It may be 8192 or 16384 (non-first header)

      if ((*first_header_written) == 0) {
        // this is the first header
        maximum_packet_length = 64;
        limit_length_two_bytes = 8192;
      }
      else {
        // this is a non-first header
        maximum_packet_length = 128;
        limit_length_two_bytes = 16384;
      }

      // check if the length has to be one, two or three bytes
      // I am assuming that a packet will never be bigger than 1048576 (2^20) bytes for a first header,
      // or 2097152 (2^21) bytes for a non-first one)

      // one-byte separator
      if (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] < maximum_packet_length ) {

        // the length can be written in the first byte of the separator
        // it can be expressed in 
        //  - 6 bits for the first separator
        // - 7 bits for non-first separators
        contextSimplemux->size_separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = 1;

        // add the 'length' field to the packet
        // since the value is < maximum_packet_length, the most significant bits will always be 0:
        // - first separator: the value will be expressed in 6 bits
        // - non-first separator: the value will be expressed in 7 bits
        contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun];

        // increase the size of the multiplexed packet
        (contextSimplemux->size_muxed_packet) ++;

        // print the Mux separator (only one byte)
        if(debug) {
          // convert the byte to bits
          bool bits[8];   // used for printing the bits of a byte in debug mode
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0], bits);
          do_debug(2, " Mux separator of 1 byte (plus Protocol): 0x%02x (", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]);
          //do_debug(2, " Mux separator of 1 byte (plus Protocol): ");
          if ((*first_header_written) == 0) {
            PrintByte(2, 7, bits);      // first header
            do_debug(2, ", SPB field not included)\n");
          }
          else {
            PrintByte(2, 8, bits);      // non-first header
            do_debug(2, ")\n");
          }
        }
      }
      
      // two-byte separator
      else if (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] < limit_length_two_bytes ) {

        // the length requires a two-byte separator (length expressed in 13 or 14 bits)
        contextSimplemux->size_separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = 2;

        // first byte of the Mux separator
        // It can be:
        // - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
        // - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
        // get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
        // add 64 (or 128) in order to put a '1' in the second (or first) bit
        
        // fill the LXT field of the first byte
        // first header
        if ((*first_header_written) == 0) {
          // add 64 (0100 0000) to the header, i.e., set the value of LXT to '1' (7th bit)
          contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128 ) + 64;  // first header
        }
        // non-first header
        else {
          // add 128 (1000 0000) to the header, i.e., set the value of LXT to '1' (8th bit)
          contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128 ) + 128;  // non-first header
          //do_debug(2, "num_pkts_stored_from_tun: %i\n", contextSimplemux->num_pkts_stored_from_tun);
          //do_debug(2, "contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun]: %i\n", contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun]);
          //do_debug(2, "contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128: %i\n", contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128);
          //do_debug(2, "contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128 + 128: %i\n", (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 128) + 128);
          //do_debug(2, "separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]: %i\n", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]);
        }


        // second byte of the Mux separator

        // Length: the 7 less significant bytes of the length. Use modulo 128
        contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] % 128;

        // fill the LXT field of the second byte
        // LXT bit has to be set to 0, because this is the last byte of the length
        // if I do nothing, it will be 0, since I have used modulo 128

        // SPB field will be filled later
        
        // increase the size of the multiplexed packet
        (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + 2;

        // print the two bytes of the separator
        if(debug) {
          bool bits[8];   // used for printing the bits of a byte in debug mode

          // first byte
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0], bits);
          do_debug(2, " Mux separator of 2 bytes (plus Protocol): 0x%02x (", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]);
          //do_debug(2, " Mux separator of 2 bytes (plus Protocol). First byte: ");
          if ((*first_header_written) == 0) {
            PrintByte(2, 7, bits);      // first header
            do_debug(2, ", SPB field not included)");
          }
          else {
            PrintByte(2, 8, bits);      // non-first header
            do_debug(2, ")");
          }

          // second byte
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1], bits);
          do_debug(2, " 0x%02x (", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1]);
          //do_debug(2, ". second byte: ");
          PrintByte(2, 8, bits);
          do_debug(2, ")\n");
        }  
      }

      // three-byte separator
      else {

        // the length requires a three-byte separator (length expressed in 20 or 21 bits)
        contextSimplemux->size_separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = 3;

        //FIXME. NOT TESTED. I have just copied the case of two-byte separator
        // first byte of the Mux separator
        // It can be:
        // - first-header: SPB bit, LXT=1 and 6 bits with the most significant bits of the length
        // - non-first-header: LXT=1 and 7 bits with the most significant bits of the length
        // get the most significant bits by dividing by 128 (the 7 less significant bits will go in the second byte)
        // add 64 (or 128) in order to put a '1' in the second (or first) bit

        if ((*first_header_written) == 0) {
          // first header
          contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 16384 ) + 64;

        }
        else {
          // non-first header
          contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = (contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 16384 ) + 128;  
        }


        // second byte of the Mux separator
        // Length: the 7 second significant bytes of the length. Use modulo 16384
        contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] % 16384;

        // LXT bit has to be set to 1, because this is not the last byte of the length
        contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] + 128;


        // third byte of the Mux separator
        // Length: the 7 less significant bytes of the length. Use modulo 128
        contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] % 128;

        // LXT bit has to be set to 0, because this is the last byte of the length
        // if I do nothing, it will be 0, since I have used modulo 128


        // increase the size of the multiplexed packet
        (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + 3;

        // print the three bytes of the separator
        if(debug) {
          bool bits[8];   // used for printing the bits of a byte in debug mode

          // first byte
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0], bits);
          do_debug(2, " Mux separator of 3 bytes: (0x%02x) ", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]);
          if ((*first_header_written) == 0) {
            PrintByte(2, 7, bits);      // first header
          }
          else {
            PrintByte(2, 8, bits);      // non-first header
          }

          // second byte
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1], bits);
          do_debug(2, " (0x%02x) ", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1]);
          PrintByte(2, 8, bits);
          do_debug(2, "\n");

          // third byte
          FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][2], bits);
          do_debug(2, " (0x%02x) ", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][2]);
          PrintByte(2, 8, bits);
          do_debug(2, "\n");
        }
      }
    }
    else {
      // fast flavor
      assert(contextSimplemux->flavor == 'F');

      // the length requires a two-byte separator (length expressed in 16 bits)
      contextSimplemux->size_separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = sizeof(uint16_t);

      //separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] = htons(size);

      
      // add first byte of the separator (most significant bits)
      contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] / 256;

      // second byte of the Mux separator (less significant bits)
      contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1] = contextSimplemux->size_packets_to_multiplex[contextSimplemux->num_pkts_stored_from_tun] % 256;
      

      // increase the size of the multiplexed packet
      (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + 2;

      // print the two bytes of the separator
      if(debug>0) {
        bool bits[8];   // used for printing the bits of a byte in debug mode

        // first byte
        FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0], bits);
        do_debug(2, " Mux separator of 3 bytes. Length: 0x%02x (", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][0]);
        PrintByte(2, 8, bits);
        do_debug(2, ")");

        // second byte
        FromByte(contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1], bits);
        do_debug(2, " 0x%02x (", contextSimplemux->separators_to_multiplex[contextSimplemux->num_pkts_stored_from_tun][1]);
        PrintByte(2, 8, bits);
        do_debug(2, ")");

        // third byte: protocol
        FromByte(contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0], bits);
        do_debug(2, ". Protocol: 0x%02x (", contextSimplemux->protocol[contextSimplemux->num_pkts_stored_from_tun][0]);
        PrintByte(2, 8, bits);
        do_debug(2, ")\n");
      }
    }

    // I have finished storing the packet, so I increase the number of stored packets
    contextSimplemux->num_pkts_stored_from_tun ++;

    if (contextSimplemux->flavor == 'N') {
      // normal flavor

      // I have written a header of the multiplexed bundle, so I have to set to 1 the "first header written bit"
      if ((*first_header_written) == 0) (*first_header_written) = 1; 

      do_debug(1, " Packet stopped and multiplexed: accumulated %i pkts: %i bytes (Protocol not included).", contextSimplemux->num_pkts_stored_from_tun , (contextSimplemux->size_muxed_packet));
    }
    else {
      // fast flavor
      assert(contextSimplemux->flavor == 'F');

      do_debug(1, " Packet stopped and multiplexed: accumulated %i pkts: %i bytes (Separator(s) included).", contextSimplemux->num_pkts_stored_from_tun , (contextSimplemux->size_muxed_packet) + (contextSimplemux->num_pkts_stored_from_tun * SIZE_PROTOCOL_FIELD));
    }
   
    uint64_t now_microsec = GetTimeStamp();
    uint64_t time_difference = now_microsec - (*time_last_sent_in_microsec);

    do_debug(1, " Time since last trigger: %" PRIu64 " usec\n", time_difference);//PRIu64 is used for printing uint64_t numbers


    // check if a multiplexed packet has to be sent

    // if the packet limit or the size threshold are reached, send all the stored packets to the network
    // do not worry about the MTU. if it is reached, a number of packets will be sent
    if ((contextSimplemux->num_pkts_stored_from_tun == limit_numpackets_tun) || ((contextSimplemux->size_muxed_packet) > size_threshold) || (time_difference > timeout )) {
      // a multiplexed packet has to be sent
      if (contextSimplemux->flavor == 'N') {
        // normal flavor

        // fill the SPB field (Single Protocol Bit)
        
        // calculate if all the packets belong to the same protocol
        single_protocol = 1;
        for (int k = 1; k < contextSimplemux->num_pkts_stored_from_tun ; k++) {
          for (int l = 0 ; l < SIZE_PROTOCOL_FIELD ; l++) {
            if (contextSimplemux->protocol[k][l] != contextSimplemux->protocol[k-1][l])
              single_protocol = 0;
          }
        }

        // Add the Single Protocol Bit in the first header (the most significant bit)
        // It is 1 if all the multiplexed packets belong to the same protocol
        if (single_protocol == 1) {
          contextSimplemux->separators_to_multiplex[0][0] = contextSimplemux->separators_to_multiplex[0][0] + 128;  // this puts a 1 in the most significant bit position
          // one or two bytes corresponding to the 'protocol' field of the first header
          (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + SIZE_PROTOCOL_FIELD;
        }
        else {
          // add the size that corresponds to the Protocol field of all the separators
          (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + ( SIZE_PROTOCOL_FIELD * contextSimplemux->num_pkts_stored_from_tun);
        }               
      }
      else {
        // fast flavor
        assert(contextSimplemux->flavor == 'F');

        // add the size that corresponds to the Protocol field of all the separators
        (contextSimplemux->size_muxed_packet) = (contextSimplemux->size_muxed_packet) + ( SIZE_PROTOCOL_FIELD * contextSimplemux->num_pkts_stored_from_tun);
        do_debug(2, "   Fast mode. Added header: length (2 bytes) + protocol (1 byte) in each separator. Total %i bytes\n", 3 * contextSimplemux->num_pkts_stored_from_tun);            
      }

      // write the debug information
      if (debug > 0) {
        //do_debug(2, "\n");
        do_debug(1, "SENDING TRIGGERED: ");
        if (contextSimplemux->num_pkts_stored_from_tun == limit_numpackets_tun)
          do_debug(1, "num packet limit reached\n");
        if ((contextSimplemux->size_muxed_packet) > size_threshold)
          do_debug(1," size threshold reached\n");
        if (time_difference > timeout)
          do_debug(1, "timeout reached\n");

        if ( SIZE_PROTOCOL_FIELD == 1 ) {
          if (single_protocol) {
            do_debug(2, "   All packets belong to the same protocol. Added 1 Protocol byte (0x%02x) in the first separator\n", contextSimplemux->protocol[0][0]);
          }
          else {
            do_debug(2, "   Not all packets belong to the same protocol. Added 1 Protocol byte in each separator. Total %i bytes\n", contextSimplemux->num_pkts_stored_from_tun);
          }
        }

        else {
          // SIZE_PROTOCOL_FIELD == 2
          if (single_protocol) {
            do_debug(2, "   All packets belong to the same protocol. Added 2 Protocol bytes (0x%02x%02x) in the first separator\n", contextSimplemux->protocol[0][0], contextSimplemux->protocol[0][1]);
          }
          else {
            do_debug(2, "   Not all packets belong to the same protocol. Added 2 Protocol bytes in each separator. Total %i bytes\n", 2 * contextSimplemux->num_pkts_stored_from_tun);
          }
        }

        switch(contextSimplemux->tunnelMode) {
          case TUN_MODE:
            switch (contextSimplemux->mode) {
              case UDP_MODE:
                do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
                do_debug(1, " Sending to the network a UDP packet containing %i native one(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
              break;
              case TCP_CLIENT_MODE:
                //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
                //do_debug(1, " Sending to the network a TCP packet containing %i native one(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(1, " Sending to the network a TCP packet containing: %i native one(s) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
              break;
              case TCP_SERVER_MODE:
                //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
                //do_debug(1, " Sending to the network a TCP packet containing %i native one(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(1, " Sending to the network a TCP packet containing: %i native one(s) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
              break;
              case NETWORK_MODE:
                do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
                do_debug(1, " Sending to the network an IP packet containing %i native one(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE );
              break;
            }
          break;
          
          case TAP_MODE:
            switch (contextSimplemux->mode) {
              case UDP_MODE:
                do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
                do_debug(1, " Sending to the network a UDP packet containing %i native Eth frame(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE);
              break;
              case TCP_CLIENT_MODE:
                //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
                //do_debug(1, " Sending to the network a TCP packet containing %i native Eth frame(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(1, " Sending to the network a TCP packet containing: %i native Eth frame(s) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
              break;
              case TCP_SERVER_MODE:
                //do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(2, "   Added tunneling header: IPv4 + TCP\n");
                //do_debug(1, " Sending to the network a TCP packet containing %i native Eth frame(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE);
                do_debug(1, " Sending to the network a TCP packet containing: %i native Eth frame(s) plus separator(s), %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet));
              break;
              case NETWORK_MODE:
                do_debug(2, "   Added tunneling header: %i bytes\n", IPv4_HEADER_SIZE );
                do_debug(1, " Sending to the network an IP packet containing %i native Eth frame(s): %i bytes\n", contextSimplemux->num_pkts_stored_from_tun, (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE );
              break;
            }
          break;
        }      
      }

      // build the multiplexed packet including the current one
      uint16_t total_length;          // total length of the built multiplexed packet
      uint8_t muxed_packet[BUFSIZE];  // stores the multiplexed packet

      total_length = build_multiplexed_packet ( contextSimplemux,
                                                single_protocol,
                                                muxed_packet);

      // send the multiplexed packet
      switch (contextSimplemux->mode) {
        case UDP_MODE:
          // send the packet. I don't need to build the header, because I have a UDP socket
          if (sendto(contextSimplemux->udp_mode_fd, muxed_packet, total_length, 0, (struct sockaddr *)&(contextSimplemux->remote), sizeof(contextSimplemux->remote))==-1) {
            perror("sendto() in UDP mode failed");
            exit (EXIT_FAILURE);                
          }
          else {
            if(contextSimplemux->tunnelMode == TUN_MODE) {
              do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);
            }
            else if(contextSimplemux->tunnelMode == TAP_MODE) {
              do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);                    
            }
            else {
              perror ("wrong value of 'tunnelMode'");
              exit (EXIT_FAILURE);
            }
          }
        break;
        
        case NETWORK_MODE:
          // build the header
          BuildIPHeader(ipheader, total_length, ipprotocol, contextSimplemux->local, contextSimplemux->remote);

          // build full IP multiplexed packet
          uint8_t full_ip_packet[BUFSIZE];
          BuildFullIPPacket(*ipheader, muxed_packet, total_length, full_ip_packet);

          // send the multiplexed packet
          if (sendto (contextSimplemux->network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&(contextSimplemux->remote), sizeof (struct sockaddr)) < 0)  {
            perror ("sendto() in Network mode failed ");
            exit (EXIT_FAILURE);
          }
          else {
            if(contextSimplemux->tunnelMode == TUN_MODE) {
              do_debug(2, "Packet sent (includes %d muxed packet(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);
            }
            else if(contextSimplemux->tunnelMode == TAP_MODE) {
              do_debug(2, "Packet sent (includes %d muxed frame(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);
            }
            else {
              perror ("wrong value of 'tunnelMode'");
              exit (EXIT_FAILURE);
            }
          }
        break;
          
        case TCP_CLIENT_MODE:
          // send the packet. I don't need to build the header, because I have a TCP socket
          
          if (write(contextSimplemux->tcp_client_fd, muxed_packet, total_length)==-1) {
            perror("write() in TCP client mode failed");
            exit (EXIT_FAILURE);
          }
          else {
            if(contextSimplemux->tunnelMode == TUN_MODE) {
              do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);
            }
            else if(contextSimplemux->tunnelMode == TAP_MODE) {
              do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);                    
            }
            else {
              perror ("wrong value of 'tunnelMode'");
              exit (EXIT_FAILURE);
            }
          }
        break;

        case TCP_SERVER_MODE:
          // send the packet. I don't need to build the header, because I have a TCP socket
          
          // check if the connection has already been established by the client
          if(accepting_tcp_connections == 1) {
            do_debug(1," The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
          }
          else {
            if (write(contextSimplemux->tcp_server_fd, muxed_packet, total_length)==-1) {
              perror("write() in TCP server mode failed");
              exit (EXIT_FAILURE);
            }
            else {
              if(contextSimplemux->tunnelMode == TUN_MODE) {
                do_debug(2, " Packet sent (includes %d muxed packet(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);
              }
              else if(contextSimplemux->tunnelMode == TAP_MODE) {
                do_debug(2, " Packet sent (includes %d muxed frame(s))\n\n", contextSimplemux->num_pkts_stored_from_tun);                    
              }
              else {
                perror ("wrong value of 'tunnelMode'");
                exit (EXIT_FAILURE);
              }
            }
          }
        break;
      }

      // write the log file
      if ( log_file != NULL ) {
        switch (contextSimplemux->mode) {
          case UDP_MODE:
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i", GetTimeStamp(), (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
          break;
          case TCP_CLIENT_MODE:
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i", GetTimeStamp(), (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE + TCP_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), ntohs(contextSimplemux->remote.sin_port), contextSimplemux->num_pkts_stored_from_tun);
          break;
          case NETWORK_MODE:
            fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i", GetTimeStamp(), (contextSimplemux->size_muxed_packet) + IPv4_HEADER_SIZE, tun2net, inet_ntoa(contextSimplemux->remote.sin_addr), contextSimplemux->num_pkts_stored_from_tun);
          break;
        }
        if (contextSimplemux->num_pkts_stored_from_tun == limit_numpackets_tun)
          fprintf(log_file, "\tnumpacket_limit");
        if ((contextSimplemux->size_muxed_packet) > size_threshold)
          fprintf(log_file, "\tsize_limit");
        if (time_difference > timeout)
          fprintf(log_file, "\ttimeout");
        fprintf(log_file, "\n");
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }

      // I have sent a packet, so I set to 0 the "first_header_written" bit
      (*first_header_written) = 0;

      // reset the length and the number of packets
      (contextSimplemux->size_muxed_packet) = 0 ;
      contextSimplemux->num_pkts_stored_from_tun = 0;

      // restart the period: update the time of the last packet sent
      *time_last_sent_in_microsec = now_microsec;
    }
    else {
      // a multiplexed packet does not have to be sent. I have just accumulated this one
      // just add a linefeed
      do_debug(2, "\n");
    }
  }
}