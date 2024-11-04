#include "buildMuxedPacket.h"

// it takes all the variables where packets are stored, and predicts the
//size of a multiplexed packet including all of them
// 'single_prot': if all the packets belong to the same protocol
// returns: the length of the multiplexed packet
uint16_t predictSizeMultiplexedPacket ( struct contextSimplemux* context,
                                        int single_prot)
{
  // only used in normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  int length = 0;

  if (context->flavor == 'N') {
    // normal flavor

    // for each packet, read the protocol field (if present), the separator and the packet itself
    for (int k = 0; k < context->numPktsStoredFromTun ; k++) {

      // count the 'Protocol' field if necessary
      if ( ( k == 0 ) || ( single_prot == 0 ) ) {
        // the protocol field is always present in the first separator (k=0), and maybe in the rest
        length = length + 1;  // the protocol field is 1 byte long
      }
    
      // count the separator
      length = length + context->sizeSeparatorsToMultiplex[k];

      // count the bytes of the packet itself
      length = length + context->sizePacketsToMultiplex[k];
    }    
  }
  else {
    // fast flavor

    // the separator is always the same size: 'sizeSeparatorFastMode'
    length = length + (context->numPktsStoredFromTun * context->sizeSeparatorFastMode);

    // for each packet, add the length of the packet itself
    for (int k = 0; k < context->numPktsStoredFromTun ; k++) {
      // count the bytes of the packet itself
      length = length + context->sizePacketsToMultiplex[k];
    }       
  }

  return length;
}



// it takes all the variables where packets are stored, and builds a multiplexed packet
// 'single_prot': if all the packets belong to the same protocol
// the multiplexed packet is stored in 'mux_packet'
// returns: the length of the multiplexed packet
uint16_t buildMultiplexedPacket ( struct contextSimplemux* context,
                                  int single_prot,
                                  uint8_t mux_packet[BUFSIZE])
{
  int length = 0;

  // for each packet, write
  // - the separator
  // - the protocol field (if required)
  // - the packet itself
  for (int k = 0; k < context->numPktsStoredFromTun ; k++) {

    #ifdef DEBUG
      if (k == 0)
        // add a tab before the first separator
        do_debug_c(2, ANSI_COLOR_RESET, " Separators: ");
      else
        // add a semicolon before the 2nd and subsequent separators
        do_debug(2, "; ");
        
      do_debug_c(2, ANSI_COLOR_RESET, "#%d: ", k+1);
      
      // add the separator
      do_debug(2, "0x");
    #endif

    // add the separator
    for (int l = 0; l < context->sizeSeparatorsToMultiplex[k] ; l++) {
      #ifdef DEBUG
        do_debug_c(2, ANSI_COLOR_RESET, "%02x", context->separatorsToMultiplex[k][l]);
      #endif

      mux_packet[length] = context->separatorsToMultiplex[k][l];
      length ++;
    }


    // add the protocol field
    if (context->flavor == 'N') { // normal flavor
      // add the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {
        // the protocol field is always present in the first separator (k=0), and maybe in the rest
        mux_packet[length] = context->protocol[k];
        length ++;

        #ifdef DEBUG
          do_debug_c(2, ANSI_COLOR_RESET, "%02x", context->protocol[k]);
        #endif
      }      
    }
    else {  // fast flavor
      // in fast flavor, always add the protocol
      mux_packet[length] = context->protocol[k];
      length ++;

      #ifdef DEBUG
        do_debug_c(2, ANSI_COLOR_RESET, "%02x", context->protocol[k]);
      #endif
    }
    

    // add the bytes of the packet itself
    memcpy(&mux_packet[length], context->packetsToMultiplex[k], context->sizePacketsToMultiplex[k]);
    length = length + context->sizePacketsToMultiplex[k];
  }
  #ifdef DEBUG
    do_debug(2,"\n");
  #endif

  return length;
}


void sendMultiplexedPacket (struct contextSimplemux* context,
                            uint16_t total_length,
                            uint8_t muxed_packet[BUFSIZE],
                            uint64_t time_difference)
{
  switch (context->mode) {
    case UDP_MODE:
      // send the packet. I don't need to build the header, because I have a UDP socket
      if (sendto( context->udp_mode_fd,
                  muxed_packet, total_length,
                  0,
                  (struct sockaddr *)&(context->remote),
                  sizeof(context->remote)) == -1)
      {
        perror("sendto() in UDP mode failed");
        exit (EXIT_FAILURE);                
      }
      else {
        if(context->tunnelMode == TUN_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed packet(s)). Protocol %d (UDP). Port %d\n\n",
                        context->numPktsStoredFromTun,
                        IPPROTO_UDP, // in UDP mode, I send an UDP packet
                        ntohs(context->remote.sin_port));
          #endif
        }
        else if(context->tunnelMode == TAP_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed frame(s)). Protocol %d (UDP). Port %d\n\n",
                        context->numPktsStoredFromTun,
                        IPPROTO_UDP, // in UDP mode, I send an UDP packet
                        ntohs(context->remote.sin_port));
          #endif                  
        }
        else {
          perror ("wrong value of 'tunnelMode'");
          exit (EXIT_FAILURE);
        }
      }
    break;
    
    case NETWORK_MODE: ;
      // build the header
      struct iphdr ipheader;
      BuildIPHeader(&ipheader, total_length, context->ipprotocol, context->local, context->remote);

      // build full IP multiplexed packet
      uint8_t full_ip_packet[BUFSIZE];
      BuildFullIPPacket(ipheader, muxed_packet, total_length, full_ip_packet);

      // send the multiplexed packet
      if (sendto (context->network_mode_fd, full_ip_packet, total_length + sizeof(struct iphdr), 0, (struct sockaddr *)&(context->remote), sizeof (struct sockaddr)) < 0)  {
        perror ("sendto() in Network mode failed ");
        exit (EXIT_FAILURE);
      }
      else {
        if(context->tunnelMode == TUN_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed packet(s)). Protocol %d\n\n",
                        context->numPktsStoredFromTun,
                        context->ipprotocol);
          #endif
        }
        else if(context->tunnelMode == TAP_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed frame(s)). Protocol %d\n\n",
                        context->numPktsStoredFromTun,
                        context->ipprotocol);
          #endif
        }
        else {
          perror ("wrong value of 'tunnelMode'");
          exit (EXIT_FAILURE);
        }
      }
    break;
      
    case TCP_CLIENT_MODE:
      // send the packet. I don't need to build the header, because I have a TCP socket
      
      if (write(context->tcp_client_fd, muxed_packet, total_length)==-1) {
        perror("write() in TCP client mode failed");
        exit (EXIT_FAILURE);
      }
      else {
        if(context->tunnelMode == TUN_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed packet(s)). Protocol %d (TCP). Port %d\n\n",
                        context->numPktsStoredFromTun,
                        IPPROTO_TCP, // in TCP mode, I send a TCP packet
                        ntohs(context->remote.sin_port));
          #endif
        }
        else if(context->tunnelMode == TAP_MODE) {
          #ifdef DEBUG
            do_debug_c( 2,
                        ANSI_COLOR_GREEN,
                        " Packet sent (includes %d muxed frame(s)). Protocol %d (TCP). Port %d\n\n",
                        context->numPktsStoredFromTun,
                        IPPROTO_TCP, // in TCP mode, I send a TCP packet
                        ntohs(context->remote.sin_port));
          #endif               
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
      if(context->acceptingTcpConnections == true) {
        #ifdef DEBUG
          do_debug(1," The packet should be sent to the TCP socket. But no client has yet been connected to this server\n");
        #endif
      }
      else {
        if (write(context->tcp_server_fd, muxed_packet, total_length)==-1) {
          perror("write() in TCP server mode failed");
          exit (EXIT_FAILURE);
        }
        else {
          if(context->tunnelMode == TUN_MODE) {
            #ifdef DEBUG
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Packet sent (includes %d muxed packet(s)). Protocol %d (TCP). Port %d\n\n",
                          context->numPktsStoredFromTun,
                          IPPROTO_TCP, // in TCP mode, I send a TCP packet
                          ntohs(context->remote.sin_port));
            #endif
          }
          else if(context->tunnelMode == TAP_MODE) {
            #ifdef DEBUG
              do_debug_c( 2,
                          ANSI_COLOR_GREEN,
                          " Packet sent (includes %d muxed frame(s)). Protocol %d (TCP). Port %d\n\n",
                          context->numPktsStoredFromTun,
                          IPPROTO_TCP, // in TCP mode, I send a TCP packet
                          ntohs(context->remote.sin_port));
            #endif                 
          }
          else {
            perror ("wrong value of 'tunnelMode'");
            exit (EXIT_FAILURE);
          }
        }
      }
    break;
  }

  #ifdef LOGFILE
    // write the log file
    if ( context->log_file != NULL ) {
      switch (context->mode) {
        case UDP_MODE:
          fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i",
            GetTimeStamp(),
            context->sizeMuxedPacket + IPv4_HEADER_SIZE + UDP_HEADER_SIZE,
            context->tun2net,
            inet_ntoa(context->remote.sin_addr),
            ntohs(context->remote.sin_port),
            context->numPktsStoredFromTun);
        break;

        case TCP_CLIENT_MODE:
          fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i",
            GetTimeStamp(),
            context->sizeMuxedPacket + IPv4_HEADER_SIZE + TCP_HEADER_SIZE,
            context->tun2net,
            inet_ntoa(context->remote.sin_addr),
            ntohs(context->remote.sin_port),
            context->numPktsStoredFromTun);
        break;

        case NETWORK_MODE:
          fprintf (context->log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i",
            GetTimeStamp(),
            context->sizeMuxedPacket + IPv4_HEADER_SIZE,
            context->tun2net,
            inet_ntoa(context->remote.sin_addr),
            context->numPktsStoredFromTun);
        break;
      }

      if (context->numPktsStoredFromTun == context->limitNumpackets)
        fprintf(context->log_file, "\tnumpacket_limit");
      if (context->sizeMuxedPacket > context->sizeThreshold)
        fprintf(context->log_file, "\tsize_limit");
      if (time_difference > context->timeout)
        fprintf(context->log_file, "\ttimeout");
      fprintf(context->log_file, "\n");

      // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      fflush(context->log_file);
    }
  #endif
}