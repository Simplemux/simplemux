#include "netToTun.c"

void tunToNetBlastMode (uint32_t tun2net,
                        char mode,
                        char tunnel_mode,
                        int tun_fd,
                        int udp_mode_fd,
                        int network_mode_fd,
                        struct sockaddr_in local,
                        struct sockaddr_in remote,
                        struct packet **packetsToSend,
                        uint64_t* lastHeartBeatReceived )
{
  uint64_t now = GetTimeStamp();

  do_debug(3, "%"PRIu64": Packet arrived from tun\n", now);             

  // add a new empty packet to the list
  struct packet* thisPacket = insertLast(packetsToSend,0,NULL);

  // read the packet from tun_fd and add the data
  // use 'htons()' because these fields will be sent through the network
  thisPacket->header.packetSize = htons(cread (tun_fd, thisPacket->tunneledPacket, BUFSIZE));
  thisPacket->header.identifier = htons((uint16_t)tun2net); // the ID is the 16 LSBs of 'tun2net'

  do_debug(1, "NATIVE PACKET arrived from tun: ID %i, length %i bytes\n", ntohs(thisPacket->header.identifier), ntohs(thisPacket->header.packetSize));

  assert ( SIZE_PROTOCOL_FIELD == 1 );

  if (tunnel_mode == TAP_MODE) {
    thisPacket->header.protocolID = IPPROTO_ETHERNET;
  }
  else if (tunnel_mode == TUN_MODE) {
    thisPacket->header.protocolID = IPPROTO_IP_ON_IP;
  }

  // this packet will require an ACK
  thisPacket->header.ACK = ACKNEEDED;

  // send the packet to the network
  int fd;
  if(mode==UDP_MODE)
    fd = udp_mode_fd;
  else if(mode==NETWORK_MODE)
    fd = network_mode_fd;
  sendPacketBlastMode( fd, mode, thisPacket, remote, local);
  do_debug(1, " Sent blast packet to the network. ID %i, Length %i\n", ntohs(thisPacket->header.identifier), ntohs(thisPacket->header.packetSize));

  /*
  // write in the log file
  switch (mode) {
    case UDP_MODE:        
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t%d\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE + UDP_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), ntohs(remote.sin_port), num_pkts_stored_from_tun);
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    break;
   
    case NETWORK_MODE:
      if ( log_file != NULL ) {
        fprintf (log_file, "%"PRIu64"\tsent\tmuxed\t%i\t%"PRIu32"\tto\t%s\t\t%i\tMTU\n", GetTimeStamp(), total_length + IPv4_HEADER_SIZE, tun2net, inet_ntoa(remote.sin_addr), num_pkts_stored_from_tun);
        fflush(log_file);  // If the IO is buffered, I have to insert fflush(fp) after the write in order to avoid things lost when pressing
      }
    break;
  }*/

  // the packet has been sent. Store the timestamp
  thisPacket->sentTimestamp = now;

  if(now - (*lastHeartBeatReceived) > HEARTBEATDEADLINE) {
    // heartbeat from the other side not received recently
    if(delete(packetsToSend,ntohs(thisPacket->header.identifier))==false) {
      do_debug(2," The packet had already been removed from the list\n");
    }
    else {
      do_debug(2," Packet with ID %i removed from the list\n", tun2net);
    }              
    do_debug(2, "%"PRIu64" The arrived packet has not been stored because the last heartbeat was received %"PRIu64" us ago. Total %i pkts stored\n", now, now - (*lastHeartBeatReceived), length(packetsToSend));
  }
  else {
    do_debug(2, "%"PRIu64" The arrived packet has been stored. Total %i pkts stored\n", thisPacket->sentTimestamp, length(packetsToSend));
    if(debug > 1)
      dump_packet ( ntohs(thisPacket->header.packetSize), thisPacket->tunneledPacket );              
  }
}