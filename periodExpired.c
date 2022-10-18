#include "tunToNet.c"

void periodExpiredBlastMode ( int fd,
                              int mode,
                              uint64_t* time_last_sent_in_microsec,
                              uint64_t period,
                              uint64_t lastHeartBeatReceived,
                              uint64_t* lastHeartBeatSent,
                              struct sockaddr_in local,
                              struct sockaddr_in remote,
                              struct packet *packetsToSend )
{

  // I may be here because of two different causes (both may have been accomplished):
  // - period expired
  // - heartbeat period expired

  uint64_t now_microsec = GetTimeStamp();

  // - period expired
  if(now_microsec - (*time_last_sent_in_microsec) > period) {
    if(now_microsec - lastHeartBeatReceived > HEARTBEATDEADLINE) {
      // heartbeat from the other side not received recently
      do_debug(2, " Period expired. But nothing is sent because the last heartbeat was received %"PRIu64" us ago\n", now_microsec - lastHeartBeatReceived);
    }
    else {
      // heartbeat from the other side received recently
      int n = sendExpiredPackects(packetsToSend,
                                  now_microsec,
                                  period,
                                  fd,
                                  mode,
                                  remote,
                                  local);
      if(n>0)
        do_debug(1, " Period expired: Sent %d blast packets (copies) at the end of the period\n", n);
      else
        do_debug(2, " Period expired: Nothing to send\n");            
    }            
  }

  // heartbeat period expired: send a heartbeat to the other side
  if(now_microsec - (*lastHeartBeatSent) > HEARTBEATPERIOD) {
    struct packet heartBeat;
    heartBeat.header.packetSize = 0;
    heartBeat.header.protocolID = 0;
    heartBeat.header.identifier = 0;
    heartBeat.header.ACK = HEARTBEAT;
    
    sendPacketBlastMode(fd,
                        mode,
                        &heartBeat,
                        remote,
                        local);

    do_debug(1," Sent blast heartbeat to the network: %"PRIu64" > %"PRIu64"\n", now_microsec - (*lastHeartBeatSent), HEARTBEATPERIOD);
    (*lastHeartBeatSent) = now_microsec;          
  }
  else {
    do_debug(2," Not sending blast heartbeat to the network: %"PRIu64" < %"PRIu64"\n", now_microsec - (*lastHeartBeatSent), HEARTBEATPERIOD);
  }
}