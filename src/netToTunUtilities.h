// header guard: avoids problems if this file is included twice
#ifndef NETTOTUNUTILITIES_H
#define NETTOTUNUTILITIES_H

#include "blastPackets.h"

#ifdef DEBUG
  void showDebugInfoFromNet(contextSimplemux* context,
                            int nread_from_net);
#endif

#ifdef LOGFILE
  void logInfoFromNet(contextSimplemux* context,
                      int nread_from_net,
                      uint8_t* buffer_from_net);
#endif

void demuxPacketBlast(contextSimplemux* context,
                      int nread_from_net,
                      uint8_t* buffer_from_net);

int demuxPacketNormal(contextSimplemux* context,
                      uint8_t* buffer_from_net,
                      int* position,
                      int num_demuxed_packets,
                      int* first_header_read,
                      int *single_protocol_rec,
                      int *LXT_first_byte,
                      int *maximum_packet_length);

int demuxPacketFast(contextSimplemux* context,
                    uint16_t bundleLength,
                    uint8_t* buffer_from_net,
                    int* position,
                    int num_demuxed_packets);

void sendPacketToTun (contextSimplemux* context,
                      uint8_t* demuxed_packet,
                      int demuxedPacketLength);

#ifdef USINGROHC
  int decompressRohcPacket( contextSimplemux* context,
                            uint8_t* demuxed_packet,
                            int* demuxedPacketLength,
                            rohc_status_t* status,
                            int nread_from_net);
#endif

#endif