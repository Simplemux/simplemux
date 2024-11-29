// header guard: avoids problems if this file is included twice
#ifndef NETTOTUN_H
#define NETTOTUN_H

#include "buildMuxedPacket.h"

int readPacketFromNet(contextSimplemux* context,
                      uint8_t* buffer_from_net,
                      int* nread_from_net,
                      uint16_t* packet_length );

int demuxBundleFromNet( contextSimplemux* context,
                        int nread_from_net,
                        uint16_t packet_length,
                        uint8_t* buffer_from_net,
                        rohc_status_t* status );

#endif  // NETTOTUN_H