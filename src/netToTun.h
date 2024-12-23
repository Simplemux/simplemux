// header guard: avoids problems if this file is included twice
#ifndef NETTOTUN_H
#define NETTOTUN_H

#include "netToTunUtilities.h"

int readPacketFromNet(contextSimplemux* context,
                      uint8_t* buffer_from_net,
                      int* nread_from_net,
                      uint16_t* packet_length );

#ifdef USINGROHC
int demuxBundleFromNet( contextSimplemux* context,
                        int nread_from_net,
                        uint16_t bundleLength,
                        uint8_t* buffer_from_net,
                        rohc_status_t* status);
#else
int demuxBundleFromNet( contextSimplemux* context,
                        int nread_from_net,
                        uint16_t bundleLength,
                        uint8_t* buffer_from_net);
#endif

#endif  // NETTOTUN_H