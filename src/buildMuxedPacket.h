// header guard: avoids problems if this file is included twice
#ifndef BUILDMUXEDPACKET_H
#define BUILDMUXEDPACKET_H

#ifdef USINGROHC
  #include <rohc/rohc.h>          // for using header compression
  #include <rohc/rohc_comp.h>
  #include <rohc/rohc_decomp.h>
#endif

#include "packetsToSend.h"

uint16_t buildMultiplexedPacket ( contextSimplemux* context,
                                  int single_prot,
                                  uint8_t mux_packet[BUFSIZE]);

void sendMultiplexedPacket (contextSimplemux* context,
                            uint16_t total_length,
                            uint8_t muxed_packet[BUFSIZE],
                            uint64_t time_difference);

#endif // BUILDMUXEDPACKET_H