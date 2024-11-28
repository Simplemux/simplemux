// header guard: avoids problems if this file is included twice
#ifndef BUILDMUXEDPACKET_H
#define BUILDMUXEDPACKET_H

#include <rohc/rohc.h>          // for using header compression
#include <rohc/rohc_comp.h>
#include <rohc/rohc_decomp.h>

#include "packetsToSend.h"


// the length of the multiplexed packet is returned by this function
uint16_t predictSizeMultiplexedPacket ( contextSimplemux* context,
                                        int single_prot);

uint16_t buildMultiplexedPacket ( contextSimplemux* context,
                                  int single_prot,
                                  uint8_t mux_packet[BUFSIZE]);

void sendMultiplexedPacket (contextSimplemux* context,
                            uint16_t total_length,
                            uint8_t muxed_packet[BUFSIZE],
                            uint64_t time_difference);

#endif // BUILDMUXEDPACKET_H