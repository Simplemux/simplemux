#include "packetsToSend.c"

// the length of the multiplexed packet is returned by this function
uint16_t predictSizeMultiplexedPacket ( struct contextSimplemux* context,
                                        int single_prot);

uint16_t buildMultiplexedPacket ( struct contextSimplemux* context,
                                  int single_prot,
                                  uint8_t mux_packet[BUFSIZE]);

void sendMultiplexedPacket (struct contextSimplemux* context,
                            uint16_t total_length,
                            uint8_t muxed_packet[BUFSIZE],
                            uint64_t time_difference);