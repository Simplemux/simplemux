//#include "commonfunctions.c"
#include "packetsToSend.c"

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (struct contextSimplemux* context,
                                          int single_prot);

uint16_t build_multiplexed_packet ( struct contextSimplemux* context,
                                    int single_prot,
                                    uint8_t mux_packet[BUFSIZE]);