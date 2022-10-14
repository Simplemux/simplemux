//#include "commonfunctions.c"
#include "packetsToSend.c"

#define MAXPKTS 100             // maximum number of packets to store
#define SIZE_PROTOCOL_FIELD 1   // 1: protocol field of one byte
                                // 2: protocol field of two bytes
#define SIZE_LENGTH_FIELD_FAST_MODE 2   // the length field in fast mode is always two bytes

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (int num_packets,
                                          bool fast_mode,
                                          int single_prot,
                                          uint8_t prot[MAXPKTS][SIZE_PROTOCOL_FIELD],
                                          uint16_t size_separators_to_mux[MAXPKTS],
                                          uint8_t separators_to_mux[MAXPKTS][3],
                                          uint16_t size_packets_to_mux[MAXPKTS],
                                          uint8_t packets_to_mux[MAXPKTS][BUFSIZE]);

uint16_t predictSizeMultiplexedPacket (struct packet* storedPackets);

uint16_t build_multiplexed_packet ( int num_packets,
                                    bool fast_mode,
                                    int single_prot,
                                    uint8_t prot[MAXPKTS][SIZE_PROTOCOL_FIELD],
                                    uint16_t size_separators_to_mux[MAXPKTS],
                                    uint8_t separators_to_mux[MAXPKTS][3],
                                    uint16_t size_packets_to_mux[MAXPKTS],
                                    uint8_t packets_to_mux[MAXPKTS][BUFSIZE],
                                    uint8_t mux_packet[BUFSIZE]);