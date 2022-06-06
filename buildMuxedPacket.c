#include "buildMuxedPacket.h"

/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//  - prot[MAXPKTS][SIZE_PROTOCOL_FIELD]  the protocol byte of each packet
//  - size_separators_to_mux[MAXPKTS]     the size of each separator (1 or 2 bytes). Protocol byte not included
//  - separators_to_mux[MAXPKTS][2]       the separators
//  - size_packets_to_mux[MAXPKTS]        the size of each packet to be multiplexed
//  - packets_to_mux[MAXPKTS][BUFSIZE]    the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (int num_packets,
                                          bool fast_mode,
                                          int single_prot,
                                          uint8_t prot[MAXPKTS][SIZE_PROTOCOL_FIELD],
                                          uint16_t size_separators_to_mux[MAXPKTS],
                                          uint8_t separators_to_mux[MAXPKTS][3],
                                          uint16_t size_packets_to_mux[MAXPKTS],
                                          uint8_t packets_to_mux[MAXPKTS][BUFSIZE])
{
  int k;
  int length = 0;

  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;

  if (!fast_mode) {
    // for each packet, read the protocol field (if present), the separator and the packet itself
    for (k = 0; k < num_packets ; k++) {

      // count the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {    // the protocol field is always present in the first separator (k=0), and maybe in the rest
        length = length + SIZE_PROTOCOL_FIELD;
      }
    
      // count the separator
      length = length + size_separators_to_mux[k];

      // count the bytes of the packet itself
      length = length + size_packets_to_mux[k];
    }    
  }
  else { // fast mode
    // count the separator and the protocol field
    length = length + (num_packets * size_separator_fast_mode);

    // for each packet, add the length of the packet itself
    for (k = 0; k < num_packets ; k++) {
      // count the bytes of the packet itself
      length = length + size_packets_to_mux[k];
    }       
  }

  return length;
}