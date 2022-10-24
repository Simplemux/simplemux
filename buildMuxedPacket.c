#include "buildMuxedPacket.h"

/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//  - contextSimplemux->protocol[MAXPKTS][SIZE_PROTOCOL_FIELD]    the protocol byte of each packet
//  - contextSimplemux->size_separators_to_multiplex[MAXPKTS]     the size of each separator (1 or 2 bytes). Protocol byte not included
//  - contextSimplemux->separators_to_multiplex[MAXPKTS][2]       the separators
//  - contextSimplemux->size_packets_to_multiplex[MAXPKTS]        the size of each packet to be multiplexed
//  - contextSimplemux->packets_to_multiplex[MAXPKTS][BUFSIZE]    the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (struct context* contextSimplemux,
                                          int single_prot)
{
  int length = 0;

  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;

  if (contextSimplemux->flavor == 'N') {
    // normal flavor

    // for each packet, read the protocol field (if present), the separator and the packet itself
    for (int k = 0; k < contextSimplemux->num_pkts_stored_from_tun ; k++) {

      // count the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {    // the protocol field is always present in the first separator (k=0), and maybe in the rest
        length = length + SIZE_PROTOCOL_FIELD;
      }
    
      // count the separator
      length = length + contextSimplemux->size_separators_to_multiplex[k];

      // count the bytes of the packet itself
      length = length + contextSimplemux->size_packets_to_multiplex[k];
    }    
  }
  else {
    // fast flavor
    assert(contextSimplemux->flavor == 'F');

    // count the separator and the protocol field
    length = length + (contextSimplemux->num_pkts_stored_from_tun * size_separator_fast_mode);

    // for each packet, add the length of the packet itself
    for (int k = 0; k < contextSimplemux->num_pkts_stored_from_tun ; k++) {
      // count the bytes of the packet itself
      length = length + contextSimplemux->size_packets_to_multiplex[k];
    }       
  }

  return length;
}


/**************************************************************************
 *                   build the multiplexed packet                         *
 **************************************************************************/
// it takes all the variables where packets are stored, and builds a multiplexed packet
// the variables are:
//  - contextSimplemux->protocol[MAXPKTS][SIZE_PROTOCOL_FIELD]    the protocol byte of each packet
//  - contextSimplemux->size_separators_to_multiplex[MAXPKTS]     the size of each separator (1 or 2 bytes). Protocol byte not included
//  - contextSimplemux->separators_to_multiplex[MAXPKTS][2]       the separators
//  - contextSimplemux->size_packets_to_multiplex[MAXPKTS]        the size of each packet to be multiplexed
//  - contextSimplemux->packets_to_multiplex[MAXPKTS][BUFSIZE]    the packet to be multiplexed

// the multiplexed packet is stored in mux_packet[BUFSIZE]
// the length of the multiplexed packet is returned by this function
uint16_t build_multiplexed_packet ( struct context* contextSimplemux,
                                    int single_prot,
                                    uint8_t mux_packet[BUFSIZE])
{
  int length = 0;

  // for each packet, write the protocol field (if required), the separator and the packet itself
  for (int k = 0; k < contextSimplemux->num_pkts_stored_from_tun ; k++) {

    if (k == 0)
      // add a tab before the first separator
      do_debug(2, "   Separators: ");
    else
      // add a semicolon before the 2nd and subsequent separators
      do_debug(2, "; ");
      
    do_debug(2, "#%d: ", k+1);
    
    // add the separator
    do_debug(2, "0x");

    for (int l = 0; l < contextSimplemux->size_separators_to_multiplex[k] ; l++) {
      do_debug(2, "%02x", contextSimplemux->separators_to_multiplex[k][l]);
      mux_packet[length] = contextSimplemux->separators_to_multiplex[k][l];
      length ++;
    }

    if (contextSimplemux->flavor == 'N') {
      // add the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {    // the protocol field is always present in the first separator (k=0), and maybe in the rest
        for (int m = 0; m < SIZE_PROTOCOL_FIELD ; m++ ) {
          mux_packet[length] = contextSimplemux->protocol[k][m];
          length ++;
        }
        //do_debug(2, "Protocol field: %02x ", contextSimplemux->protocol[k][0]);
        do_debug(2, "%02x", contextSimplemux->protocol[k][0]);
      }      
    }
    else {  // fast mode
      // in fast mode, I always add the protocol
      for (int m = 0; m < SIZE_PROTOCOL_FIELD ; m++ ) {
        mux_packet[length] = contextSimplemux->protocol[k][m];
        length ++;
      }
      //do_debug(2, "Protocol field: %02x ", contextSimplemux->protocol[k][0]);
      do_debug(2, "%02x", contextSimplemux->protocol[k][0]);
    }
    
    // add the bytes of the packet itself
    for (int l = 0; l < contextSimplemux->size_packets_to_multiplex[k] ; l++) {
      mux_packet[length] = contextSimplemux->packets_to_multiplex[k][l];
      length ++;
    }
  }
  do_debug(2,"\n");
  return length;
}