#include "buildMuxedPacket.h"

/**************************************************************************
 *       predict the size of the multiplexed packet                       *
 **************************************************************************/
// it takes all the variables where packets are stored, and predicts the size of a multiplexed packet including all of them
// the variables are:
//  - context->protocol[MAXPKTS][SIZE_PROTOCOL_FIELD]    the protocol byte of each packet
//  - context->size_separators_to_multiplex[MAXPKTS]     the size of each separator (1 or 2 bytes). Protocol byte not included
//  - context->separators_to_multiplex[MAXPKTS][2]       the separators
//  - context->size_packets_to_multiplex[MAXPKTS]        the size of each packet to be multiplexed
//  - context->packets_to_multiplex[MAXPKTS][BUFSIZE]    the packet to be multiplexed

// the length of the multiplexed packet is returned by this function
uint16_t predict_size_multiplexed_packet (struct contextSimplemux* context,
                                          int single_prot)
{
  // only used in normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  int length = 0;

  int size_separator_fast_mode = SIZE_PROTOCOL_FIELD + SIZE_LENGTH_FIELD_FAST_MODE;

  if (context->flavor == 'N') {
    // normal flavor

    // for each packet, read the protocol field (if present), the separator and the packet itself
    for (int k = 0; k < context->num_pkts_stored_from_tun ; k++) {

      // count the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {    // the protocol field is always present in the first separator (k=0), and maybe in the rest
        length = length + SIZE_PROTOCOL_FIELD;
      }
    
      // count the separator
      length = length + context->size_separators_to_multiplex[k];

      // count the bytes of the packet itself
      length = length + context->size_packets_to_multiplex[k];
    }    
  }
  else {
    // fast flavor

    // count the separator and the protocol field
    length = length + (context->num_pkts_stored_from_tun * size_separator_fast_mode);

    // for each packet, add the length of the packet itself
    for (int k = 0; k < context->num_pkts_stored_from_tun ; k++) {
      // count the bytes of the packet itself
      length = length + context->size_packets_to_multiplex[k];
    }       
  }

  return length;
}


/**************************************************************************
 *                   build the multiplexed packet                         *
 **************************************************************************/
// it takes all the variables where packets are stored, and builds a multiplexed packet
// the variables are:
//  - context->protocol[MAXPKTS][SIZE_PROTOCOL_FIELD]    the protocol byte of each packet
//  - context->size_separators_to_multiplex[MAXPKTS]     the size of each separator (1 or 2 bytes). Protocol byte not included
//  - context->separators_to_multiplex[MAXPKTS][2]       the separators
//  - context->size_packets_to_multiplex[MAXPKTS]        the size of each packet to be multiplexed
//  - context->packets_to_multiplex[MAXPKTS][BUFSIZE]    the packet to be multiplexed

// the multiplexed packet is stored in mux_packet[BUFSIZE]
// the length of the multiplexed packet is returned by this function
uint16_t build_multiplexed_packet ( struct contextSimplemux* context,
                                    int single_prot,
                                    uint8_t mux_packet[BUFSIZE])
{
  int length = 0;

  // for each packet, write the protocol field (if required), the separator and the packet itself
  for (int k = 0; k < context->num_pkts_stored_from_tun ; k++) {

    #ifdef DEBUG
      if (k == 0)
        // add a tab before the first separator
        do_debug(2, "   Separators: ");
      else
        // add a semicolon before the 2nd and subsequent separators
        do_debug(2, "; ");
        
      do_debug(2, "#%d: ", k+1);
      
      // add the separator
      do_debug(2, "0x");
    #endif

    for (int l = 0; l < context->size_separators_to_multiplex[k] ; l++) {
      #ifdef DEBUG
        do_debug(2, "%02x", context->separators_to_multiplex[k][l]);
      #endif

      mux_packet[length] = context->separators_to_multiplex[k][l];
      length ++;
    }

    if (context->flavor == 'N') {
      // add the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {    // the protocol field is always present in the first separator (k=0), and maybe in the rest
        for (int m = 0; m < SIZE_PROTOCOL_FIELD ; m++ ) {
          mux_packet[length] = context->protocol[k][m];
          length ++;
        }
        #ifdef DEBUG
          //do_debug(2, "Protocol field: %02x ", context->protocol[k][0]);
          do_debug(2, "%02x", context->protocol[k][0]);
        #endif
      }      
    }
    else {  // fast mode
      // in fast mode, I always add the protocol
      for (int m = 0; m < SIZE_PROTOCOL_FIELD ; m++ ) {
        mux_packet[length] = context->protocol[k][m];
        length ++;
      }
      #ifdef DEBUG
        //do_debug(2, "Protocol field: %02x ", context->protocol[k][0]);
        do_debug(2, "%02x", context->protocol[k][0]);
      #endif
    }
    
    // add the bytes of the packet itself
    for (int l = 0; l < context->size_packets_to_multiplex[k] ; l++) {
      mux_packet[length] = context->packets_to_multiplex[k][l];
      length ++;
    }
  }
  #ifdef DEBUG
    do_debug(2,"\n");
  #endif

  return length;
}