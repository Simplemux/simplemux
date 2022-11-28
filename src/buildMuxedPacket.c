#include "buildMuxedPacket.h"

// it takes all the variables where packets are stored, and predicts the
//size of a multiplexed packet including all of them
// 'single_prot': if all the packets belong to the same protocol
// returns: the length of the multiplexed packet
uint16_t predictSizeMultiplexedPacket ( struct contextSimplemux* context,
                                        int single_prot)
{
  // only used in normal or fast flavor
  #ifdef ASSERT
    assert( (context->flavor == 'N') || (context->flavor == 'F') ) ;
  #endif

  int length = 0;

  if (context->flavor == 'N') {
    // normal flavor

    // for each packet, read the protocol field (if present), the separator and the packet itself
    for (int k = 0; k < context->numPktsStoredFromTun ; k++) {

      // count the 'Protocol' field if necessary
      if ( ( k == 0 ) || ( single_prot == 0 ) ) {
        // the protocol field is always present in the first separator (k=0), and maybe in the rest
        length = length + 1;  // the protocol field is 1 byte long
      }
    
      // count the separator
      length = length + context->sizeSeparatorsToMultiplex[k];

      // count the bytes of the packet itself
      length = length + context->sizePacketsToMultiplex[k];
    }    
  }
  else {
    // fast flavor

    // the separator is always the same size: 'sizeSeparatorFastMode'
    length = length + (context->numPktsStoredFromTun * context->sizeSeparatorFastMode);

    // for each packet, add the length of the packet itself
    for (int k = 0; k < context->numPktsStoredFromTun ; k++) {
      // count the bytes of the packet itself
      length = length + context->sizePacketsToMultiplex[k];
    }       
  }

  return length;
}



// it takes all the variables where packets are stored, and builds a multiplexed packet
// 'single_prot': if all the packets belong to the same protocol
// the multiplexed packet is stored in 'mux_packet'
// returns: the length of the multiplexed packet
uint16_t buildMultiplexedPacket ( struct contextSimplemux* context,
                                  int single_prot,
                                  uint8_t mux_packet[BUFSIZE])
{
  int length = 0;

  // for each packet, write
  // - the protocol field (if required)
  // - the separator
  // - the packet itself
  for (int k = 0; k < context->numPktsStoredFromTun ; k++) {

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

    for (int l = 0; l < context->sizeSeparatorsToMultiplex[k] ; l++) {
      #ifdef DEBUG
        do_debug(2, "%02x", context->separatorsToMultiplex[k][l]);
      #endif

      mux_packet[length] = context->separatorsToMultiplex[k][l];
      length ++;
    }

    if (context->flavor == 'N') { // normal flavor
      // add the 'Protocol' field if necessary
      if ( (k==0) || (single_prot == 0 ) ) {
        // the protocol field is always present in the first separator (k=0), and maybe in the rest
        mux_packet[length] = context->protocol[k];
        length ++;

        #ifdef DEBUG
          do_debug(2, "%02x", context->protocol[k]);
        #endif
      }      
    }
    else {  // fast flavor
      // in fast flavor, always add the protocol
      mux_packet[length] = context->protocol[k];
      length ++;

      #ifdef DEBUG
        do_debug(2, "%02x", context->protocol[k]);
      #endif
    }
    
    // add the bytes of the packet itself
    memcpy(&mux_packet[length], context->packetsToMultiplex[k], context->sizePacketsToMultiplex[k]);
    length = length + context->sizePacketsToMultiplex[k];
  }
  #ifdef DEBUG
    do_debug(2,"\n");
  #endif

  return length;
}