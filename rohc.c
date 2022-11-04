#include "socketRequest.c"

static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
  return rand();
}

/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level    The priority level of the trace
 * @param entity  The entity that emitted the trace among:
 *          \li ROHC_TRACE_COMP
 *          \li ROHC_TRACE_DECOMP
 * @param profile  The ID of the ROHC compression/decompression profile
 *          the trace is related to
 * @param format  The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
  // Only prints ROHC messages if debug level is > 2
  if ( debug > 2 ) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
  }
}


/**
 * @brief The RTP detection callback which does detect RTP stream.
 * it assumes that UDP packets belonging to certain ports are RTP packets
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rtp_detect( const uint8_t *const ip __attribute__((unused)),
                        const uint8_t *const udp,
                        const uint8_t *const payload __attribute__((unused)),
                        const unsigned int payload_size __attribute__((unused)),
                        void *const rtp_private __attribute__((unused)))
{
  const size_t default_rtp_ports_nr = 5;
  unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
  uint16_t udp_dport;
  bool is_rtp = false;
  size_t i;

  if (udp == NULL) {
    return false;
  }

  /* get the UDP destination port */
  memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

  /* is the UDP destination port in the list of ports reserved for RTP
   * traffic by default (for compatibility reasons) */
  for(i = 0; i < default_rtp_ports_nr; i++) {
    if(ntohs(udp_dport) == default_rtp_ports[i]) {
      is_rtp = true;
      break;
    }
  }
  return is_rtp;
}


int initRohc( struct contextSimplemux* context )
{
  if ( context->rohcMode > 0 ) {

    /* initialize the random generator */
    seed = time(NULL);
    srand(seed);
    
    /* Create a ROHC compressor with Large CIDs and the largest MAX_CID
     * possible for large CIDs */
    compressor = rohc_comp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, gen_random_num, NULL);
    if(compressor == NULL) {
      fprintf(stderr, "failed to create the ROHC compressor\n");
      /*fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
      if ( context->log_file != NULL )
        fclose (context->log_file);
      return 1;*/
      goto error;
    }
    
    do_debug(1, "ROHC compressor created. Profiles: ");
    
    // Set the callback function to be used for detecting RTP.
    // RTP is not detected automatically. So you have to create a callback function "rtp_detect" where you specify the conditions.
    // In our case we will consider as RTP the UDP packets belonging to certain ports
    if(!rohc_comp_set_rtp_detection_cb(compressor, rtp_detect, NULL)) {
      fprintf(stderr, "failed to set RTP detection callback\n");
      /*fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
      if ( context->log_file != NULL )
        fclose (context->log_file);
      return 1;*/
      goto error;
    }

    // set the function that will manage the ROHC compressing traces (it will be 'print_rohc_traces')
    if(!rohc_comp_set_traces_cb2(compressor, print_rohc_traces, NULL)) {
      fprintf(stderr, "failed to set the callback for traces on compressor\n");
      goto release_compressor;
    }

    /* Enable the ROHC compression profiles */
    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_UNCOMPRESSED)) {
      fprintf(stderr, "failed to enable the Uncompressed compression profile\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "Uncompressed. ");
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP)) {
      fprintf(stderr, "failed to enable the IP-only compression profile\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "IP-only. ");
    }

    if(!rohc_comp_enable_profiles(compressor, ROHC_PROFILE_UDP, ROHC_PROFILE_UDPLITE, -1)) {
      fprintf(stderr, "failed to enable the IP/UDP and IP/UDP-Lite compression profiles\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "IP/UDP. IP/UDP-Lite. ");
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_RTP)) {
      fprintf(stderr, "failed to enable the RTP compression profile\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "RTP (UDP ports 1234, 36780, 33238, 5020, 5002). ");
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_ESP)) {
      fprintf(stderr, "failed to enable the ESP compression profile\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "ESP. ");
    }

    if(!rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP)) {
      fprintf(stderr, "failed to enable the TCP compression profile\n");
      goto release_compressor;
    }
    else {
      do_debug(1, "TCP. ");
    }
    do_debug(1, "\n");


    /* Create a ROHC decompressor to operate:
    *  - with large CIDs use ROHC_LARGE_CID, ROHC_LARGE_CID_MAX
    *  - with small CIDs use ROHC_SMALL_CID, ROHC_SMALL_CID_MAX maximum of 5 streams (MAX_CID = 4),
    *  - ROHC_O_MODE: Bidirectional Optimistic mode (O-mode)
    *  - ROHC_U_MODE: Unidirectional mode (U-mode).    */
    if ( context->rohcMode == 1 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);  // Unidirectional mode
    }
    else if ( context->rohcMode == 2 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_O_MODE);  // Bidirectional Optimistic mode
    }
    /*else if ( context->rohcMode == 3 ) {
      decompressor = rohc_decomp_new2 (ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_R_MODE);  // Bidirectional Reliable mode (not implemented yet)
    }*/

    if(decompressor == NULL)
    {
      fprintf(stderr, "failed create the ROHC decompressor\n");
      goto release_decompressor;
    }

    do_debug(1, "ROHC decompressor created. Profiles: ");

    // set the function that will manage the ROHC decompressing traces (it will be 'print_rohc_traces')
    if(!rohc_decomp_set_traces_cb2(decompressor, print_rohc_traces, NULL)) {
      fprintf(stderr, "failed to set the callback for traces on decompressor\n");
      goto release_decompressor;
    }

    // enable rohc decompression profiles
    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UNCOMPRESSED, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the Uncompressed decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "Uncompressed. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_IP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the IP-only decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "IP-only. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the IP/UDP decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "IP/UDP. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_UDPLITE, -1);
    if(!status)
    {
      fprintf(stderr, "failed to enable the IP/UDP-Lite decompression profile\n");
      goto release_decompressor;
    } else {
      do_debug(1, "IP/UDP-Lite. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_RTP, -1);
    if(!status)  {
      fprintf(stderr, "failed to enable the RTP decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "RTP. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_ESP,-1);
    if(!status)  {
    fprintf(stderr, "failed to enable the ESP decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "ESP. ");
    }

    status = rohc_decomp_enable_profiles(decompressor, ROHC_PROFILE_TCP, -1);
    if(!status) {
      fprintf(stderr, "failed to enable the TCP decompression profile\n");
      goto release_decompressor;
    }
    else {
      do_debug(1, "TCP. ");
    }

    do_debug(1, "\n");
  }

  return 1;

  /******* labels ************/
  release_compressor:
    rohc_comp_free(compressor);
    return -1;

  release_decompressor:
    rohc_decomp_free(decompressor);
    return -1;
  
  error:
    fprintf(stderr, "an error occurred during program execution, "
      "abort program\n");
    if ( context->log_file != NULL )
      fclose (context->log_file);
    return -1;
}