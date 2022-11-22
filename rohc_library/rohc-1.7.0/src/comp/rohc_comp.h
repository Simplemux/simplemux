/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2013 Friedrich
 * Copyright 2009,2010 Thales Communications
 * Copyright 2007,2009,2010,2012,2013,2014 Viveris Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file rohc_comp.h
 * @brief ROHC compression routines
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_COMP_H
#define ROHC_COMP_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <rohc/rohc.h>
#include <rohc/rohc_packets.h>
#include <rohc/rohc_traces.h>
#include <rohc/rohc_time.h>
#include <rohc/rohc_buf.h>

#include <stdlib.h>
#include <stdint.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif


/** Macro that handles DLL export declarations gracefully */
#ifdef DLL_EXPORT /* passed by autotools on command line */
	#define ROHC_EXPORT __declspec(dllexport)
#else
	#define ROHC_EXPORT 
#endif


/*
 * Declare the private ROHC compressor structure that is defined inside the
 * library.
 */

struct rohc_comp;


/*
 * Public structures and types
 */


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief The different ROHC compressor states
 *
 * The different ROHC operation states at compressor as defined in section
 * 4.3.1 of RFC 3095.
 *
 * If you add a new compressor state, please also add the corresponding
 * textual description in \ref rohc_comp_get_state_descr.
 *
 * @deprecated do not use this type anymore, use \ref rohc_comp_state_t
 *             instead
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_get_state_descr
 */
typedef enum
{
	/** The Initialization and Refresh (IR) compressor state */
	IR = 1,
	/** The First Order (FO) compressor state */
	FO = 2,
	/** The Second Order (SO) compressor state */
	SO = 3,
} rohc_c_state
	ROHC_DEPRECATED("please do not use this type anymore, "
	                "use rohc_comp_state_t instead");

#endif /* !ROHC_ENABLE_DEPRECATED_API) */

/**
 * @brief The different ROHC compressor states
 *
 * The different ROHC operation states at compressor as defined in section
 * 4.3.1 of RFC 3095.
 *
 * If you add a new compressor state, please also add the corresponding
 * textual description in \ref rohc_comp_get_state_descr.
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_get_state_descr
 */
typedef enum
{
	/** The Initialization and Refresh (IR) compressor state */
	ROHC_COMP_STATE_IR = 1,
	/** The First Order (FO) compressor state */
	ROHC_COMP_STATE_FO = 2,
	/** The Second Order (SO) compressor state */
	ROHC_COMP_STATE_SO = 3,

} rohc_comp_state_t;


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Some information about the last compressed packet
 *
 * Non-extensible version of \ref rohc_comp_last_packet_info2_t
 *
 * @deprecated do not use this struct anymore,
 *             use rohc_comp_last_packet_info2_t instead
 *
 * @ingroup rohc_comp
 */
typedef struct
{
	rohc_mode_t context_mode;              /**< Compression mode */
	rohc_comp_state_t context_state;       /**< Compression state */
	rohc_packet_t packet_type;             /**< Packet type */
	unsigned long total_last_uncomp_size;  /**< Uncompressed packet size (bytes) */
	unsigned long header_last_uncomp_size; /**< Uncompressed header size (bytes) */
	unsigned long total_last_comp_size;    /**< Compressed packet size (bytes) */
	unsigned long header_last_comp_size;   /**< Compressed header size (bytes) */

} rohc_comp_last_packet_info_t;

#endif /* !ROHC_ENABLE_DEPRECATED_API */


/**
 * @brief Some information about the last compressed packet
 *
 * The structure is used by the \ref rohc_comp_get_last_packet_info2 function
 * to store some information about the last compressed packet.
 *
 * Versioning works as follow:
 *  - The \e version_major field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The \e version_minor field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_comp_get_last_packet_info2.
 *
 * Notes for developers:
 *  - Increase the major version if a field is removed.
 *  - Increase the major version if a field is added at the beginning or in
 *    the middle of the structure.
 *  - Increase the minor version if a field is added at the very end of the
 *    structure.
 *  - The version_major and version_minor fields must be located at the very
 *    beginning of the structure.
 *  - The structure must be packed.
 *
 * Supported versions:
 *  - Major 0 / Minor 0 contains: version_major, version_minor, context_id,
 *    is_context_init, context_mode, context_state, context_used, profile_id,
 *    packet_type, total_last_uncomp_size, header_last_uncomp_size,
 *    total_last_comp_size, and header_last_comp_size
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_get_last_packet_info2
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The Context ID (CID) */
	unsigned int context_id;
	/** Whether the context was initialized (created/re-used) by the packet */
	bool is_context_init;
	/** The mode of the last context used by the compressor */
	rohc_mode_t context_mode;
	/** The state of the last context used by the compressor */
	rohc_comp_state_t context_state;
	/** Whether the last context used by the compressor is still in use */
	bool context_used;
	/** The profile ID of the last context used by the compressor */
	int profile_id;
	/** The type of ROHC packet created for the last compressed packet */
	rohc_packet_t packet_type;
	/** The uncompressed size (in bytes) of the last compressed packet */
	unsigned long total_last_uncomp_size;
	/** The uncompressed size (in bytes) of the last compressed header */
	unsigned long header_last_uncomp_size;
	/** The compressed size (in bytes) of the last compressed packet */
	unsigned long total_last_comp_size;
	/** The compressed size (in bytes) of the last compressed header */
	unsigned long header_last_comp_size;
} __attribute__((packed)) rohc_comp_last_packet_info2_t;


/**
 * @brief Some general information about the compressor
 *
 * The structure is used by the \ref rohc_comp_get_general_info function
 * to store some general information about the compressor.
 *
 * Versioning works as follow:
 *  - The \e version_major field defines the compatibility level. If the major
 *    number given by user does not match the one expected by the library,
 *    an error is returned.
 *  - The \e version_minor field defines the extension level. If the minor
 *    number given by user does not match the one expected by the library,
 *    only the fields supported in that minor version will be filled by
 *    \ref rohc_comp_get_general_info.
 *
 * Notes for developers:
 *  - Increase the major version if a field is removed.
 *  - Increase the major version if a field is added at the beginning or in
 *    the middle of the structure.
 *  - Increase the minor version if a field is added at the very end of the
 *    structure.
 *  - The version_major and version_minor fields must be located at the very
 *    beginning of the structure.
 *  - The structure must be packed.
 *
 * Supported versions:
 *  - major 0 and minor = 0 contains: version_major, version_minor,
 *    contexts_nr, packets_nr, uncomp_bytes_nr, and comp_bytes_nr.
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_get_general_info
 */
typedef struct
{
	/** The major version of this structure */
	unsigned short version_major;
	/** The minor version of this structure */
	unsigned short version_minor;
	/** The number of contexts used by the compressor */
	size_t contexts_nr;
	/** The number of packets processed by the compressor */
	unsigned long packets_nr;
	/** The number of uncompressed bytes received by the compressor */
	unsigned long uncomp_bytes_nr;
	/** The number of compressed bytes produced by the compressor */
	unsigned long comp_bytes_nr;
} __attribute__((packed)) rohc_comp_general_info_t;


/**
 * @brief The different features of the ROHC compressor
 *
 * Features for the ROHC compressor control whether mechanisms defined as
 * optional by RFCs are enabled or not. They can be set or unset with the
 * function \ref rohc_comp_set_features.
 *
 * @ingroup rohc_comp
 *
 * @see rohc_comp_set_features
 */
typedef enum
{
	/** No feature at all */
	ROHC_COMP_FEATURE_NONE            = 0,
	/** Be compatible with 1.6.x versions */
	ROHC_COMP_FEATURE_COMPAT_1_6_x    = (1 << 0),
	/** Do not check IP checksums at compressor */
	ROHC_COMP_FEATURE_NO_IP_CHECKSUMS = (1 << 2),

} rohc_comp_features_t;


/**
 * @brief The prototype of the RTP detection callback
 *
 * User-defined function that is called by the ROHC library for every UDP
 * packet to determine whether the UDP packet transports RTP data. If the
 * function returns true, the RTP profile is used to compress the packet.
 * Otherwise the UDP profile is used.
 *
 * The user-defined function is set by calling the function
 * \ref rohc_comp_set_rtp_detection_cb
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @param rtp_private  A pointer to a memory area to be used by the callback
 *                     function, may be NULL.
 * @return             true if the packet is an RTP packet, false otherwise
 *
 * @see rohc_comp_set_rtp_detection_cb
 * @ingroup rohc_comp
 */
typedef bool (*rohc_rtp_detection_callback_t)(const unsigned char *const ip,
                                              const unsigned char *const udp,
                                              const unsigned char *const payload,
                                              const unsigned int payload_size,
                                              void *const rtp_private)
	__attribute__((warn_unused_result));


/**
 * @brief The prototype of the callback for random numbers
 *
 * User-defined function that is called when the ROHC library requires a random
 * number. Currently, the ROHC library uses it when initializing the Sequence
 * Number (SN) of contexts using the IP-only, IP/UDP, and IP/UDP-Lite profiles.
 *
 * The user-defined function is set by calling the function
 * \ref rohc_comp_set_random_cb
 *
 * @param comp          The ROHC compressor
 * @param user_context  The context given by the user when he/she called the
 *                      rohc_comp_set_random_cb function, may be NULL.
 *
 * @see rohc_comp_set_random_cb
 * @ingroup rohc_comp
 */
typedef int (*rohc_comp_random_cb_t) (const struct rohc_comp *const comp,
                                      void *const user_context)
	__attribute__((warn_unused_result));


/*
 * Prototypes of main public functions related to ROHC compression
 */

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

struct rohc_comp * ROHC_EXPORT rohc_alloc_compressor(int max_cid,
                                                     int jam_use,
                                                     int adapt_size,
                                                     int encap_size)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_new() instead");

void ROHC_EXPORT rohc_free_compressor(struct rohc_comp *comp)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_free() instead");

struct rohc_comp * ROHC_EXPORT rohc_comp_new(const rohc_cid_type_t cid_type,
                                             const rohc_cid_t max_cid)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_new2() instead");

#endif /* !ROHC_ENABLE_DEPRECATED_API */

struct rohc_comp * ROHC_EXPORT rohc_comp_new2(const rohc_cid_type_t cid_type,
                                              const rohc_cid_t max_cid,
                                              const rohc_comp_random_cb_t rand_cb,
                                              void *const rand_priv)
	__attribute__((warn_unused_result));

void ROHC_EXPORT rohc_comp_free(struct rohc_comp *const comp);

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

bool ROHC_EXPORT rohc_comp_set_traces_cb(struct rohc_comp *const comp,
                                         rohc_trace_callback_t callback)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_set_traces_cb2() instead");

#endif /* !ROHC_ENABLE_DEPRECATED_API */

bool ROHC_EXPORT rohc_comp_set_traces_cb2(struct rohc_comp *const comp,
                                          rohc_trace_callback2_t callback,
                                          void *const priv_ctxt)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

bool ROHC_EXPORT rohc_comp_set_random_cb(struct rohc_comp *const comp,
                                         rohc_comp_random_cb_t callback,
                                         void *const user_context)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_new2() instead");

int ROHC_EXPORT rohc_compress(struct rohc_comp *comp,
                              unsigned char *ibuf,
                              int isize,
                              unsigned char *obuf,
                              int osize)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_compress4() instead");

int ROHC_EXPORT rohc_compress2(struct rohc_comp *const comp,
                               const unsigned char *const uncomp_packet,
                               const size_t uncomp_packet_len,
                               unsigned char *const rohc_packet,
                               const size_t rohc_packet_max_len,
                               size_t *const rohc_packet_len)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_compress4() instead");

int ROHC_EXPORT rohc_compress3(struct rohc_comp *const comp,
                               const struct rohc_ts arrival_time,
                               const unsigned char *const uncomp_packet,
                               const size_t uncomp_packet_len,
                               unsigned char *const rohc_packet,
                               const size_t rohc_packet_max_len,
                               size_t *const rohc_packet_len)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_compress4() instead");

#endif /* !ROHC_ENABLE_DEPRECATED_API */

rohc_status_t ROHC_EXPORT rohc_compress4(struct rohc_comp *const comp,
                                         const struct rohc_buf uncomp_packet,
                                         struct rohc_buf *const rohc_packet)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
int ROHC_EXPORT rohc_comp_get_segment(struct rohc_comp *const comp,
                                      unsigned char *const segment,
                                      const size_t max_len,
                                      size_t *const len)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_segment2() instead");
#endif /* !ROHC_ENABLE_DEPRECATED_API */

rohc_status_t ROHC_EXPORT rohc_comp_get_segment2(struct rohc_comp *const comp,
                                                 struct rohc_buf *const segment)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_force_contexts_reinit(struct rohc_comp *const comp)
	__attribute__((warn_unused_result));


/*
 * Prototypes of public functions related to user interaction
 */

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
int ROHC_EXPORT rohc_c_is_enabled(struct rohc_comp *comp)
	ROHC_DEPRECATED("do not use this function anymore, the ROHC compressor "
	                "shall be considered always enabled now");
int ROHC_EXPORT rohc_c_using_small_cid(struct rohc_comp *comp)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_cid_type() instead");
#endif

bool ROHC_EXPORT rohc_comp_profile_enabled(const struct rohc_comp *const comp,
                                           const rohc_profile_t profile)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_activate_profile(struct rohc_comp *comp, int profile)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_enable_profile() instead");
#endif /* !ROHC_ENABLE_DEPRECATED_API */
bool ROHC_EXPORT rohc_comp_enable_profile(struct rohc_comp *const comp,
                                          const rohc_profile_t profile)
	__attribute__((warn_unused_result));
bool ROHC_EXPORT rohc_comp_disable_profile(struct rohc_comp *const comp,
                                           const rohc_profile_t profile)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_enable_profiles(struct rohc_comp *const comp,
                                           ...)
	__attribute__((warn_unused_result));
bool ROHC_EXPORT rohc_comp_disable_profiles(struct rohc_comp *const comp,
                                           ...)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_c_set_header(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("do not use this function anymore, "
	                "simply remove it from your code");
#endif

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_c_set_mrru(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_set_mrru() instead");
#endif /* !ROHC_ENABLE_DEPRECATED_API */
bool ROHC_EXPORT rohc_comp_set_mrru(struct rohc_comp *const comp,
                                    const size_t mrru)
	__attribute__((warn_unused_result));
bool ROHC_EXPORT rohc_comp_get_mrru(const struct rohc_comp *const comp,
                                    size_t *const mrru)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_c_set_max_cid(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("please do not use this function anymore, use the "
	                "parameter max_cid of rohc_comp_new() instead");
#endif
bool ROHC_EXPORT rohc_comp_get_max_cid(const struct rohc_comp *const comp,
                                       size_t *const max_cid)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_c_set_large_cid(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("please do not use this function anymore, use the "
	                "parameter cid_type of rohc_comp_new() instead");
#endif
bool ROHC_EXPORT rohc_comp_get_cid_type(const struct rohc_comp *const comp,
                                        rohc_cid_type_t *const cid_type)
	__attribute__((warn_unused_result));

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT rohc_c_set_enable(struct rohc_comp *compressor, int value)
	ROHC_DEPRECATED("do not use this function anymore, the ROHC compressor "
	                "shall be considered always enabled now");
#endif

/* RTP stream detection through UDP ports */
bool ROHC_EXPORT rohc_comp_add_rtp_port(struct rohc_comp *const comp,
                                        const unsigned int port)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_set_rtp_detection_cb() instead");
bool ROHC_EXPORT rohc_comp_remove_rtp_port(struct rohc_comp *const comp,
                                           const unsigned int port)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_set_rtp_detection_cb() instead");
bool ROHC_EXPORT rohc_comp_reset_rtp_ports(struct rohc_comp *const comp)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("do not use this function anymore, "
	                "use rohc_comp_set_rtp_detection_cb() instead");

/* RTP stream detection through callback */
bool ROHC_EXPORT rohc_comp_set_rtp_detection_cb(struct rohc_comp *const comp,
                                                rohc_rtp_detection_callback_t callback,
                                                void *const rtp_private)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_set_features(struct rohc_comp *const comp,
                                        const rohc_comp_features_t features)
	__attribute__((warn_unused_result));



/*
 * Prototypes of public functions related to ROHC feedback
 */

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
void ROHC_EXPORT c_piggyback_feedback(struct rohc_comp *comp,
                                      unsigned char *packet,
                                      int size)
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and prepend feedback data yourself");
bool ROHC_EXPORT __rohc_comp_piggyback_feedback(struct rohc_comp *const comp,
                                                const unsigned char *const feedback,
                                                const size_t size)
	__attribute__((warn_unused_result));
bool ROHC_EXPORT rohc_comp_piggyback_feedback(struct rohc_comp *const comp,
                                              const unsigned char *const feedback,
                                              const size_t size)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and prepend feedback data yourself");
void ROHC_EXPORT c_deliver_feedback(struct rohc_comp *comp,
                                    unsigned char *feedback,
                                    int size)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_deliver_feedback2() instead");
bool ROHC_EXPORT __rohc_comp_deliver_feedback(struct rohc_comp *const comp,
                                              const uint8_t *const feedback,
                                              const size_t size)
	__attribute__((warn_unused_result));
bool ROHC_EXPORT rohc_comp_deliver_feedback(struct rohc_comp *const comp,
                                            const uint8_t *const feedback,
                                            const size_t size)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_deliver_feedback2() instead");
#endif /* !ROHC_ENABLE_DEPRECATED_API */
bool ROHC_EXPORT rohc_comp_deliver_feedback2(struct rohc_comp *const comp,
                                             const struct rohc_buf feedback)
	__attribute__((warn_unused_result));
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
int ROHC_EXPORT rohc_feedback_flush(struct rohc_comp *comp,
                                    unsigned char *obuf,
                                    int osize)
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and send feedback data yourself");
size_t ROHC_EXPORT rohc_feedback_avail_bytes(const struct rohc_comp *const comp)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and handle feedback data yourself");
bool ROHC_EXPORT rohc_feedback_remove_locked(struct rohc_comp *const comp)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and handle feedback data yourself");
bool ROHC_EXPORT rohc_feedback_unlock(struct rohc_comp *const comp)
	__attribute__((warn_unused_result))
	ROHC_DEPRECATED("please do not use this function anymore, instead use "
	                "rohc_decompress3() and handle feedback data yourself");
#endif /* !ROHC_ENABLE_DEPRECATED_API */


/*
 * Prototypes of public functions that configure robustness to packet
 * loss/damage
 */

bool ROHC_EXPORT rohc_comp_set_wlsb_window_width(struct rohc_comp *const comp,
                                                 const size_t width)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_set_periodic_refreshes(struct rohc_comp *const comp,
																  const size_t ir_timeout,
																  const size_t fo_timeout)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_set_list_trans_nr(struct rohc_comp *const comp,
                                             const size_t list_trans_nr)
	__attribute__((warn_unused_result));


/*
 * Prototypes of public functions related to ROHC compression statistics
 */

#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
int ROHC_EXPORT rohc_c_info(char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_c_statistics(struct rohc_comp *comp,
                                  unsigned int indent,
                                  char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_c_context(struct rohc_comp *comp,
                               int cid,
                               unsigned int indent,
                               char *buffer)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_general_info() instead");
int ROHC_EXPORT rohc_comp_get_last_packet_info(const struct rohc_comp *const comp,
                                               rohc_comp_last_packet_info_t *const info)
	ROHC_DEPRECATED("please do not use this function anymore, "
	                "use rohc_comp_get_last_packet_info2() instead");
#endif /* !ROHC_ENABLE_DEPRECATED_API */

bool ROHC_EXPORT rohc_comp_get_general_info(const struct rohc_comp *const comp,
                                            rohc_comp_general_info_t *const info)
	__attribute__((warn_unused_result));

bool ROHC_EXPORT rohc_comp_get_last_packet_info2(const struct rohc_comp *const comp,
                                                 rohc_comp_last_packet_info2_t *const info);

const char * ROHC_EXPORT rohc_comp_get_state_descr(const rohc_comp_state_t state);


#undef ROHC_EXPORT /* do not pollute outside this header */

#ifdef __cplusplus
}
#endif

#endif /* ROHC_COMP_H */

