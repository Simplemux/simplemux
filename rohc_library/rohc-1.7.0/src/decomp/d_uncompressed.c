/*
 * Copyright 2010,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2009,2010,2012,2013 Viveris Technologies
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
 * @file d_uncompressed.c
 * @brief ROHC decompression context for the uncompressed profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp.h"
#include "rohc_decomp_internals.h"
#include "rohc_bit_ops.h"
#include "rohc_traces_internal.h"
#include "crc.h"
#include "rohc_decomp_detect_packet.h" /* for rohc_decomp_packet_is_ir() */

#ifndef __KERNEL__
#	include <string.h>
#endif


/*
 * Prototypes of private functions
 */

static rohc_packet_t uncomp_detect_pkt_type(const struct rohc_decomp_ctxt *const context,
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static rohc_status_t uncomp_decode(struct rohc_decomp *const decomp,
                                   struct rohc_decomp_ctxt *const context,
                                   const struct rohc_buf rohc_packet,
                                   const size_t add_cid_len,
                                   const size_t large_cid_len,
                                   struct rohc_buf *const uncomp_packet,
                                   rohc_packet_t *const packet_type)
	__attribute__((warn_unused_result, nonnull(1, 2, 6, 7)));

static rohc_status_t uncomp_decode_ir(struct rohc_decomp *const decomp,
                                      struct rohc_decomp_ctxt *context,
                                      const struct rohc_buf rohc_packet,
                                      const size_t add_cid_len,
                                      const size_t large_cid_len,
                                      struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 2, 6)));

static rohc_status_t uncomp_decode_normal(struct rohc_decomp_ctxt *context,
                                          const struct rohc_buf rohc_packet,
                                          const size_t large_cid_len,
                                          struct rohc_buf *const uncomp_packet)
	__attribute__((warn_unused_result, nonnull(1, 4)));

static uint32_t uncomp_get_sn(const struct rohc_decomp_ctxt *const context)
	__attribute__((warn_unused_result, nonnull(1), pure));


/*
 * Definitions of private functions
 */

/**
 * @brief Allocate profile-specific data, nothing to allocate for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @return The newly-created generic decompression context
 */
static void * uncomp_new_context(const struct rohc_decomp_ctxt *const context __attribute__((unused)))
{
	return (void *) 1;
}


/**
 * @brief Destroy profile-specific data, nothing to destroy for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 */
static void uncomp_free_context(void *context __attribute__((unused)))
{
}


/**
 * @brief Detect the type of ROHC packet for the Uncompressed profile
 *
 * @param context        The decompression context
 * @param rohc_packet    The ROHC packet
 * @param rohc_length    The length of the ROHC packet
 * @param large_cid_len  The length of the optional large CID field
 * @return               The packet type
 */
static rohc_packet_t uncomp_detect_pkt_type(const struct rohc_decomp_ctxt *const context __attribute__((unused)),
                                            const uint8_t *const rohc_packet,
                                            const size_t rohc_length,
                                            const size_t large_cid_len __attribute__((unused)))
{
	rohc_packet_t type;

	if(rohc_decomp_packet_is_ir(rohc_packet, rohc_length))
	{
		type = ROHC_PACKET_IR;
	}
	else
	{
		type = ROHC_PACKET_NORMAL;
	}

	return type;
}


/**
 * @brief Decode one IR or Normal packet for the Uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param decomp              The ROHC decompressor
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param add_cid_len         The length of the optional Add-CID field
 * @param large_cid_len       The length of the large CID field
 * @param[out] uncomp_packet  The uncompressed packet
 * @param packet_type         IN:  The type of the ROHC packet to parse
 *                            OUT: The type of the parsed ROHC packet
 * @return                    ROHC_STATUS_OK if packet is successfully decoded,
 *                            ROHC_STATUS_MALFORMED if packet is malformed,
 *                            ROHC_STATUS_BAD_CRC if a CRC error occurs
 *                            ROHC_STATUS_ERROR if an error occurs
 */
static rohc_status_t uncomp_decode(struct rohc_decomp *const decomp,
                                   struct rohc_decomp_ctxt *const context,
                                   const struct rohc_buf rohc_packet,
                                   const size_t add_cid_len,
                                   const size_t large_cid_len,
                                   struct rohc_buf *const uncomp_packet,
                                   rohc_packet_t *const packet_type)
{
	rohc_status_t status;

	if((*packet_type) == ROHC_PACKET_IR)
	{
		/* TODO: check dest max size */
		status = uncomp_decode_ir(decomp, context, rohc_packet, add_cid_len,
		                          large_cid_len, uncomp_packet);
	}
	else if((*packet_type) == ROHC_PACKET_NORMAL)
	{
		/* TODO: check dest max size */
		status = uncomp_decode_normal(context, rohc_packet, large_cid_len,
		                              uncomp_packet);
	}
	else
	{
		rohc_decomp_warn(context, "unsupported ROHC packet type %u", *packet_type);
		status = ROHC_STATUS_ERROR;
	}

	return status;
}


/**
 * @brief Decode one IR packet for the Uncompressed profile.
 *
 * @param decomp              The ROHC decompressor
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param add_cid_len         The length of the optional Add-CID field
 * @param large_cid_len       The length of the large CID field
 * @param[out] uncomp_packet  The uncompressed packet
 * @return                    ROHC_STATUS_OK if packet is successfully decoded,
 *                            ROHC_STATUS_MALFORMED if packet is malformed,
 *                            ROHC_STATUS_BAD_CRC if CRC in IR header is wrong
 */
static rohc_status_t uncomp_decode_ir(struct rohc_decomp *const decomp,
                                      struct rohc_decomp_ctxt *context,
                                      const struct rohc_buf rohc_packet,
                                      const size_t add_cid_len,
                                      const size_t large_cid_len,
                                      struct rohc_buf *const uncomp_packet)
{
	/* remaining ROHC data not parsed yet */
	struct rohc_buf rohc_remain_data = rohc_packet;

	/* packet and computed CRCs */
	uint8_t crc_packet;
	uint8_t crc_computed;

	/* ROHC and uncompressed payloads (they are the same) */
	const unsigned char *payload_data;
	unsigned int payload_len;

	/* packet must large enough for:
	 * IR type + (large CID + ) Profile ID + CRC */
	if(rohc_remain_data.len < (1 + large_cid_len + 2))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu bytes)",
		                 rohc_remain_data.len);
		goto error_malformed;
	}

	/* change state to Full Context */
	context->state = ROHC_DECOMP_STATE_FC;

	/* skip the IR type, optional large CID bytes, and Profile ID */
	rohc_buf_pull(&rohc_remain_data, large_cid_len + 2);

	/* parse CRC */
	crc_packet = GET_BIT_0_7(rohc_buf_data(rohc_remain_data));
	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "CRC-8 found in packet = 0x%02x", crc_packet);
	rohc_buf_pull(&rohc_remain_data, 1);

	/* ROHC header is now fully decoded */
	payload_data = rohc_buf_data(rohc_remain_data);
	payload_len = rohc_remain_data.len;

	/* compute header CRC: the CRC covers the first octet of the IR packet
	 * through the Profile octet of the IR packet, i.e. it does not cover the
	 * CRC itself or the IP packet */
	crc_computed = crc_calculate(ROHC_CRC_TYPE_8,
	                             rohc_buf_data(rohc_packet) - add_cid_len,
	                             add_cid_len + large_cid_len + 2, CRC_INIT_8,
	                             decomp->crc_table_8);
	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "CRC-8 on compressed ROHC header = 0x%x", crc_computed);

	/* does the computed CRC match the one in packet? */
	if(crc_computed != crc_packet)
	{
		rohc_decomp_warn(context, "CRC failure (computed = 0x%02x, packet = "
		                 "0x%02x)", crc_computed, crc_packet);
		goto error_crc;
	}

	/* copy IR payload to uncompressed packet */
	if(payload_len != 0)
	{
		memcpy(rohc_buf_data(*uncomp_packet), payload_data, payload_len);
		uncomp_packet->len += payload_len;
	}

	return ROHC_STATUS_OK;

error_crc:
	return ROHC_STATUS_BAD_CRC;
error_malformed:
	return ROHC_STATUS_MALFORMED;
}


/**
 * @brief Decode one Normal packet for the Uncompressed profile.
 *
 * @param context             The decompression context
 * @param rohc_packet         The ROHC packet to decode
 * @param large_cid_len       The length of the optional large CID field
 * @param[out] uncomp_packet  The uncompressed packet
 * @return                    ROHC_STATUS_OK if packet is successfully decoded,
 *                            ROHC_STATUS_MALFORMED if packet is malformed,
 *                            ROHC_STATUS_ERROR if another error occurs
 */
static rohc_status_t uncomp_decode_normal(struct rohc_decomp_ctxt *context,
                                          const struct rohc_buf rohc_packet,
                                          const size_t large_cid_len,
                                          struct rohc_buf *const uncomp_packet)
{
	/* remaining ROHC data not parsed yet */
	struct rohc_buf rohc_remain_data = rohc_packet;

	rohc_debug(context->decompressor, ROHC_TRACE_DECOMP, context->profile->id,
	           "decode Normal packet");

	/* state must not be No Context */
	if(context->state == ROHC_DECOMP_STATE_NC)
	{
		rohc_decomp_warn(context, "cannot receive Normal packets in No Context "
		                 "state");
		goto error;
	}

	/* check if the ROHC packet is large enough for the first byte, the
	 * optional large CID field, and at least one more byte of data */
	if(rohc_remain_data.len < (1 + large_cid_len + 1))
	{
		rohc_decomp_warn(context, "ROHC packet too small (len = %zu bytes)",
		                 rohc_remain_data.len);
		goto error_malformed;
	}

	/* copy the first byte of the ROHC packet to the decompressed packet */
	rohc_buf_byte(*uncomp_packet) = GET_BIT_0_7(rohc_buf_data(rohc_remain_data));
	uncomp_packet->len++;
	rohc_buf_pull(uncomp_packet, 1);
	rohc_buf_pull(&rohc_remain_data, 1);

	/* skip the optional large CID field */
	rohc_buf_pull(&rohc_remain_data, large_cid_len);

	/* copy the second byte and the following bytes of the ROHC packet
	 * to the decompressed packet */
	if(rohc_remain_data.len > 0)
	{
		memcpy(rohc_buf_data(*uncomp_packet), rohc_buf_data(rohc_remain_data),
		       rohc_remain_data.len);
		uncomp_packet->len += rohc_remain_data.len;
		rohc_buf_pull(&rohc_remain_data, rohc_remain_data.len);
		rohc_buf_pull(uncomp_packet, rohc_remain_data.len);
	}

	rohc_buf_push(uncomp_packet, 1 + rohc_remain_data.len);

	return ROHC_STATUS_OK;

error:
	return ROHC_STATUS_ERROR;
error_malformed:
	return ROHC_STATUS_MALFORMED;
}


/**
 * @brief Get the reference SN value of the context. Always return 0 for the
 *        uncompressed profile.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The decompression context
 * @return        The reference SN value
 */
static uint32_t uncomp_get_sn(const struct rohc_decomp_ctxt *const context __attribute__((unused)))
{
	return 0;
}


/**
 * @brief Define the decompression part of the Uncompressed profile as
 *        described in the RFC 3095.
 */
const struct rohc_decomp_profile d_uncomp_profile =
{
	.id              = ROHC_PROFILE_UNCOMPRESSED, /* profile ID (RFC3095 §8) */
	.new_context     = uncomp_new_context,
	.free_context    = uncomp_free_context,
	.decode          = uncomp_decode,
	.detect_pkt_type = uncomp_detect_pkt_type,
	.get_sn          = uncomp_get_sn,
};

