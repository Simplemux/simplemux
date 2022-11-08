/*
 * Copyright 2007,2008 CNES
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
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
 * @file c_rtp.c
 * @brief ROHC compression context for the RTP profile.
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "c_rtp.h"
#include "c_udp.h"
#include "rohc_traces_internal.h"
#include "rohc_packets.h"
#include "rohc_utils.h"
#include "sdvl.h"
#include "crc.h"

#include <stdlib.h>
#ifndef __KERNEL__
#	include <string.h>
#endif
#include <assert.h>


/*
 * Constants and macros
 */


/*
 * Private function prototypes.
 */

static bool c_rtp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));
static void c_rtp_destroy(struct rohc_comp_ctxt *const context)
	__attribute__((nonnull(1)));

static bool c_rtp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
		__attribute__((warn_unused_result, nonnull(1, 2)));
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
static bool rtp_is_udp_port_for_rtp(const struct rohc_comp *const comp,
                                    const uint16_t port);
#endif
static bool c_rtp_use_udp_port(const struct rohc_comp_ctxt *const context,
                               const unsigned int port);

static bool c_rtp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static int c_rtp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
	__attribute__((warn_unused_result, nonnull(1, 2, 3, 5, 6)));

static void rtp_decide_state(struct rohc_comp_ctxt *const context);

static rohc_packet_t c_rtp_decide_FO_packet(const struct rohc_comp_ctxt *context);
static rohc_packet_t c_rtp_decide_SO_packet(const struct rohc_comp_ctxt *context);
static rohc_ext_t c_rtp_decide_extension(const struct rohc_comp_ctxt *context);

static uint32_t c_rtp_get_next_sn(const struct rohc_comp_ctxt *const context,
                                  const struct net_pkt *const uncomp_pkt)
	__attribute__((warn_unused_result, nonnull(1, 2)));

static bool rtp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
		__attribute__((warn_unused_result, nonnull(1, 2)));

static size_t rtp_code_static_rtp_part(const struct rohc_comp_ctxt *const context,
                                       const unsigned char *const next_header,
                                       unsigned char *const dest,
                                       const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static size_t rtp_code_dynamic_rtp_part(const struct rohc_comp_ctxt *const context,
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
                                        const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

static int rtp_changed_rtp_dynamic(const struct rohc_comp_ctxt *const context,
                                   const struct udphdr *const udp,
                                   const struct rtphdr *const rtp)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));


/**
 * @brief Create a new RTP context and initialize it thanks to the given
 *        IP/UDP/RTP packet.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP/RTP packet given to initialize the new context
 * @return         true if successful, false otherwise
 */
static bool c_rtp_create(struct rohc_comp_ctxt *const context,
                         const struct net_pkt *const packet)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	const struct udphdr *udp;
	const struct rtphdr *rtp;

	assert(context != NULL);
	assert(context->profile != NULL);

	/* create and initialize the generic part of the profile context */
	if(!c_generic_create(context, ROHC_LSB_SHIFT_RTP_SN, packet))
	{
		rohc_comp_warn(context, "generic context creation failed");
		goto quit;
	}
	g_context = (struct c_generic_context *) context->specific;

	/* check that transport protocol is UDP, and application protocol is RTP */
	assert(packet->transport->proto == ROHC_IPPROTO_UDP);
	assert(packet->transport->data != NULL);
	udp = (struct udphdr *) packet->transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* initialize SN with the SN found in the RTP header */
	g_context->sn = (uint32_t) rohc_ntoh16(rtp->sn);
	assert(g_context->sn <= 0xffff);
	rohc_comp_debug(context, "initialize context(SN) = hdr(SN) of first "
	                "packet = %u", g_context->sn);

	/* create the RTP part of the profile context */
	rtp_context = malloc(sizeof(struct sc_rtp_context));
	if(rtp_context == NULL)
	{
		rohc_error(context->compressor, ROHC_TRACE_COMP, context->profile->id,
		           "no memory for the RTP part of the profile context");
		goto clean;
	}
	g_context->specific = rtp_context;

	/* initialize the RTP part of the profile context */
	rtp_context->udp_checksum_change_count = 0;
	memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
	rtp_context->rtp_pt_change_count = 0;
	rtp_context->rtp_padding_change_count = 0;
	rtp_context->rtp_extension_change_count = 0;
	memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	if(!c_create_sc(&rtp_context->ts_sc,
	                context->compressor->wlsb_window_width,
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	                context->compressor->trace_callback,
#endif
	                context->compressor->trace_callback2,
	                context->compressor->trace_callback_priv))
	{
		rohc_comp_warn(context, "cannot create scaled RTP Timestamp encoding");
		goto clean;
	}

	/* init the RTP-specific temporary variables */
	rtp_context->tmp.send_rtp_dynamic = -1;
	rtp_context->tmp.ts_send = 0;
	/* do not transmit any RTP TimeStamp (TS) bit by default */
	rtp_context->tmp.nr_ts_bits = 0;
	/* RTP Marker (M) bit is not set by default */
	rtp_context->tmp.is_marker_bit_set = false;
	rtp_context->tmp.rtp_pt_changed = 0;
	rtp_context->tmp.padding_bit_changed = false;
	rtp_context->tmp.extension_bit_changed = false;

	/* init the RTP-specific variables and functions */
	g_context->next_header_len = sizeof(struct udphdr) + sizeof(struct rtphdr);
	g_context->encode_uncomp_fields = rtp_encode_uncomp_fields;
	g_context->decide_state = rtp_decide_state;
	g_context->decide_FO_packet = c_rtp_decide_FO_packet;
	g_context->decide_SO_packet = c_rtp_decide_SO_packet;
	g_context->decide_extension = c_rtp_decide_extension;
	g_context->init_at_IR = NULL;
	g_context->get_next_sn = c_rtp_get_next_sn;
	g_context->code_static_part = rtp_code_static_rtp_part;
	g_context->code_dynamic_part = rtp_code_dynamic_rtp_part;
	g_context->code_ir_remainder = NULL;
	g_context->code_UO_packet_head = NULL;
	g_context->code_uo_remainder = udp_code_uo_remainder;
	g_context->compute_crc_static = rtp_compute_crc_static;
	g_context->compute_crc_dynamic = rtp_compute_crc_dynamic;

	return true;

clean:
	c_generic_destroy(context);
quit:
	return false;
}


/**
 * @brief Destroy the RTP context.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The RTP compression context to destroy
 */
static void c_rtp_destroy(struct rohc_comp_ctxt *const context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	c_destroy_sc(&rtp_context->ts_sc);
	c_generic_destroy(context);
}


/**
 * @brief Check if the given packet corresponds to the RTP profile
 *
 * Conditions are:
 *  \li the transport protocol is UDP
 *  \li the version of the outer IP header is 4 or 6
 *  \li the outer IP header is not an IP fragment
 *  \li if there are at least 2 IP headers, the version of the inner IP header
 *      is 4 or 6
 *  \li if there are at least 2 IP headers, the inner IP header is not an IP
 *      fragment
 *  \li the inner IP payload is at least 8-byte long for UDP header
 *  \li the UDP Length field and the UDP payload match
 *  \li the UDP payload is at least 12-byte long for RTP header
 *  \li the UDP ports are in the list of RTP ports or the user-defined RTP
 *      callback function detected one RTP packet
 *
 * @see c_udp_check_profile
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param comp    The ROHC compressor
 * @param packet  The packet to check
 * @return        Whether the IP packet corresponds to the profile:
 *                  \li true if the IP packet corresponds to the profile,
 *                  \li false if the IP packet does not correspond to
 *                      the profile
 */
static bool c_rtp_check_profile(const struct rohc_comp *const comp,
                                const struct net_pkt *const packet)
{
	const struct udphdr *udp_header;
	const unsigned char *udp_payload;
	unsigned int udp_payload_size;
	bool udp_check;

	/* check that:
	 *  - the transport protocol is UDP,
	 *  - that the versions of outer and inner IP headers are 4 or 6,
	 *  - that outer and inner IP headers are not IP fragments,
	 *  - the IP payload is at least 8-byte long for UDP header,
	 *  - the UDP Length field and the UDP payload match.
	 */
	udp_check = c_udp_check_profile(comp, packet);
	if(!udp_check)
	{
		goto bad_profile;
	}

	/* retrieve the UDP header and the UDP payload */
	assert(packet->transport->proto == ROHC_IPPROTO_UDP);
	assert(packet->transport->data != NULL);
	udp_header = (const struct udphdr *) packet->transport->data;
	udp_payload = (unsigned char *) (udp_header + 1);
	udp_payload_size = packet->transport->len - sizeof(struct udphdr);

	/* UDP payload shall be large enough for RTP header  */
	if(udp_payload_size < sizeof(struct rtphdr))
	{
		goto bad_profile;
	}

	/* check if the IP/UDP packet is a RTP packet */
	if(comp->rtp_callback != NULL)
	{
		/* check if the IP/UDP packet is a RTP packet with the user callback
		   dedicated to RTP stream detection: if the RTP callback returns 1,
		   consider that the packet matches the RTP profile */

		const struct ip_packet *innermost_ip_hdr;
		bool is_rtp_packet;

		/* retrieve the innermost IP header */
		if(packet->ip_hdr_nr == 1)
		{
			innermost_ip_hdr = &packet->outer_ip;
		}
		else
		{
			innermost_ip_hdr = &packet->inner_ip;
		}

		is_rtp_packet = comp->rtp_callback(innermost_ip_hdr->data,
		                                   (unsigned char *) udp_header,
		                                   udp_payload, udp_payload_size,
		                                   comp->rtp_private);
		if(!is_rtp_packet)
		{
			goto bad_profile;
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "RTP packet detected by the RTP callback");
	}
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	else if(comp->rtp_ports[0] != 0)
	{
		/* check if the UDP destination port belongs to the list of RTP
		   destination ports reserved for RTP traffic */

		const uint16_t dest_port = rohc_ntoh16(udp_header->dest);
		bool is_rtp_packet;


		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "destination port in UDP packet = 0x%04x (%u)",
		           dest_port, dest_port);

		is_rtp_packet = rtp_is_udp_port_for_rtp(comp, dest_port);
		if(!is_rtp_packet)
		{
			goto bad_profile;
		}

		rohc_debug(comp, ROHC_TRACE_COMP, ROHC_PROFILE_GENERAL,
		           "UDP destination port is in the list of RTP ports");
	}
#endif
	else
	{
		/* no callback for advanced RTP stream detection and no UDP
		   destination port reserved for RTP trafic, so the IP/UDP packet will
		   be compressed with another profile (the IP/UDP one probably) */
		goto bad_profile;
	}

	return true;

bad_profile:
	return false;
}


#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1

/**
 * @brief Check whether the given UDP port is reserved for RTP traffic
 *
 * @param comp  The compressor
 * @param port  The UDP port to search for
 * @return      true if the UDP port is reserved for RTP traffic,
 *              false otherwise
 */
static bool rtp_is_udp_port_for_rtp(const struct rohc_comp *const comp,
                                    const uint16_t port)
{
	bool match = false;
	size_t i;

	/* explore the list of UDP ports reserved for RTP and stop:
	 *  - if a port is equal to 0 (current entry and next ones are unused)
	 *  - if the port is found
	 *  - if the port in the list is greater than the port in the packet
	 *    because the list is sorted in ascending order
	 *  - if the end of the list is reached
	 */
	i = 0;
	while(i < MAX_RTP_PORTS &&
	      comp->rtp_ports[i] != 0 &&
	      !match &&
	      port >= comp->rtp_ports[i])
	{
		match = (port == comp->rtp_ports[i]);
		i++;
	}

	return match;
}

#endif


/**
 * @brief Check if the IP/UDP/RTP packet belongs to the context
 *
 * Conditions are:
 *  - the number of IP headers must be the same as in context
 *  - IP version of the two IP headers must be the same as in context
 *  - IP packets must not be fragmented
 *  - the source and destination addresses of the two IP headers must match the
 *    ones in the context
 *  - the transport protocol must be UDP
 *  - the source and destination ports of the UDP header must match the ones in
 *    the context
 *  - IPv6 only: the Flow Label of the two IP headers must match the ones the
 *    context
 *  - the SSRC field of the RTP header must match the one in the context
 *
 * All the context but the last one are done by the c_udp_check_context()
 * function.
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context  The compression context
 * @param packet   The IP/UDP/RTP packet to check
 * @return         true if the IP/UDP/RTP packet belongs to the context
 *                 false if it does not belong to the context
 *
 * @see c_udp_check_context
 */
static bool c_rtp_check_context(const struct rohc_comp_ctxt *const context,
                                const struct net_pkt *const packet)
{
	const struct c_generic_context *g_context;
	const struct sc_rtp_context *rtp_context;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	bool udp_check;

	/* check IP and UDP headers */
	udp_check = c_udp_check_context(context, packet);
	if(!udp_check)
	{
		goto bad_context;
	}

	/* get UDP and RTP headers */
	assert(packet->transport->data != NULL);
	udp = (struct udphdr *) packet->transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* check the RTP SSRC field */
	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	if(rtp_context->old_rtp.ssrc != rtp->ssrc)
	{
		goto bad_context;
	}

	return true;

bad_context:
	return false;
}


/**
 * @brief Decide which packet to send when in First Order (FO) state.
 *
 * Packets that can be used are the IR-DYN and UO-2 packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - ROHC_PACKET_UOR_2_RTP
 *                 - ROHC_PACKET_UOR_2_TS
 *                 - ROHC_PACKET_UOR_2_ID
 *                 - ROHC_PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_FO_packet(const struct rohc_comp_ctxt *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	rohc_packet_t packet;
	size_t nr_of_ip_hdr;
	size_t nr_sn_bits;
	size_t nr_ts_bits;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_of_ip_hdr = g_context->ip_hdr_nr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ts_bits = rtp_context->tmp.nr_ts_bits;

	if((g_context->outer_ip_flags.version == IPV4 &&
	    g_context->outer_ip_flags.info.v4.sid_count < MAX_FO_COUNT) ||
	   (nr_of_ip_hdr > 1 &&
	    g_context->inner_ip_flags.version == IPV4 &&
	   	g_context->inner_ip_flags.info.v4.sid_count < MAX_FO_COUNT))
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because at least one "
		                "SID flag changed");
	}
	else if(g_context->tmp.send_static && nr_sn_bits <= 14)
	{
		packet = ROHC_PACKET_UOR_2_RTP;
		rohc_comp_debug(context, "choose packet UOR-2-RTP because at least one "
		                "static field changed and %zd <= 14 SN bits must be "
		                "transmitted", nr_sn_bits);
	}
	else if(nr_of_ip_hdr == 1 && g_context->tmp.send_dynamic > 2)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 2 dynamic "
		                "fields changed with a single IP header",
		                g_context->tmp.send_dynamic);
	}
	else if(nr_of_ip_hdr > 1 && g_context->tmp.send_dynamic > 4)
	{
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %d > 4 dynamic "
		                "fields changed with double IP headers",
		                g_context->tmp.send_dynamic);
	}
	else if(nr_sn_bits <= 14)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		const int is_ip_v4 = (g_context->outer_ip_flags.version == IPV4);
		const int is_rnd = g_context->outer_ip_flags.info.v4.rnd;
		const size_t nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
		const bool is_outer_ipv4_non_rnd = (is_ip_v4 && !is_rnd);
		size_t nr_ipv4_non_rnd;
		size_t nr_ipv4_non_rnd_with_bits;

		rohc_comp_debug(context, "choose one UOR-2-* packet because %zd <= 14 "
		                "SN bits must be transmitted", nr_sn_bits);

		/* how many IP headers are IPv4 headers with non-random IP-IDs */
		nr_ipv4_non_rnd = 0;
		nr_ipv4_non_rnd_with_bits = 0;
		if(is_outer_ipv4_non_rnd)
		{
			nr_ipv4_non_rnd++;
			if(nr_ip_id_bits > 0)
			{
				nr_ipv4_non_rnd_with_bits++;
			}
		}
		if(nr_of_ip_hdr >= 1)
		{
			const int is_ip2_v4 = g_context->inner_ip_flags.version == IPV4;
			const int is_rnd2 = g_context->inner_ip_flags.info.v4.rnd;
			const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;
			const bool is_inner_ipv4_non_rnd = (is_ip2_v4 && !is_rnd2);

			if(is_inner_ipv4_non_rnd)
			{
				nr_ipv4_non_rnd++;
				if(nr_ip_id_bits2 > 0)
				{
					nr_ipv4_non_rnd_with_bits++;
				}
			}
		}

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_SO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = ROHC_PACKET_UOR_2_RTP;
			rohc_comp_debug(context, "choose packet UOR-2-RTP because neither "
			                "of the %zd IP header(s) are IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(nr_ts_bits))
		{
			packet = ROHC_PACKET_UOR_2_ID;
			rohc_comp_debug(context, "choose packet UOR-2-ID because at least "
			                "one of the %zd IP header(s) is IPv4 with "
			                "non-random IP-ID with at least 1 bit of IP-ID to "
			                "transmit, and ( TS bits are deducible from SN, or "
			                "%zd TS bits can be SDVL-encoded", nr_of_ip_hdr,
			                nr_ts_bits);
		}
		else
		{
			packet = ROHC_PACKET_UOR_2_TS;
			rohc_comp_debug(context, "choose packet UOR-2-TS because at least "
			                "one of the %zd IP header(s) is IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %zd > 14 SN "
		                "bits must be transmitted", nr_sn_bits);
	}

	return packet;
}


/**
 * @brief Decide which packet to send when in Second Order (SO) state.
 *
 * Packets that can be used are the UO-0, UO-1 and UO-2 (with or without
 * extensions) packets.
 *
 * @see decide_packet
 *
 * @param context The compression context
 * @return        The packet type among:
 *                 - ROHC_PACKET_UO_0
 *                 - ROHC_PACKET_UO_1_RTP
 *                 - ROHC_PACKET_UO_1_TS
 *                 - ROHC_PACKET_UO_1_ID
 *                 - ROHC_PACKET_UOR_2_RTP
 *                 - ROHC_PACKET_UOR_2_TS
 *                 - ROHC_PACKET_UOR_2_ID
 *                 - ROHC_PACKET_IR_DYN
 */
static rohc_packet_t c_rtp_decide_SO_packet(const struct rohc_comp_ctxt *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	size_t nr_of_ip_hdr;
	rohc_packet_t packet;
	unsigned int nr_ipv4_non_rnd;
	unsigned int nr_ipv4_non_rnd_with_bits;
	size_t nr_innermost_ip_id_bits;
	size_t nr_outermost_ip_id_bits;
	bool is_outer_ipv4_non_rnd;
	int is_rnd;
	int is_ip_v4;
	size_t nr_sn_bits;
	size_t nr_ts_bits;
	size_t nr_ip_id_bits;
	bool is_ts_deducible;
	bool is_ts_scaled;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;
	nr_of_ip_hdr = g_context->ip_hdr_nr;
	nr_sn_bits = g_context->tmp.nr_sn_bits;
	nr_ts_bits = rtp_context->tmp.nr_ts_bits;
	nr_ip_id_bits = g_context->tmp.nr_ip_id_bits;
	is_rnd = g_context->outer_ip_flags.info.v4.rnd;
	is_ip_v4 = (g_context->outer_ip_flags.version == IPV4);
	is_outer_ipv4_non_rnd = (is_ip_v4 && !is_rnd);

	is_ts_deducible = rohc_ts_sc_is_deducible(&rtp_context->ts_sc);
	is_ts_scaled = (rtp_context->ts_sc.state == SEND_SCALED);

	rohc_comp_debug(context, "nr_ip_bits = %zd, nr_sn_bits = %zd, "
	                "nr_ts_bits = %zd, is_ts_deducible = %d, is_ts_scaled = %d, "
	                "Marker bit = %d, nr_of_ip_hdr = %zd, rnd = %d",
	                nr_ip_id_bits, nr_sn_bits, nr_ts_bits, !!is_ts_deducible,
	                !!is_ts_scaled, !!rtp_context->tmp.is_marker_bit_set,
	                nr_of_ip_hdr, is_rnd);

	/* sanity check */
	if(g_context->outer_ip_flags.version == IPV4)
	{
		assert(g_context->outer_ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
		assert(g_context->outer_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
		assert(g_context->outer_ip_flags.info.v4.nbo_count >= MAX_FO_COUNT);
	}
	if(nr_of_ip_hdr > 1 && g_context->inner_ip_flags.version == IPV4)
	{
		assert(g_context->inner_ip_flags.info.v4.sid_count >= MAX_FO_COUNT);
		assert(g_context->inner_ip_flags.info.v4.rnd_count >= MAX_FO_COUNT);
		assert(g_context->inner_ip_flags.info.v4.nbo_count >= MAX_FO_COUNT);
	}
	assert(g_context->tmp.send_static == 0);
	assert(g_context->tmp.send_dynamic == 0);
	assert(rtp_context->tmp.send_rtp_dynamic == 0);
	/* RTP Padding bit is a STATIC field, not allowed to change in SO state */
	assert(!rtp_context->tmp.padding_bit_changed);
	/* RTP eXtension bit is STATIC field, not allowed to change in SO state */
	assert(!rtp_context->tmp.extension_bit_changed);

	/* find out how many IP headers are IPv4 headers with non-random IP-IDs */
	nr_ipv4_non_rnd = 0;
	nr_ipv4_non_rnd_with_bits = 0;
	if(is_outer_ipv4_non_rnd)
	{
		nr_ipv4_non_rnd++;
		if(nr_ip_id_bits > 0)
		{
			nr_ipv4_non_rnd_with_bits++;
		}
	}
	if(nr_of_ip_hdr >= 1)
	{
		const int is_ip2_v4 = (g_context->inner_ip_flags.version == IPV4);
		const int is_rnd2 = g_context->inner_ip_flags.info.v4.rnd;
		const size_t nr_ip_id_bits2 = g_context->tmp.nr_ip_id_bits2;
		const bool is_inner_ipv4_non_rnd = (is_ip2_v4 && !is_rnd2);

		if(is_inner_ipv4_non_rnd)
		{
			nr_ipv4_non_rnd++;
			if(nr_ip_id_bits2 > 0)
			{
				nr_ipv4_non_rnd_with_bits++;
			}
		}
	}
	rohc_comp_debug(context, "nr_ipv4_non_rnd = %u, nr_ipv4_non_rnd_with_bits = %u",
	                nr_ipv4_non_rnd, nr_ipv4_non_rnd_with_bits);

	/* determine the number of IP-ID bits and the IP-ID offset of the
	 * innermost IPv4 header with non-random IP-ID */
	rohc_get_ipid_bits(context, &nr_innermost_ip_id_bits,
	                   &nr_outermost_ip_id_bits);

	/* what packet type do we choose? */
	if(nr_sn_bits <= 4 &&
	   nr_ipv4_non_rnd_with_bits == 0 &&
	   is_ts_scaled && (nr_ts_bits == 0 || is_ts_deducible) &&
	   !rtp_context->tmp.is_marker_bit_set)
	{
		packet = ROHC_PACKET_UO_0;
		rohc_comp_debug(context, "choose packet UO-0 because %zd <= 4 SN bits "
		                "must be transmitted, neither of the %zd IP header(s) "
		                "are IPv4 with non-random IP-ID with some IP-ID bits "
		                "to transmit, ( %zd <= 0 TS bit must be transmitted, "
		                "or TS bits are deducible from SN ), and RTP M bit is "
		                "not set", nr_sn_bits, nr_of_ip_hdr, nr_ts_bits);
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd == 0 &&
	        is_ts_scaled && nr_ts_bits <= 6)
	{
		packet = ROHC_PACKET_UO_1_RTP;
		rohc_comp_debug(context, "choose packet UO-1-RTP because neither of "
		                "the %zd IP header(s) are 'IPv4 with non-random IP-ID', "
		                "%zd <= 4 SN bits must be transmitted, and "
		                "%zd <= 6 TS bits must be transmitted", nr_sn_bits,
		                nr_of_ip_hdr, nr_ts_bits);
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd_with_bits == 1 && nr_innermost_ip_id_bits <= 5 &&
	        is_ts_scaled && (nr_ts_bits == 0 || is_ts_deducible) &&
	        !rtp_context->tmp.is_marker_bit_set)
	{
		/* UO-1-ID without extension */
		packet = ROHC_PACKET_UO_1_ID;
		rohc_comp_debug(context, "choose packet UO-1-ID because only one of the "
		                "%zd IP header(s) is IPv4 with non-random IP-ID with "
		                "%zd <= 5 IP-ID bits to transmit, %zd <= 4 SN bits "
		                "must be transmitted, ( %zd <= 0 TS bit must be "
		                "transmitted, or TS bits are deducible from SN ), and "
		                "RTP M bit is not set", nr_of_ip_hdr,
		                nr_innermost_ip_id_bits, nr_sn_bits, nr_ts_bits);
	}
	else if(nr_sn_bits <= 4 &&
	        nr_ipv4_non_rnd_with_bits == 0 &&
	        is_ts_scaled && nr_ts_bits <= 5)
	{
		packet = ROHC_PACKET_UO_1_TS;
		rohc_comp_debug(context, "choose packet UO-1-TS because neither of the "
		                "%zd IP header(s) are IPv4 with non-random IP-ID with "
		                "some IP-ID bits to to transmit for that IP header, "
		                "%zd <= 4 SN bits must be transmitted, and "
		                "%zd <= 6 TS bits must be transmitted", nr_of_ip_hdr,
		                nr_sn_bits, nr_ts_bits);
	}
	else if(nr_sn_bits <= 12 &&
	        nr_ipv4_non_rnd_with_bits >= 1 &&
	        sdvl_can_length_be_encoded(nr_ts_bits))
	{
		/* UO-1-ID packet with extension can be used only if SN stand on
		 * <= 12 bits (4 bits in base header + 8 bits in extension 3) */

		packet = ROHC_PACKET_UO_1_ID;
		rohc_comp_debug(context, "choose packet UO-1-ID because at least "
		                "one of the %zd IP header(s) is IPv4 with "
		                "non-random IP-ID with at least 1 bit of IP-ID to "
		                "transmit, %zu <= 12 SN bits must be transmitted, "
		                "and %zd TS bits can be SDVL-encoded", nr_of_ip_hdr,
		                nr_sn_bits, nr_ts_bits);
	}
	else if(nr_sn_bits <= 14)
	{
		/* UOR-2* packets can be used only if SN stand on <= 14 bits (6 bits
		 * in base header + 8 bits in extension 3): determine which UOR-2*
		 * packet to choose */

		/* what UOR-2* packet do we choose? */
		/* TODO: the 3 next if/else could be merged with the ones from
		 * c_rtp_decide_FO_packet */
		if(nr_ipv4_non_rnd == 0)
		{
			packet = ROHC_PACKET_UOR_2_RTP;
			rohc_comp_debug(context, "choose packet UOR-2-RTP because neither "
			                "of the %zd IP header(s) are IPv4 with non-random "
			                "IP-ID", nr_of_ip_hdr);
		}
		else if(nr_ipv4_non_rnd_with_bits >= 1 &&
		        sdvl_can_length_be_encoded(nr_ts_bits))
		{
			packet = ROHC_PACKET_UOR_2_ID;
			rohc_comp_debug(context, "choose packet UOR-2-ID because at least "
			                "one of the %zd IP header(s) is IPv4 with "
			                "non-random IP-ID with at least 1 bit of IP-ID to "
			                "transmit, and %zd TS bits can be SDVL-encoded",
			                nr_of_ip_hdr, nr_ts_bits);
		}
		else
		{
			packet = ROHC_PACKET_UOR_2_TS;
			rohc_comp_debug(context, "choose packet UOR-2-TS because at least "
			                "one of the %zd IP header(s) is IPv4 with "
			                "non-random IP-ID", nr_of_ip_hdr);
		}
	}
	else
	{
		/* UOR-2* packets can not be used, use IR-DYN instead */
		packet = ROHC_PACKET_IR_DYN;
		rohc_comp_debug(context, "choose packet IR-DYN because %zd > 14 SN "
		                "bits must be transmitted", nr_sn_bits);
	}

	return packet;
}


/**
 * @brief Decide what extension shall be used in the UO-1/UO-2 packet.
 *
 * Extensions 0, 1 & 2 are IPv4 only because of the IP-ID.
 *
 * @param context The compression context
 * @return        The extension code among ROHC_EXT_NO, ROHC_EXT_0,
 *                ROHC_EXT_1 and ROHC_EXT_3 if successful,
 *                ROHC_EXT_UNKNOWN otherwise
 */
static rohc_ext_t c_rtp_decide_extension(const struct rohc_comp_ctxt *context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	rohc_ext_t ext;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* force extension type 3 if at least one RTP dynamic field changed
	 *                     OR if TS cannot be transmitted scaled */
	if(rtp_context->tmp.send_rtp_dynamic > 0)
	{
		rohc_comp_debug(context, "force EXT-3 because at least one RTP dynamic "
		                "field changed");
		ext = ROHC_EXT_3;
	}
	else if(rtp_context->ts_sc.state != SEND_SCALED)
	{
		rohc_comp_debug(context, "force EXT-3 because TS cannot be transmitted "
		                "scaled");
		ext = ROHC_EXT_3;
	}
	else
	{
		/* fallback on the algorithm shared by all IP-based profiles */
		ext = decide_extension(context);
	}

	return ext;
}


/**
 * @brief Encode an IP/UDP/RTP packet according to a pattern decided by several
 *        different factors.
 *
 * @param context           The compression context
 * @param uncomp_pkt        The uncompressed packet to encode
 * @param rohc_pkt          OUT: The ROHC packet
 * @param rohc_pkt_max_len  The maximum length of the ROHC packet
 * @param packet_type       OUT: The type of ROHC packet that is created
 * @param payload_offset    OUT: The offset for the payload in the IP packet
 * @return                  The length of the ROHC packet if successful,
 *                          -1 otherwise
 */
static int c_rtp_encode(struct rohc_comp_ctxt *const context,
                        const struct net_pkt *const uncomp_pkt,
                        unsigned char *const rohc_pkt,
                        const size_t rohc_pkt_max_len,
                        rohc_packet_t *const packet_type,
                        size_t *const payload_offset)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	const struct udphdr *udp;
	const struct rtphdr *rtp;
	int size;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* retrieve the UDP and RTP headers */
	assert(uncomp_pkt->transport->data != NULL);
	udp = (struct udphdr *) uncomp_pkt->transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* how many UDP/RTP fields changed? */
	rtp_context->tmp.send_rtp_dynamic = rtp_changed_rtp_dynamic(context, udp, rtp);

	/* encode the IP packet */
	size = c_generic_encode(context, uncomp_pkt, rohc_pkt, rohc_pkt_max_len,
	                        packet_type, payload_offset);
	if(size < 0)
	{
		goto quit;
	}

	/* update the context with the new UDP/RTP headers */
	if(g_context->tmp.packet_type == ROHC_PACKET_IR ||
	   g_context->tmp.packet_type == ROHC_PACKET_IR_DYN)
	{
		memcpy(&rtp_context->old_udp, udp, sizeof(struct udphdr));
		memcpy(&rtp_context->old_rtp, rtp, sizeof(struct rtphdr));
	}
	else
	{
		if(rtp_context->tmp.padding_bit_changed)
		{
			rtp_context->old_rtp.padding = rtp->padding;
		}
		if(rtp_context->tmp.extension_bit_changed)
		{
			rtp_context->old_rtp.extension = rtp->extension;
		}
	}

quit:
	return size;
}


/**
 * @brief Decide the state that should be used for the next packet compressed
 *        with the ROHC RTP profile.
 *
 * The three states are:
 *  - Initialization and Refresh (IR),
 *  - First Order (FO),
 *  - Second Order (SO).
 *
 * @param context The compression context
 */
static void rtp_decide_state(struct rohc_comp_ctxt *const context)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	if(context->state != ROHC_COMP_STATE_IR &&
	   rtp_context->udp_checksum_change_count < MAX_IR_COUNT)
	{
		/* TODO: could be optimized: IR state is not required, only IR or
		 * IR-DYN packet is */
		rohc_comp_debug(context, "go back to IR state because UDP checksum "
		                "behaviour changed in the last few packets");
		change_state(context, ROHC_COMP_STATE_IR);
	}
	else if(rtp_context->tmp.send_rtp_dynamic)
	{
		if(context->state == ROHC_COMP_STATE_IR)
		{
			rohc_comp_debug(context, "%d RTP dynamic fields changed, stay in "
			                "IR state", rtp_context->tmp.send_rtp_dynamic);
		}
		else
		{
			rohc_comp_debug(context, "%d RTP dynamic fields changed, go in FO "
			                "state", rtp_context->tmp.send_rtp_dynamic);
			change_state(context, ROHC_COMP_STATE_FO);
		}
	}
	else
	{
		/* generic function used by the IP-only, UDP and UDP-Lite profiles */
		decide_state(context);
	}

	/* force initializing TS, TS_STRIDE and TS_SCALED again after
	 * transition back to IR */
	if(context->state == ROHC_COMP_STATE_IR &&
	   rtp_context->ts_sc.state > INIT_STRIDE)
	{
		rtp_context->ts_sc.state = INIT_STRIDE;
		rtp_context->ts_sc.nr_init_stride_packets = 0;
	}
}


/**
 * @brief Determine the SN value for the next packet
 *
 * Profile SN is the 16-bit RTP SN.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            The SN
 */
static uint32_t c_rtp_get_next_sn(const struct rohc_comp_ctxt *const context __attribute__((unused)),
                                  const struct net_pkt *const uncomp_pkt)
{
	const struct udphdr *const udp =
		(struct udphdr *) uncomp_pkt->transport->data;
	const struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);
	uint32_t next_sn;

	next_sn = (uint32_t) rohc_ntoh16(rtp->sn);

	assert(next_sn <= 0xffff);
	return next_sn;
}


/**
 * @brief Encode uncompressed RTP fields
 *
 * Handle the RTP TS field.
 *
 * @param context     The compression context
 * @param uncomp_pkt  The uncompressed packet to encode
 * @return            true in case of success, false otherwise
 */
static bool rtp_encode_uncomp_fields(struct rohc_comp_ctxt *const context,
                                     const struct net_pkt *const uncomp_pkt)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	struct udphdr *udp;
	struct rtphdr *rtp;

	assert(context != NULL);
	assert(context->specific != NULL);
	g_context = (struct c_generic_context *) context->specific;
	assert(g_context->specific != NULL);
	rtp_context = g_context->specific;
	assert(uncomp_pkt != NULL);
	assert(uncomp_pkt->transport->data != NULL);
	udp = (struct udphdr *) uncomp_pkt->transport->data;
	rtp = (struct rtphdr *) (udp + 1);

	/* add new TS value to context */
	assert(g_context->sn <= 0xffff);
	c_add_ts(&rtp_context->ts_sc, rohc_ntoh32(rtp->timestamp), g_context->sn);

	/* determine the number of TS bits to send wrt compression state */
	if(rtp_context->ts_sc.state == INIT_TS ||
	   rtp_context->ts_sc.state == INIT_STRIDE)
	{
		if((context->compressor->features & ROHC_COMP_FEATURE_COMPAT_1_6_x) != 0)
		{
			/* keep compatibility with previous versions */
			rtp_context->tmp.ts_send = rohc_ntoh32(rtp->timestamp);
			rtp_context->tmp.nr_ts_bits = 32;
		}
		else
		{
			/* state INIT_TS: TS_STRIDE cannot be computed yet (first packet or TS
			 *                is constant), so send TS only
			 * state INIT_STRIDE: TS and TS_STRIDE will be send
			 */
			rtp_context->tmp.ts_send = get_ts_unscaled(&rtp_context->ts_sc);
			if(!nb_bits_unscaled(&rtp_context->ts_sc, &(rtp_context->tmp.nr_ts_bits)))
			{
				const uint32_t ts_send = rtp_context->tmp.ts_send;
				size_t nr_bits;
				uint32_t mask;

				/* this is the first LSB bits of unscaled TS to be sent, we cannot
				 * compute them with W-LSB and we must find its size (in bits) */
				for(nr_bits = 1, mask = 1;
				    nr_bits <= 32 && (ts_send & mask) != ts_send;
				    nr_bits++, mask |= (1 << (nr_bits - 1)))
				{
				}
				rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
				            (ts_send & mask) == ts_send, error, "size of unscaled TS "
				            "(0x%x) not found, this should never happen!", ts_send);

				rohc_comp_debug(context, "first unscaled TS to be sent: ts_send = %u, "
				                "mask = 0x%x, nr_bits = %zd", ts_send, mask, nr_bits);
				rtp_context->tmp.nr_ts_bits = nr_bits;
			}

			/* save the new unscaled value */
			assert(g_context->sn <= 0xffff);
			add_unscaled(&rtp_context->ts_sc, g_context->sn);
		}
		rohc_comp_debug(context, "unscaled TS = %u on %zd bits",
		                rtp_context->tmp.ts_send, rtp_context->tmp.nr_ts_bits);
	}
	else /* SEND_SCALED */
	{
		/* TS_SCALED value will be send */
		rtp_context->tmp.ts_send = get_ts_scaled(&rtp_context->ts_sc);
		if(!nb_bits_scaled(&rtp_context->ts_sc, &(rtp_context->tmp.nr_ts_bits)))
		{
			const uint32_t ts_send = rtp_context->tmp.ts_send;
			size_t nr_bits;
			uint32_t mask;

			/* this is the first TS scaled to be sent, we cannot code it with
			 * W-LSB and we must find its size (in bits) */
			for(nr_bits = 1, mask = 1;
			    nr_bits <= 32 && (ts_send & mask) != ts_send;
			    nr_bits++, mask |= (1 << (nr_bits - 1)))
			{
			}
			rohc_assert(context->compressor, ROHC_TRACE_COMP, context->profile->id,
			            (ts_send & mask) == ts_send, error, "size of TS scaled "
			            "(0x%x) not found, this should never happen!", ts_send);

			rohc_comp_debug(context, "first TS scaled to be sent: ts_send = %u, "
			                "mask = 0x%x, nr_bits = %zd", ts_send, mask, nr_bits);
			rtp_context->tmp.nr_ts_bits = nr_bits;
		}

		/* save the new unscaled and TS_SCALED values */
		assert(g_context->sn <= 0xffff);
		add_unscaled(&rtp_context->ts_sc, g_context->sn);
		add_scaled(&rtp_context->ts_sc, g_context->sn);
		rohc_comp_debug(context, "TS_SCALED = %u on %zd bits",
		                rtp_context->tmp.ts_send, rtp_context->tmp.nr_ts_bits);
	}

	rohc_comp_debug(context, "%s%zd bits are required to encode new TS",
	                (rohc_ts_sc_is_deducible(&rtp_context->ts_sc) ?
	                 "0 (TS is deducible from SN bits) or " : ""),
	                rtp_context->tmp.nr_ts_bits);

	return true;

error:
	return false;
}


/**
 * @brief Build the static part of the UDP/RTP headers.
 *
 * \verbatim

 Static part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /          Source Port          /   2 octets
    +---+---+---+---+---+---+---+---+
 2  /       Destination Port        /   2 octets
    +---+---+---+---+---+---+---+---+

 Static part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 3  /             SSRC              /   4 octets
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 1 & 2 are done by the udp_code_static_udp_part() function. Part 3 is
 * done by this function.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 *
 * @see udp_code_static_udp_part
 */
static size_t rtp_code_static_rtp_part(const struct rohc_comp_ctxt *const context,
                                       const unsigned char *const next_header,
                                       unsigned char *const dest,
                                       const size_t counter)
{
	const struct udphdr *const udp = (struct udphdr *) next_header;
	const struct rtphdr *const rtp = (struct rtphdr *) (udp + 1);
	size_t counter2;
	size_t nr_written = 0;

	/* parts 1 & 2 */
	counter2 = udp_code_static_udp_part(context, next_header, dest, counter);

	/* part 3 */
	rohc_comp_debug(context, "RTP SSRC = 0x%x", rtp->ssrc);
	memcpy(&dest[counter2 + nr_written], &rtp->ssrc, 4);
	nr_written += 4;

	return counter2 + nr_written;
}


/**
 * @brief Build the dynamic part of the UDP/RTP headers.
 *
 * \verbatim

 Dynamic part of UDP header (5.7.7.5):

    +---+---+---+---+---+---+---+---+
 1  /           Checksum            /   2 octets
    +---+---+---+---+---+---+---+---+

 Dynamic part of RTP header (5.7.7.6):

    +---+---+---+---+---+---+---+---+
 2  |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
    +---+---+---+---+---+---+---+---+
 3  | M |            PT             |
    +---+---+---+---+---+---+---+---+
 4  /      RTP Sequence Number      /  2 octets
    +---+---+---+---+---+---+---+---+
 5  /   RTP Timestamp (absolute)    /  4 octets
    +---+---+---+---+---+---+---+---+
 6  /      Generic CSRC list        /  variable length
    +---+---+---+---+---+---+---+---+
 7  : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
    +---+---+---+---+---+---+---+---+
 8  :         TS_Stride             :  1-4 octets, if TSS = 1
    +---+---+---+---+---+---+---+---+
 9  :         Time_Stride           :  1-4 octets, if TIS = 1
    +---+---+---+---+---+---+---+---+

\endverbatim
 *
 * Parts 6 & 9 are not supported yet. The TIS flag in part 7 is not supported.
 *
 * @param context     The compression context
 * @param next_header The UDP/RTP headers
 * @param dest        The rohc-packet-under-build buffer
 * @param counter     The current position in the rohc-packet-under-build buffer
 * @return            The new position in the rohc-packet-under-build buffer
 */
static size_t rtp_code_dynamic_rtp_part(const struct rohc_comp_ctxt *const context,
                                        const unsigned char *const next_header,
                                        unsigned char *const dest,
                                        const size_t counter)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	const struct udphdr *udp = (struct udphdr *) next_header;
	const struct rtphdr *rtp = (struct rtphdr *) (udp + 1);
	unsigned char byte;
	unsigned int rx_byte = 0;
	size_t nr_written;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	/* part 1 */
	rohc_comp_debug(context, "UDP checksum = 0x%04x", udp->check);
	memcpy(&dest[counter], &udp->check, 2);
	nr_written = 2;
	rtp_context->udp_checksum_change_count++;

	/* part 2 */
	byte = 0;
	if(rtp_context->ts_sc.state == INIT_STRIDE ||
	   rtp_context->tmp.extension_bit_changed ||
	   rtp_context->rtp_extension_change_count < MAX_IR_COUNT)
	{
		/* send TS_STRIDE and/or the eXtension (X) bit */
		rx_byte = 1;
		byte |= 1 << 4;
	}
	byte |= (rtp->version & 0x03) << 6;
	byte |= (rtp->padding & 0x01) << 5;
	byte |= rtp->cc & 0x0f;
	dest[counter + nr_written] = byte;
	rohc_comp_debug(context, "(V = %u, P = %u, RX = %u, CC = 0x%x) = 0x%02x",
	                rtp->version & 0x03, rtp->padding & 0x01, rx_byte,
	                rtp->cc & 0x0f, dest[counter + nr_written]);
	nr_written++;
	rtp_context->rtp_padding_change_count++;

	/* part 3 */
	byte = 0;
	byte |= (rtp->m & 0x01) << 7;
	byte |= rtp->pt & 0x7f;
	dest[counter + nr_written] = byte;
	rohc_comp_debug(context, "(M = %u, PT = 0x%02x) = 0x%02x", rtp->m & 0x01,
	                rtp->pt & 0x7f, dest[counter + nr_written]);
	nr_written++;
	rtp_context->rtp_pt_change_count++;

	/* part 4 */
	memcpy(&dest[counter + nr_written], &rtp->sn, 2);
	rohc_comp_debug(context, "SN = 0x%02x 0x%02x", dest[counter + nr_written],
	                dest[counter + nr_written + 1]);
	nr_written += 2;

	/* part 5 */
	memcpy(&dest[counter + nr_written], &rtp->timestamp, 4);
	rohc_comp_debug(context, "TS = 0x%02x 0x%02x 0x%02x 0x%02x",
	                dest[counter + nr_written], dest[counter + nr_written + 1],
	                dest[counter + nr_written + 2],
	                dest[counter + nr_written + 3]);
	nr_written += 4;

	/* part 6 not supported yet  but the field is mandatory,
	   so add a zero byte */
	dest[counter + nr_written] = 0x00;
	rohc_comp_debug(context, "Generic CSRC list not supported yet, put a 0x00 byte");
	nr_written++;

	/* parts 7, 8 & 9 */
	if(rx_byte)
	{
		int tis;
		int tss;

		/* part 7 */
		tis = 0; /* TIS flag not supported yet */
		tss = (rtp_context->ts_sc.state == INIT_STRIDE);

		byte = 0;
		byte |= (rtp->extension & 0x01) << 4;
		byte |= (context->mode & 0x03) << 2;
#if 0 /* TODO: handle TIS */
		byte |= (tis & 0x01) << 1;
#endif
		byte |= tss & 0x01;
		dest[counter + nr_written] = byte;
		rohc_comp_debug(context, "(X = %u, Mode = %u, TIS = %u, TSS = %u) = 0x%02x",
		                rtp->extension & 0x01, context->mode & 0x03, tis & 0x01,
		                tss & 0x01, dest[counter + nr_written]);
		nr_written++;
		rtp_context->rtp_extension_change_count++;

		/* part 8 */
		if(tss)
		{
			uint32_t ts_stride;
			size_t ts_stride_sdvl_len;

			/* get the TS_STRIDE to send in packet */
			ts_stride = get_ts_stride(&rtp_context->ts_sc);

			/* encode TS_STRIDE in SDVL and write it to packet */
			if(!sdvl_encode_full(dest + counter + nr_written, 4U /* TODO */,
			                     &ts_stride_sdvl_len, ts_stride))
			{
				rohc_comp_warn(context, "failed to SDVL-encode TS_STRIDE %u",
				               ts_stride);
				/* TODO: should handle error gracefully */
				assert(0);
			}
			rohc_comp_debug(context, "send TS_STRIDE = 0x%08x encoded with SDVL "
			                "on %zu bytes", ts_stride, ts_stride_sdvl_len);

			/* skip the bytes used to encode TS_STRIDE in SDVL */
			nr_written += ts_stride_sdvl_len;

			/* do we transmit the scaled RTP Timestamp (TS) in the next packet ? */
			rtp_context->ts_sc.nr_init_stride_packets++;
			if(rtp_context->ts_sc.nr_init_stride_packets >= ROHC_INIT_TS_STRIDE_MIN)
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted at least %u "
				                "times, so change from state INIT_STRIDE to "
				                "SEND_SCALED", ROHC_INIT_TS_STRIDE_MIN);
				rtp_context->ts_sc.state = SEND_SCALED;
			}
			else
			{
				rohc_comp_debug(context, "TS_STRIDE transmitted only %zd times, "
				                "so stay in state INIT_STRIDE (at least %u times "
				                "are required to change to state SEND_SCALED)",
				                rtp_context->ts_sc.nr_init_stride_packets,
				                ROHC_INIT_TS_STRIDE_MIN);
			}
		}

		/* part 9 not supported yet */
	}

	return counter + nr_written;
}


/**
 * @brief Check if the dynamic part of the UDP/RTP headers changed.
 *
 * @param context The compression context
 * @param udp     The UDP header
 * @param rtp     The RTP header
 * @return        The number of UDP/RTP fields that changed
 */
static int rtp_changed_rtp_dynamic(const struct rohc_comp_ctxt *const context,
                                   const struct udphdr *const udp,
                                   const struct rtphdr *const rtp)
{
	struct c_generic_context *g_context;
	struct sc_rtp_context *rtp_context;
	int fields = 0;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	rohc_comp_debug(context, "find changes in RTP dynamic fields");

	/* check UDP checksum field */
	if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
	   (udp->check == 0 && rtp_context->old_udp.check != 0) ||
	   (rtp_context->udp_checksum_change_count < MAX_IR_COUNT))
	{
		if((udp->check != 0 && rtp_context->old_udp.check == 0) ||
		   (udp->check == 0 && rtp_context->old_udp.check != 0))
		{
			rohc_comp_debug(context, "UDP checksum field changed");
			rtp_context->udp_checksum_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "UDP checksum field did not change but "
			                "changed in the last few packets");
		}

		/* do not count the UDP checksum change as other RTP dynamic fields
		 * because it requires a specific behaviour (IR or IR-DYN packet
		 * required). */
	}

	/* check RTP CSRC Counter and CSRC field */
	if(rtp->cc != rtp_context->old_rtp.cc)
	{
		rohc_comp_debug(context, "RTP CC field changed (0x%x -> 0x%x)",
		                rtp_context->old_rtp.cc, rtp->cc);
		fields += 2;
	}

	/* check SSRC field */
	if(rtp->ssrc != rtp_context->old_rtp.ssrc)
	{
		rohc_comp_debug(context, "RTP SSRC field changed (0x%08x -> 0x%08x)",
		                rtp_context->old_rtp.ssrc, rtp->ssrc);
		fields++;
	}

	/* check RTP Marker field: remember its value but do not count it
	 * as a changed field since it is not stored in the context */
	if(rtp->m != 0)
	{
		rohc_comp_debug(context, "RTP Marker (M) bit is set");
		rtp_context->tmp.is_marker_bit_set = true;
	}
	else
	{
		rtp_context->tmp.is_marker_bit_set = false;
	}

	/* check RTP Padding field */
	if(rtp->padding != rtp_context->old_rtp.padding ||
	   rtp_context->rtp_padding_change_count < MAX_IR_COUNT)
	{
		if(rtp->padding != rtp_context->old_rtp.padding)
		{
			rohc_comp_debug(context, "RTP Padding (P) bit changed (0x%x -> 0x%x)",
			                rtp_context->old_rtp.padding, rtp->padding);
			rtp_context->tmp.padding_bit_changed = true;
			rtp_context->rtp_padding_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP Padding (P) bit did not change but "
			                "changed in the last few packets");
			rtp_context->tmp.padding_bit_changed = false;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.padding_bit_changed = false;
	}

	/* check RTP eXtension (X) field */
	if(rtp->extension != rtp_context->old_rtp.extension ||
	   rtp_context->rtp_extension_change_count < MAX_IR_COUNT)
	{
		if(rtp->extension != rtp_context->old_rtp.extension)
		{
			rohc_comp_debug(context, "RTP eXtension (X) bit changed (0x%x -> "
			                "0x%x)", rtp_context->old_rtp.extension,
			                rtp->extension);
			rtp_context->tmp.extension_bit_changed = true;
			rtp_context->rtp_extension_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP eXtension (X) bit did not change but "
			                "changed in the last few packets");
			rtp_context->tmp.extension_bit_changed = false;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.extension_bit_changed = false;
	}

	/* check RTP Payload Type field */
	if(rtp->pt != rtp_context->old_rtp.pt ||
	   rtp_context->rtp_pt_change_count < MAX_IR_COUNT)
	{
		if(rtp->pt != rtp_context->old_rtp.pt)
		{
			rohc_comp_debug(context, "RTP Payload Type (PT) field changed "
			                "(0x%x -> 0x%x)", rtp_context->old_rtp.pt, rtp->pt);
			rtp_context->tmp.rtp_pt_changed = 1;
			rtp_context->rtp_pt_change_count = 0;
		}
		else
		{
			rohc_comp_debug(context, "RTP Payload Type (PT) field did not "
			                "change but changed in the last few packets");
			rtp_context->tmp.rtp_pt_changed = 0;
		}

		fields++;
	}
	else
	{
		rtp_context->tmp.rtp_pt_changed = 0;
	}

	/* we verify if ts_stride changed */
	if(rtp_context->ts_sc.state != SEND_SCALED)
	{
		rohc_comp_debug(context, "TS_STRIDE changed now or in the last few "
		                "packets");
		fields++;
	}

	rohc_comp_debug(context, "%d RTP dynamic fields changed", fields);

	return fields;
}


/**
 * @brief Tells if the selected profile uses the RTP port
 *
 * This function is one of the functions that must exist in one profile for the
 * framework to work.
 *
 * @param context The compression context
 * @param port    The port number to check
 * @return        true if the profile uses this port, false otherwise
 */
static bool c_rtp_use_udp_port(const struct rohc_comp_ctxt *const context,
                                    const unsigned int port)
{
	const struct c_generic_context *g_context;
	const struct sc_rtp_context *rtp_context;

	g_context = (struct c_generic_context *) context->specific;
	rtp_context = (struct sc_rtp_context *) g_context->specific;

	return (rtp_context->old_udp.dest == port);
}


/**
 * @brief Define the compression part of the RTP profile as described
 *        in the RFC 3095.
 */
const struct rohc_comp_profile c_rtp_profile =
{
	.id             = ROHC_PROFILE_RTP, /* profile ID */
	.protocol       = ROHC_IPPROTO_UDP, /* IP protocol */
	.create         = c_rtp_create,     /* profile handlers */
	.destroy        = c_rtp_destroy,
	.check_profile  = c_rtp_check_profile,
	.check_context  = c_rtp_check_context,
	.encode         = c_rtp_encode,
	.reinit_context = c_generic_reinit_context,
	.feedback       = c_generic_feedback,
	.use_udp_port   = c_rtp_use_udp_port,
};

