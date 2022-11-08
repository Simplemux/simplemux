/*
 * Copyright 2007,2008 CNES
 * Copyright 2011,2012,2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2010 Viveris Technologies
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
 * @file rtp.h
 * @brief RTP header
 * @author David Moreau from TAS
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * See section 5.1 of RFC 1889 for details.
 */

#ifndef ROHC_PROTOCOLS_RTP_H
#define ROHC_PROTOCOLS_RTP_H

#include <stdint.h>

#ifdef __KERNEL__
#	include <endian.h>
#else
#	include "config.h" /* for WORDS_BIGENDIAN */
#endif


/**
 * @brief The RTP header
 *
 * See section 5.1 of RFC 1889 for details.
 */
struct rtphdr
{
#if WORDS_BIGENDIAN == 1
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t cc:4;
	uint16_t m:1;
	uint16_t pt:7;
#else
	uint16_t cc:4;          ///< CSRC Count
	uint16_t extension:1;   ///< Extension bit
	uint16_t padding:1;     ///< Padding bit
	uint16_t version:2;     ///< RTP version
	uint16_t pt:7;          ///< Payload Type
	uint16_t m:1;           ///< Marker
#endif
	uint16_t sn;            ///< Sequence Number
	uint32_t timestamp;     ///< Timestamp
	uint32_t ssrc;          ///< Synchronization SouRCe (SSRC) identifier
} __attribute__((packed));


#endif

