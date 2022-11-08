/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010 Viveris Technologies
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
 * @file   ip_id_offset.h
 * @brief  Offset IP-ID decoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#ifndef ROHC_DECOMP_IP_ID_OFFSET_H
#define ROHC_DECOMP_IP_ID_OFFSET_H

#include <stdint.h>
#include <stdlib.h>
#ifdef __KERNEL__
#	include <linux/types.h>
#else
#	include <stdbool.h>
#endif

#include "dllexport.h"


/* The definition of the Offset IP-ID decoding object is private */
struct ip_id_offset_decode;


/*
 * Function prototypes.
 */

struct ip_id_offset_decode * ROHC_EXPORT ip_id_offset_new(void);

void ROHC_EXPORT ip_id_offset_free(struct ip_id_offset_decode *const ipid)
	__attribute__((nonnull(1)));

bool ROHC_EXPORT ip_id_offset_decode(const struct ip_id_offset_decode *const ipid,
                                     const uint16_t m,
                                     const size_t k,
                                     const uint32_t sn,
                                     uint16_t *const decoded)
	__attribute__((nonnull(1, 5), warn_unused_result));

void ROHC_EXPORT ip_id_offset_set_ref(struct ip_id_offset_decode *const ipid,
                                      const uint16_t id_ref,
                                      const uint32_t sn_ref)
	__attribute__((nonnull(1)));

#endif

