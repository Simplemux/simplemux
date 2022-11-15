/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2007,2008 Thales Alenia Space
 * Copyright 2007,2009,2010,2012,2014 Viveris Technologies
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
 * @file c_udp.h
 * @brief ROHC compression context for the UDP profile.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#ifndef ROHC_COMP_UDP_H
#define ROHC_COMP_UDP_H

#include "rohc_comp_internals.h"

#include <stdint.h>
#include <stdbool.h>


/*
 * Function prototypes.
 */

bool c_udp_check_profile(const struct rohc_comp *const comp,
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

bool c_udp_check_context(const struct rohc_comp_ctxt *context,
                         const struct net_pkt *const packet)
	__attribute__((warn_unused_result, nonnull(1, 2)));

size_t udp_code_uo_remainder(const struct rohc_comp_ctxt *context,
                             const unsigned char *next_header,
                             unsigned char *const dest,
                             const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

size_t udp_code_static_udp_part(const struct rohc_comp_ctxt *const context,
                                const unsigned char *const next_header,
                                unsigned char *const dest,
                                const size_t counter)
	__attribute__((warn_unused_result, nonnull(1, 2, 3)));

#endif

