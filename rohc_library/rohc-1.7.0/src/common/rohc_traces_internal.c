/*
 * Copyright 2012,2013 Didier Barvaux
 * Copyright 2009,2010 Thales Communications
 * Copyright 2012 Viveris Technologies
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
 * @file   rohc_traces_internal.c
 * @brief  ROHC for traces
 * @author Julien Bernard <julien.bernard@toulouse.viveris.com>
 * @author Audric Schiltknecht <audric.schiltknecht@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_traces_internal.h"
#include "rohc_buf.h"
#include "rohc_utils.h"

#include <stdio.h> /* for snprintf(3) */
#include <assert.h>


/**
 * @brief Dump the content of the given packet
 *
 * @param trace_cb      The old function to log traces
 * @param trace_cb2     The new function to log traces
 * @param trace_cb_priv An optional private context, may be NULL
 * @param trace_entity  The entity that emits the traces
 * @param trace_level   The priority level for the trace
 * @param descr         The description of the packet to dump
 * @param packet        The packet to dump
 */
void rohc_dump_packet(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                      const rohc_trace_callback_t trace_cb,
#endif
                      const rohc_trace_callback2_t trace_cb2,
                      void *const trace_cb_priv,
                      const rohc_trace_entity_t trace_entity,
                      const rohc_trace_level_t trace_level,
                      const char *const descr,
                      const struct rohc_buf packet)
{
	assert(descr != NULL);
	assert(!rohc_buf_is_malformed(packet));

	rohc_dump_buf(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	              trace_cb,
#endif
	              trace_cb2, trace_cb_priv,
	              trace_entity, trace_level, descr,
	              rohc_buf_data(packet), rohc_min(packet.len, 100U));
}


/**
 * @brief Dump the content of the given buffer
 *
 * @param trace_cb      The old function to log traces
 * @param trace_cb2     The new function to log traces
 * @param trace_cb_priv An optional private context, may be NULL
 * @param trace_entity  The entity that emits the traces
 * @param trace_level   The priority level for the trace
 * @param descr         The description of the packet to dump
 * @param packet        The packet to dump
 * @param length        The length (in bytes) of the packet to dump
 */
void rohc_dump_buf(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
                   const rohc_trace_callback_t trace_cb,
#endif
                   const rohc_trace_callback2_t trace_cb2,
                   void *const trace_cb_priv,
                   const rohc_trace_entity_t trace_entity,
                   const rohc_trace_level_t trace_level,
                   const char *const descr,
                   const unsigned char *const packet,
                   const size_t length)
{
	assert(descr != NULL);
	assert(packet != NULL);

	if(length == 0)
	{
		__rohc_print(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
		             trace_cb,
#endif
		             trace_cb2, trace_cb_priv,
		             ROHC_TRACE_DEBUG, trace_entity, ROHC_PROFILE_GENERAL,
		             "%s (0 byte)", descr);
	}
	else
	{
		const size_t byte_width = 3; /* 'XX ' */
		const size_t byte_nr = 16; /* 16 bytes per line */
		const size_t column_width = 2; /* spaces between 8 1st/last bytes */
		const size_t line_max = byte_width * byte_nr + column_width;
		char line[line_max + 1];
		size_t line_index;
		size_t i;

		__rohc_print(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
		             trace_cb,
#endif
		             trace_cb2, trace_cb_priv,
		             trace_level, trace_entity, ROHC_PROFILE_GENERAL,
		             "%s (%zd bytes):", descr, length);
		line_index = 0;
		for(i = 0; i < length; i++)
		{
			if(i > 0 && (i % 16) == 0)
			{
				assert(line_index <= line_max);
				line[line_index] = '\0';
				__rohc_print(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
				             trace_cb,
#endif
				             trace_cb2, trace_cb_priv,
				             trace_level, trace_entity, ROHC_PROFILE_GENERAL,
				             "%s", line);
				line_index = 0;
			}
			else if(i > 0 && (i % 8) == 0)
			{
				assert(line_index <= (line_max - column_width));
				snprintf(line + line_index, column_width + 1, "  ");
				line_index += column_width;
			}
			assert(line_index <= (line_max - byte_width));
			snprintf(line + line_index, byte_width + 1, "%02x ", packet[i]);
			line_index += byte_width;
		}

		/* flush incomplete line */
		if(line_index > 0)
		{
			assert(line_index <= line_max);
			line[line_index] = '\0';
			__rohc_print(
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
			             trace_cb,
#endif
			             trace_cb2, trace_cb_priv,
			             trace_level, trace_entity, ROHC_PROFILE_GENERAL,
			             "%s", line);
		}
	}
}

