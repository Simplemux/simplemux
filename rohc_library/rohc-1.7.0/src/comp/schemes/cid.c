/*
 * Copyright 2010,2011,2012,2013 Didier Barvaux
 * Copyright 2007,2009,2010,2012 Viveris Technologies
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
 * @file cid.c
 * @brief Context ID (CID) routines.
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "cid.h"
#include "sdvl.h"

#include <stdint.h>
#include <assert.h>


/*
 * Prototypes of private functions
 */

static uint8_t c_add_cid(const int cid)
	__attribute__((warn_unused_result, const));


/*
 * Definitions of functions that may used by other ROHC modules
 */

/**
 * @brief Build the CID part of the ROHC packets.
 *
 * @param cid_type       The type of CID in use for the compression context:
 *                       ROHC_SMALL_CID or ROHC_LARGE_CID
 * @param cid            The value of the CID for the compression context
 * @param dest           The rohc-packet-under-build buffer
 * @param dest_size      The length of the rohc-packet-under-build buffer
 * @param first_position OUT: The position of the first byte to be completed
 *                       by other functions
 * @return               The position in the rohc-packet-under-build buffer
 *                       in case of success, -1 in case of error
 */
int code_cid_values(const rohc_cid_type_t cid_type,
                    const int cid,
                    unsigned char *const dest,
                    const size_t dest_size,
                    size_t *const first_position)
{
	size_t counter = 0;

	/* small CID */
	if(cid_type == ROHC_SMALL_CID)
	{
		if(cid > 0)
		{
			/* Add-CID */
			if(dest_size < 2)
			{
				goto error;
			}
			dest[counter] = c_add_cid(cid);
			*first_position = 1;
			counter = 2;
		}
		else
		{
			/* no Add-CID */
			if(dest_size < 1)
			{
				goto error;
			}
			*first_position = 0;
			counter = 1;
		}
	}
	else /* large CID */
	{
		size_t sdvl_len;

		*first_position = 0;
		counter++;

		/* SDVL-encode the large CID */
		if(!sdvl_encode_full(dest + counter, dest_size, &sdvl_len, cid))
		{
			/* failed to SDVL-encode the large CID */
			goto error;
		}
		else if(sdvl_len != 1 && sdvl_len != 2)
		{
			/* SDVL-encoded large CID shall be 1 or 2 byte long */
			goto error;
		}
		counter += sdvl_len;
	}

	return counter;

error:
	return -1;
}


/*
 * Definitions of private functions
 */


/**
 * @brief Set an add-CID value.
 *
 * Add-CID is needed when using small CIDs.
 *
 * @param cid The small CID to set
 * @return    The add-CID byte
 */
static uint8_t c_add_cid(const int cid)
{
	const uint8_t add_cid_type = 0xe0;

	assert(cid >= 0 && cid <= ROHC_SMALL_CID_MAX);

	return (add_cid_type | (cid & 0x0f));
}

