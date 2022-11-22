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
 * @file sdvl.c
 * @brief Self-Describing Variable-Length (SDVL) encoding
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 */

#include "sdvl.h"
#include "rohc_bit_ops.h"

#include <assert.h>


/** The maximum values that can be SDVL-encoded in 1, 2, 3 and 4 bytes */
typedef enum
{
	/** Maximum value in 1 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_1_BYTE = ((1 << ROHC_SDVL_MAX_BITS_IN_1_BYTE) - 1),
	/** Maximum value in 2 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_2_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_2_BYTES) - 1),
	/** Maximum value in 3 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_3_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_3_BYTES) - 1),
	/** Maximum value in 4 SDVL-encoded byte */
	ROHC_SDVL_MAX_VALUE_IN_4_BYTES = ((1 << ROHC_SDVL_MAX_BITS_IN_4_BYTES) - 1),
} rohc_sdvl_max_value_t;


/**
 * @brief Can the given value be encoded with SDVL?
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param value  The value to encode
 * @return       Whether the value can be encoded with SDVL or not
 */
bool sdvl_can_value_be_encoded(const uint32_t value)
{
	return (value <= ROHC_SDVL_MAX_VALUE_IN_4_BYTES);
}


/**
 * @brief Is the given length (in bits) compatible with SDVL?
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param bits_nr  The length (in bits) of the value to encode
 * @return         Whether the value can be encoded with SDVL or not
 */
bool sdvl_can_length_be_encoded(const size_t bits_nr)
{
	return (bits_nr <= ROHC_SDVL_MAX_BITS_IN_4_BYTES);
}


/**
 * @brief Find out how many SDVL bits are needed to represent a value
 *
 * The number of bits already encoded in another field may be specified.
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param nr_min_required  The minimum required number of bits to encode
 * @param nr_encoded       The number of bits already encoded in another field
 * @return                 The number of bits needed to encode the value
 */
size_t sdvl_get_min_len(const size_t nr_min_required,
                        const size_t nr_encoded)
{
	size_t nr_needed;

	if(nr_min_required <= nr_encoded)
	{
		nr_needed = 0;
	}
	else
	{
		const size_t remaining = nr_min_required - nr_encoded;

		assert(remaining <= ROHC_SDVL_MAX_BITS_IN_4_BYTES);

		if(remaining <= ROHC_SDVL_MAX_BITS_IN_1_BYTE)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_1_BYTE;
		}
		else if(remaining <= ROHC_SDVL_MAX_BITS_IN_2_BYTES)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_2_BYTES;
		}
		else if(remaining <= ROHC_SDVL_MAX_BITS_IN_3_BYTES)
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_3_BYTES;
		}
		else
		{
			nr_needed = ROHC_SDVL_MAX_BITS_IN_4_BYTES;
		}
	}

	assert((nr_encoded + nr_needed) >= nr_min_required);

	return nr_needed;
}


/**
 * @brief Find out how many bytes are needed to represent the value using
 *        Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param value  The value to encode
 * @return       The size needed to represent the SDVL-encoded value
 */
size_t sdvl_get_encoded_len(const uint32_t value)
{
	size_t size;

	/* find the length for SDVL-encoding */
	if(value <= ROHC_SDVL_MAX_VALUE_IN_1_BYTE)
	{
		size = 1;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_2_BYTES)
	{
		size = 2;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_3_BYTES)
	{
		size = 3;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_4_BYTES)
	{
		size = 4;
	}
	else
	{
		/* value is too large for SDVL-encoding */
		size = 5;
	}

	return size;
}


/**
 * @brief Encode a value using Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * Encoding failures may be due to a value greater than 2^29.
 *
 * @param sdvl_bytes         IN/OUT: The SDVL-encoded bytes
 * @param sdvl_bytes_max_nr  The maximum available free bytes for SDVL
 * @param sdvl_bytes_nr      OUT: The number of SDVL bytes written
 * @param value              The value to encode
 * @param bits_nr            The number of bits to encode
 * @return                   true if SDVL encoding is successful,
 *                           false in case of failure
 */
bool sdvl_encode(uint8_t *const sdvl_bytes,
                 const size_t sdvl_bytes_max_nr,
                 size_t *const sdvl_bytes_nr,
                 const uint32_t value,
                 const size_t bits_nr)
{
	/* encoding 0 bit is an error */
	assert(bits_nr > 0);

	/* encode the value according to the number of available bits */
	if(bits_nr <= ROHC_SDVL_MAX_BITS_IN_1_BYTE)
	{
		*sdvl_bytes_nr = 1;
		if(sdvl_bytes_max_nr < (*sdvl_bytes_nr))
		{
			/* number of bytes needed is too large for buffer */
			goto error;
		}

		/* bit pattern 0 */
		sdvl_bytes[0] = value & 0x7f;
	}
	else if(bits_nr <= ROHC_SDVL_MAX_BITS_IN_2_BYTES)
	{
		*sdvl_bytes_nr = 2;
		if(sdvl_bytes_max_nr < (*sdvl_bytes_nr))
		{
			/* number of bytes needed is too large for buffer */
			goto error;
		}

		/* 2 = bit pattern 10 */
		sdvl_bytes[0] = ((2 << 6) | ((value >> 8) & 0x3f)) & 0xff;
		sdvl_bytes[1] = value & 0xff;
	}
	else if(bits_nr <= ROHC_SDVL_MAX_BITS_IN_3_BYTES)
	{
		*sdvl_bytes_nr = 3;
		if(sdvl_bytes_max_nr < (*sdvl_bytes_nr))
		{
			/* number of bytes needed is too large for buffer */
			goto error;
		}

		/* 6 = bit pattern 110 */
		sdvl_bytes[0] = ((6 << 5) | ((value >> 16) & 0x1f)) & 0xff;
		sdvl_bytes[1] = (value >> 8) & 0xff;
		sdvl_bytes[2] = value & 0xff;
	}
	else if(bits_nr <= ROHC_SDVL_MAX_BITS_IN_4_BYTES)
	{
		*sdvl_bytes_nr = 4;
		if(sdvl_bytes_max_nr < (*sdvl_bytes_nr))
		{
			/* number of bytes needed is too large for buffer */
			goto error;
		}

		/* 7 = bit pattern 111 */
		sdvl_bytes[0] = ((7 << 5) | ((value >> 24) & 0x1f)) & 0xff;
		sdvl_bytes[1] = (value >> 16) & 0xff;
		sdvl_bytes[2] = (value >> 8) & 0xff;
		sdvl_bytes[3] = value & 0xff;
	}
	else
	{
		/* number of bytes needed is too large (value must be < 2^29) */
		goto error;
	}

	return true;

error:
	return false;
}


/**
 * @brief Encode a value using Self-Describing Variable-Length (SDVL) encoding
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * Encoding failures may be due to a value greater than 2^29.
 *
 * @param sdvl_bytes         IN/OUT: The SDVL-encoded bytes
 * @param sdvl_bytes_max_nr  The maximum available free bytes for SDVL
 * @param sdvl_bytes_nr      OUT: The number of SDVL bytes written
 * @param value              The value to encode
 * @return                   true if SDVL encoding is successful,
 *                           false in case of failure
 */
bool sdvl_encode_full(uint8_t *const sdvl_bytes,
                      const size_t sdvl_bytes_max_nr,
                      size_t *const sdvl_bytes_nr,
                      const uint32_t value)
{
	size_t bits_nr;

	/* find the number of bits for SDVL-encoding */
	if(value <= ROHC_SDVL_MAX_VALUE_IN_1_BYTE)
	{
		bits_nr = ROHC_SDVL_MAX_BITS_IN_1_BYTE;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_2_BYTES)
	{
		bits_nr = ROHC_SDVL_MAX_BITS_IN_2_BYTES;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_3_BYTES)
	{
		bits_nr = ROHC_SDVL_MAX_BITS_IN_3_BYTES;
	}
	else if(value <= ROHC_SDVL_MAX_VALUE_IN_4_BYTES)
	{
		bits_nr = ROHC_SDVL_MAX_BITS_IN_4_BYTES;
	}
	else
	{
		/* value is too large for SDVL-encoding */
		goto error;
	}

	return sdvl_encode(sdvl_bytes, sdvl_bytes_max_nr, sdvl_bytes_nr,
	                   value, bits_nr);

error:
	return false;
}


/**
 * @brief Decode a Self-Describing Variable-Length (SDVL) value
 *
 * See 4.5.6 in the RFC 3095 for details about SDVL encoding.
 *
 * @param data     The SDVL data to decode
 * @param length   The maximum data length available (in bytes)
 * @param value    OUT: The decoded value
 * @param bits_nr  OUT: The number of useful bits
 * @return         The number of bytes used by the SDVL field (value between
 *                 1 and 4), 0 in case of problem
 */
size_t sdvl_decode(const uint8_t *const data,
                   const size_t length,
                   uint32_t *const value,
                   size_t *const bits_nr)
{
	size_t sdvl_len;

	if(length < 1)
	{
		/* packet too small to decode SDVL field */
		goto error;
	}

	if(!GET_BIT_7(data)) /* bit == 0 */
	{
		*value = GET_BIT_0_6(data);
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_1_BYTE;
		sdvl_len = 1;
	}
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) /* bits == 0b10 */
	{
		if(length < 2)
		{
			/* packet too small to decode SDVL field */
			goto error;
		}
		*value = (GET_BIT_0_5(data) << 8 | GET_BIT_0_7(data + 1));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_2_BYTES;
		sdvl_len = 2;
	}
	else if(GET_BIT_5_7(data) == (0xc >> 1)) /* bits == 0b110 */
	{
		if(length < 3)
		{
			/* packet too small to decode SDVL field */
			goto error;
		}
		*value = (GET_BIT_0_4(data) << 16 |
		          GET_BIT_0_7(data + 1) << 8 |
		          GET_BIT_0_7(data + 2));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_3_BYTES;
		sdvl_len = 3;
	}
	else if(GET_BIT_5_7(data) == (0xe >> 1)) /* bits == 0b111 */
	{
		if(length < 4)
		{
			/* packet too small to decode SDVL field */
			goto error;
		}
		*value = (GET_BIT_0_4(data) << 24 |
		          GET_BIT_0_7(data + 1) << 16 |
		          GET_BIT_0_7(data + 2) << 8 |
		          GET_BIT_0_7(data + 3));
		*bits_nr = ROHC_SDVL_MAX_BITS_IN_4_BYTES;
		sdvl_len = 4;
	}
	else
	{
		/* bad SDVL-encoded field length */
		goto error;
	}

	return sdvl_len;

error:
	return 0;
}

