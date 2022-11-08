/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file   test_segment.c
 * @brief  Check that ROHC segments are handled as expected
 * @author Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses ROHC packets, doing segmentation if needed.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <stdarg.h>

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>


/** The max size */
#define TEST_MAX_ROHC_SIZE  (5U * 1024U)


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const size_t ip_packet_len,
                                const size_t mrru,
                                const bool is_comp_expected_ok,
                                const size_t expected_segments_nr);
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));


/**
 * @brief Check that the decompression of the ROHC packets read in the capture
 *        generates a FEEDBACK-2 packet of the expected type with the expected
 *        feedback options.
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc != 1)
	{
		usage();
		goto error;
	}

	/* test ROHC segments with small packet (wrt output buffer) and large MRRU
	 * => no segmentation needed */
	status = test_comp_and_decomp(100, TEST_MAX_ROHC_SIZE * 2, true, 0);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with large packet (wrt output buffer) and large MRRU,
	 * => segmentation needed */
	status |= test_comp_and_decomp(TEST_MAX_ROHC_SIZE,
	                               TEST_MAX_ROHC_SIZE * 2, true, 2);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with large packet (wrt output buffer) and MRRU = 0,
	 * ie. segments disabled => segmentation needed but impossible */
	status |= test_comp_and_decomp(TEST_MAX_ROHC_SIZE, 0, false, 0);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with very large packet (wrt output buffer) and large
	 * MRRU => segmentation needed, more than 2 segments expected */
	status |= test_comp_and_decomp(TEST_MAX_ROHC_SIZE * 2,
	                               TEST_MAX_ROHC_SIZE * 3, true, 3);
	if(status != 0)
	{
		goto error;
	}

	/* test ROHC segments with very large packet (wrt output buffer) and large
	 * MRRU (but not large enough) => segmentation needed, but MRRU forbids it */
	status |= test_comp_and_decomp(TEST_MAX_ROHC_SIZE * 2, TEST_MAX_ROHC_SIZE,
	                               false, 0);
	if(status != 0)
	{
		goto error;
	}

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that ROHC segments are handled as expected\n"
	        "\n"
	        "usage: test_segment [OPTIONS]\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with one IP packet of given length and the
 *        given MRRU
 *
 * @param ip_packet_len         The size of the IP packet to generate for the
 *                              test
 * @param mrru                  The MRRU for the test
 * @param is_comp_expected_ok   Whether compression is expected to be
 *                              successful or not?
 * @parma expected_segments_nr  The number of ROHC segments that we expect
 *                              for the test
 * @return                      0 in case of success,
 *                              1 in case of failure
 */
static int test_comp_and_decomp(const size_t ip_packet_len,
                                const size_t mrru,
                                const bool is_comp_expected_ok,
                                const size_t expected_segments_nr)
{
//! [define ROHC compressor]
	struct rohc_comp *comp;
//! [define ROHC compressor]
//! [define ROHC decompressor]
	struct rohc_decomp *decomp;
//! [define ROHC decompressor]

	struct ipv4_hdr *ip_header;
	uint8_t ip_buffer[TEST_MAX_ROHC_SIZE * 3];
	struct rohc_buf ip_packet =
		rohc_buf_init_empty(ip_buffer, TEST_MAX_ROHC_SIZE * 3);

	uint8_t rohc_buffer[TEST_MAX_ROHC_SIZE];
	struct rohc_buf rohc_packet =
		rohc_buf_init_empty(rohc_buffer, TEST_MAX_ROHC_SIZE);

	uint8_t uncomp_buffer[TEST_MAX_ROHC_SIZE * 3];
	struct rohc_buf uncomp_packet =
		rohc_buf_init_empty(uncomp_buffer, TEST_MAX_ROHC_SIZE * 3);

	size_t segments_nr;

	int is_failure = 1;
	rohc_status_t status;
	size_t i;

	fprintf(stderr, "test ROHC segments with %zd-byte IP packet and "
	        "MMRU = %zd bytes\n", ip_packet_len, mrru);

	/* check that buffer for IP packet is large enough */
	if(ip_packet_len > TEST_MAX_ROHC_SIZE * 3)
	{
		fprintf(stderr, "size requested for IP packet is too large\n");
		goto error;
	}

	/* initialize the random generator with the same number to ease debugging */
	srand(4 /* chosen by fair dice roll, guaranteed to be random */);

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                      gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto error;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable profiles */
	if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
	                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the compression profiles\n");
		goto destroy_comp;
	}

//! [set compressor MRRU]
	/* set the MRRU at compressor */
	if(!rohc_comp_set_mrru(comp, mrru))
	{
		fprintf(stderr, "failed to set the MRRU at compressor\n");
		goto destroy_comp;
	}
//! [set compressor MRRU]

	/* create the ROHC decompressor in uni-directional mode */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "decompressor\n");
		goto destroy_decomp;
	}

//! [set decompressor MRRU]
	/* set the MRRU at decompressor */
	if(!rohc_decomp_set_mrru(decomp, mrru))
	{
		fprintf(stderr, "failed to set the MRRU at decompressor\n");
		goto destroy_decomp;
	}
//! [set decompressor MRRU]

	/* enable decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* generate the IP packet of the given length */
	ip_packet.len = ip_packet_len;
	ip_header = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
	ip_header->version = 4; /* we create an IPv4 header */
	ip_header->ihl = 5; /* minimal IPv4 header length (in 32-bit words) */
	ip_header->tos = 0;
	ip_header->tot_len = htons(ip_packet_len);
	ip_header->id = 0;
	ip_header->frag_off = 0;
	ip_header->ttl = 1;
	ip_header->protocol = 134; /* unassigned number according to /etc/protocols */
	ip_header->check = 0; /* set to 0 for checksum computation */
	ip_header->saddr = htonl(0x01020304);
	ip_header->daddr = htonl(0x05060708);
	if(ip_packet_len == 100)
	{
		ip_header->check = htons(0xa901);
	}
	else if(ip_packet_len == TEST_MAX_ROHC_SIZE)
	{
		ip_header->check = htons(0x9565);
	}
	else if(ip_packet_len == TEST_MAX_ROHC_SIZE * 2)
	{
		ip_header->check = htons(0x8165);
	}
	else
	{
		/* compute the IP checksum for your test length */
		assert(0);
	}
	for(i = sizeof(struct ipv4_hdr); i < ip_packet_len; i++)
	{
		rohc_buf_byte_at(ip_packet, i) = i & 0xff;
	}

	/* compress the IP packet */
	segments_nr = 0;
//! [segment ROHC packet #1]
	status = rohc_compress4(comp, ip_packet, &rohc_packet);
	if(status == ROHC_STATUS_SEGMENT)
	{
		/* ROHC segmentation is required to compress the IP packet */
//! [segment ROHC packet #1]
		fprintf(stderr, "\tROHC segments are required to compress the IP "
		        "packet\n");
		assert(rohc_packet.len == 0);

//! [segment ROHC packet #2]
		/* get the segments */
		while((status = rohc_comp_get_segment2(comp, &rohc_packet)) == ROHC_STATUS_SEGMENT)
		{
			/* new ROHC segment retrieved */
//! [segment ROHC packet #2]
			fprintf(stderr, "\t%zd-byte ROHC segment generated\n",
			        rohc_packet.len);
			segments_nr++;

			/* decompress segment */
			status = rohc_decompress3(decomp, rohc_packet, &uncomp_packet,
			                          NULL, NULL);
			if(status != ROHC_STATUS_OK)
			{
				fprintf(stderr, "\tfailed to decompress ROHC segment packet\n");
				goto destroy_decomp;
			}
//! [segment ROHC packet #3]
			if(uncomp_packet.len > 0)
			{
				fprintf(stderr, "\tdecompression of ROHC segment succeeded while "
				        "it should have not\n");
				goto destroy_decomp;
			}
			rohc_packet.len = 0;
		}
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "failed to generate ROHC segment (status = %d)\n",
			        status);
			goto destroy_decomp;
		}
		/* final ROHC segment retrieved */
//! [segment ROHC packet #3]
		fprintf(stderr, "\t%zd-byte final ROHC segment generated\n",
		        rohc_packet.len);
		segments_nr++;

		/* decompress last segment */
		status = rohc_decompress3(decomp, rohc_packet, &uncomp_packet,
		                          NULL, NULL);
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to decompress ROHC segments\n");
			goto destroy_decomp;
		}
//! [segment ROHC packet #4]
		if(uncomp_packet.len == 0)
		{
			fprintf(stderr, "\tdecompression of ROHC segment failed while it "
			        "should have succeeded\n");
			goto destroy_decomp;
		}
	}
	else if(status != ROHC_STATUS_OK)
	{
//! [segment ROHC packet #4]
		if(is_comp_expected_ok)
		{
			fprintf(stderr, "\tfailed to compress ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\texpected failure to compress packet\n");
	}
	else if(!is_comp_expected_ok)
	{
		fprintf(stderr, "\tunexpected success to compress packet\n");
		goto destroy_decomp;
	}
	else
	{
		fprintf(stderr, "\t%zu-byte ROHC packet generated\n", rohc_packet.len);

		/* decompress ROHC packet */
		status = rohc_decompress3(decomp, rohc_packet, &uncomp_packet,
		                          NULL, NULL);
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to decompress ROHC packet\n");
			goto destroy_decomp;
		}
	}

	/* check the number of generated segments */
	if(expected_segments_nr != segments_nr)
	{
		fprintf(stderr, "\tunexpected number of segment(s): %zd segment(s) "
		        "generated while %zu expected\n", segments_nr,
		        expected_segments_nr);
		goto destroy_decomp;
	}
	fprintf(stderr, "\t%zd segment(s) generated as expected\n", segments_nr);

	/* check that decompressed packet matches the original IP packet */
	if(is_comp_expected_ok)
	{
		if(ip_packet.len != uncomp_packet.len)
		{
			fprintf(stderr, "\t%zu-byte decompressed packet does not match "
			        "original %zu-byte IP packet: different lengths\n",
			        uncomp_packet.len, ip_packet.len);
			goto destroy_decomp;
		}
		if(memcmp(rohc_buf_data(ip_packet), rohc_buf_data(uncomp_packet),
		          ip_packet.len) != 0)
		{
			fprintf(stderr, "\t%zu-byte decompressed packet does not match "
			        "original %zu-byte IP packet\n", uncomp_packet.len,
			        ip_packet.len);
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompressed ROHC packet/segments match the "
		        "original IP packet\n");
	}

	/* everything went fine */
	fprintf(stderr, "\n");
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
error:
	return is_failure;
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
}


/**
 * @brief Generate a random number
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              A random number
 */
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return rand();
}

