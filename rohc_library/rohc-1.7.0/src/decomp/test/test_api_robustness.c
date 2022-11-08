/*
 * Copyright 2013,2014 Didier Barvaux
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
 * @file    test_api_robustness.c
 * @brief   Test the robustness of the decompression API
 * @author  Didier Barvaux <didier@barvaux.org>
 */

#include "rohc_decomp.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


/** Print trace on stdout only in verbose mode */
#define trace(is_verbose, format, ...) \
	do { \
		if(is_verbose) { \
			printf(format, ##__VA_ARGS__); \
		} \
	} while(0)

/** Improved assert() */
#define CHECK(condition) \
	do { \
		trace(verbose, "test '%s'\n", #condition); \
		fflush(stdout); \
		assert(condition); \
	} while(0)


/**
 * @brief Test the robustness of the decompression API
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	struct rohc_decomp *decomp;
	bool verbose; /* whether to run in verbose mode or not */
	int is_failure = 1; /* test fails by default */

	/* do we run in verbose mode ? */
	if(argc == 1)
	{
		/* no argument, run in silent mode */
		verbose = false;
	}
	else if(argc == 2 && strcmp(argv[1], "verbose") == 0)
	{
		/* run in verbose mode */
		verbose = true;
	}
	else
	{
		/* invalid usage */
		printf("test the robustness of the decompression API\n");
		printf("usage: %s [verbose]\n", argv[0]);
		goto error;
	}

	/* rohc_decomp_new2() */
	CHECK(rohc_decomp_new2(-1, ROHC_SMALL_CID_MAX, ROHC_U_MODE) == NULL);
	CHECK(rohc_decomp_new2(ROHC_SMALL_CID + 1, ROHC_SMALL_CID_MAX, ROHC_U_MODE) == NULL);
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, 0, ROHC_U_MODE);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX + 1, ROHC_U_MODE) == NULL);
	decomp = rohc_decomp_new2(ROHC_LARGE_CID, 0, ROHC_U_MODE);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	decomp = rohc_decomp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX, ROHC_U_MODE);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);
	CHECK(rohc_decomp_new2(ROHC_LARGE_CID, ROHC_LARGE_CID_MAX + 1, ROHC_U_MODE) == NULL);
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	CHECK(decomp != NULL);
	rohc_decomp_free(decomp);

	decomp = rohc_decomp_new2(ROHC_LARGE_CID, ROHC_SMALL_CID_MAX, ROHC_O_MODE);
	CHECK(decomp != NULL);

	/* rohc_decomp_set_traces_cb2() */
	{
		rohc_trace_callback2_t fct = (rohc_trace_callback2_t) NULL;
		CHECK(rohc_decomp_set_traces_cb2(NULL, fct, NULL) == false);
		CHECK(rohc_decomp_set_traces_cb2(decomp, fct, NULL) == true);
		CHECK(rohc_decomp_set_traces_cb2(decomp, fct, decomp) == true);
	}

	/* rohc_decomp_profile_enabled() */
	CHECK(rohc_decomp_profile_enabled(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_GENERAL) == false);
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UNCOMPRESSED) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_RTP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_ESP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_IP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDPLITE) == true);
#else
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UNCOMPRESSED) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_ESP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDPLITE) == false);
#endif /* !ROHC_ENABLE_DEPRECATED_API */

	/* rohc_decomp_enable_profile() */
	CHECK(rohc_decomp_enable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_enable_profile(decomp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_decomp_enable_profile(decomp, ROHC_PROFILE_IP) == true);

	/* rohc_decomp_disable_profile() */
	CHECK(rohc_decomp_disable_profile(NULL, ROHC_PROFILE_IP) == false);
	CHECK(rohc_decomp_disable_profile(decomp, ROHC_PROFILE_GENERAL) == false);
	CHECK(rohc_decomp_disable_profile(decomp, ROHC_PROFILE_IP) == true);

	/* rohc_decomp_enable_profiles() */
	CHECK(rohc_decomp_enable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_IP, -1) == true);
	CHECK(rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_IP, ROHC_PROFILE_UDP,
	                                  ROHC_PROFILE_RTP, -1) == true);

	/* rohc_decomp_disable_profiles() */
	CHECK(rohc_decomp_disable_profiles(NULL, ROHC_PROFILE_IP, -1) == false);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_GENERAL, -1) == false);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_UDP, -1) == true);
	CHECK(rohc_decomp_disable_profiles(decomp, ROHC_PROFILE_UDP,
	                                   ROHC_PROFILE_RTP, -1) == true);

	/* rohc_decomp_profile_enabled() */
#if !defined(ROHC_ENABLE_DEPRECATED_API) || ROHC_ENABLE_DEPRECATED_API == 1
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UNCOMPRESSED) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_ESP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_IP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDPLITE) == true);
#else
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UNCOMPRESSED) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_RTP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_ESP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_IP) == true);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_TCP) == false);
	CHECK(rohc_decomp_profile_enabled(decomp, ROHC_PROFILE_UDPLITE) == false);
#endif /* !ROHC_ENABLE_DEPRECATED_API */

	/* rohc_decomp_set_mrru() */
	CHECK(rohc_decomp_set_mrru(NULL, 10) == false);
	CHECK(rohc_decomp_set_mrru(decomp, 65535 + 1) == false);
	CHECK(rohc_decomp_set_mrru(decomp, 0) == true);
	CHECK(rohc_decomp_set_mrru(decomp, 65535) == true);

	/* rohc_decomp_get_mrru() */
	{
		size_t mrru;
		CHECK(rohc_decomp_get_mrru(NULL, &mrru) == false);
		CHECK(rohc_decomp_get_mrru(decomp, NULL) == false);
		CHECK(rohc_decomp_get_mrru(decomp, &mrru) == true);
		CHECK(mrru == 65535);
	}

	/* rohc_decomp_get_max_cid() */
	{
		size_t max_cid;
		CHECK(rohc_decomp_get_max_cid(NULL, &max_cid) == false);
		CHECK(rohc_decomp_get_max_cid(decomp, NULL) == false);
		CHECK(rohc_decomp_get_max_cid(decomp, &max_cid) == true);
		CHECK(max_cid == ROHC_SMALL_CID_MAX);
	}

	/* rohc_decomp_get_cid_type() */
	{
		rohc_cid_type_t cid_type;
		CHECK(rohc_decomp_get_cid_type(NULL, &cid_type) == false);
		CHECK(rohc_decomp_get_cid_type(decomp, NULL) == false);
		CHECK(rohc_decomp_get_cid_type(decomp, &cid_type) == true);
		CHECK(cid_type == ROHC_LARGE_CID);
	}

	/* rohc_decompress3() */
	{
		const struct rohc_ts ts = { .sec = 0, .nsec = 0 };
		unsigned char buf1[1];
		struct rohc_buf pkt1 = rohc_buf_init_full(buf1, 1, ts);
		unsigned char buf2[100];
		struct rohc_buf pkt2 = rohc_buf_init_empty(buf2, 100);
		unsigned char buf[] =
		{
			0xfd, 0x00, 0x04, 0xce,  0x40, 0x01, 0xc0, 0xa8,
			0x13, 0x01, 0xc0, 0xa8,  0x13, 0x05, 0x00, 0x40,
			0x00, 0x00, 0xa0, 0x00,  0x00, 0x01, 0x08, 0x00,
			0xe9, 0xc2, 0x9b, 0x42,  0x00, 0x01, 0x66, 0x15,
			0xa6, 0x45, 0x77, 0x9b,  0x04, 0x00, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d,  0x0e, 0x0f, 0x10, 0x11,
			0x12, 0x13, 0x14, 0x15,  0x16, 0x17, 0x18, 0x19,
			0x1a, 0x1b, 0x1c, 0x1d,  0x1e, 0x1f, 0x20, 0x21,
			0x22, 0x23, 0x24, 0x25,  0x26, 0x27, 0x28, 0x29,
			0x2a, 0x2b, 0x2c, 0x2d,  0x2e, 0x2f, 0x30, 0x31,
			0x32, 0x33, 0x34, 0x35,  0x36, 0x37
		};
		struct rohc_buf pkt = rohc_buf_init_full(buf, sizeof(buf), ts);
		CHECK(rohc_decompress3(NULL, pkt1, &pkt2, NULL, NULL) == ROHC_STATUS_ERROR);
		CHECK(pkt2.len == 0);
		pkt1.len = 0;
		CHECK(rohc_decompress3(decomp, pkt1, &pkt2, NULL, NULL) == ROHC_STATUS_ERROR);
		CHECK(pkt2.len == 0);
		pkt1.len = 1;
		CHECK(rohc_decompress3(decomp, pkt1, NULL, NULL, NULL) == ROHC_STATUS_ERROR);
		CHECK(pkt2.len == 0);
		pkt2.max_len = 0;
		pkt2.offset = 0;
		pkt2.len = 0;
		CHECK(rohc_decompress3(decomp, pkt, &pkt2, NULL, NULL) == ROHC_STATUS_ERROR);
		CHECK(pkt2.len == 0);
		for(size_t i = 1; i < (pkt.len - 2); i++)
		{
			pkt2.max_len = i;
			pkt2.offset = 0;
			pkt2.len = 0;
			CHECK(rohc_decompress3(decomp, pkt, &pkt2, NULL, NULL) == ROHC_STATUS_OUTPUT_TOO_SMALL);
			CHECK(pkt2.len == 0);
		}
		pkt2.max_len = pkt.len - 2;
		pkt2.offset = 0;
		pkt2.len = 0;
		CHECK(rohc_decompress3(decomp, pkt, &pkt2, NULL, NULL) == ROHC_STATUS_OK);
		CHECK(pkt2.len > 0);
	}

	/* rohc_decomp_get_last_packet_info() */
	{
		rohc_decomp_last_packet_info_t info;
		memset(&info, 0, sizeof(rohc_decomp_last_packet_info_t));
		CHECK(rohc_decomp_get_last_packet_info(NULL, &info) == false);
		CHECK(rohc_decomp_get_last_packet_info(decomp, NULL) == false);
		info.version_major = 0xffff;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == false);
		info.version_major = 0;
		info.version_minor = 0xffff;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == false);
		info.version_minor = 0;
		CHECK(rohc_decomp_get_last_packet_info(decomp, &info) == true);
	}

	/* rohc_decomp_get_general_info() */
	{
		rohc_decomp_general_info_t info;
		memset(&info, 0, sizeof(rohc_decomp_general_info_t));
		CHECK(rohc_decomp_get_general_info(NULL, &info) == false);
		CHECK(rohc_decomp_get_general_info(decomp, NULL) == false);
		info.version_major = 0xffff;
		CHECK(rohc_decomp_get_general_info(decomp, &info) == false);
		info.version_major = 0;
		info.version_minor = 0xffff;
		CHECK(rohc_decomp_get_general_info(decomp, &info) == false);
		info.version_minor = 0;
		CHECK(rohc_decomp_get_general_info(decomp, &info) == true);
	}


	/* rohc_decomp_get_state_descr() */
	CHECK(strcmp(rohc_decomp_get_state_descr(ROHC_DECOMP_STATE_NC), "No Context") == 0);
	CHECK(strcmp(rohc_decomp_get_state_descr(ROHC_DECOMP_STATE_SC), "Static Context") == 0);
	CHECK(strcmp(rohc_decomp_get_state_descr(ROHC_DECOMP_STATE_FC), "Full Context") == 0);

	/* rohc_decomp_free() */
	rohc_decomp_free(NULL);
	rohc_decomp_free(decomp);

	/* test succeeds */
	trace(verbose, "all tests are successful\n");
	is_failure = 0;

error:
	return is_failure;
}

