/*
 * Copyright 2013 Didier Barvaux
 * Copyright 2013 Viveris Technologies
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
 * @file    test_wlsb.c
 * @brief   Test W-LSB decoding
 * @author  Didier Barvaux <didier.barvaux@toulouse.viveris.com>
 */

#include "wlsb.h"

#include <setjmp.h>
#include <stddef.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>


/** Stub for \ref rohc_f_32bits */
struct rohc_interval32 __wrap_rohc_f_32bits(const uint32_t v_ref,
                                            const size_t k,
                                            const rohc_lsb_shift_t p)
{
	struct rohc_interval32 interval;

	check_expected(v_ref);
	check_expected(k);
	check_expected(p);

	interval.min = mock_type(uint32_t);
	interval.max = mock_type(uint32_t);

	return interval;
}


/** Test \ref test_lsb_new */
static void test_lsb_new(void **state)
{
	struct rohc_lsb_decode *lsb;

	/* 32-bit LSB */
	lsb = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 32);
	assert_true(lsb != NULL);
	rohc_lsb_free(lsb);

	/* 16-bit LSB */
	lsb = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 16);
	assert_true(lsb != NULL);
	rohc_lsb_free(lsb);

#if 0 /* TODO: enable this when all assert() of the library are replaced */
	lsb = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 0);
	assert_true(lsb == NULL);
#endif
}


/** Test \ref test_lsb_decode */
static void test_lsb_decode(void **state)
{
	const struct
	{
		bool used;
		uint32_t min;
		uint32_t max;
		uint32_t m;
		size_t k;
		bool exp_status;
		uint32_t exp_value;
	} tests[] = {
		/* used          min          max            m   k   exp_status    exp_value */
		/* full interval + limits of the interval */
		{  true,         0x0,  0xffffffff,         0x0,  5,        true,         0x0 },
		{  true,         0x0,  0xffffffff,  0xffffffff, 32,        true,  0xffffffff },
		/* full interval + small/medium/large values */
		{  true,         0x0,  0xffffffff,         0x2,  5,        true,         0x2 },
		{  true,         0x0,  0xffffffff,  0x7fffffff, 31,        true,  0x7fffffff },
		{  true,         0x0,  0xffffffff,  0xfffffffd, 32,        true,  0xfffffffd },
		/* zero interval */
		{  true,      0x4242,      0x4242,         0x0,  0,        true,      0x4242 },
		{  true,      0x4242,      0x4242,         0x0,  1,        true,      0x4242 },
		{  true,      0x4242,      0x4242,  0x00004242, 32,        true,      0x4242 },
		{  true,      0x4242,      0x4242,         0x1,  1,       false,         0x0 },
		/* small interval (no wraparound) */
		{  true,      0x4242,      0x42ff,         0x0,  0,        true,      0x4242 },
		{  true,      0x4242,      0x42ff,         0x0,  1,        true,      0x4242 },
		{  true,      0x4242,      0x42ff,         0x1,  1,        true,      0x4243 },
		{  true,      0x4242,      0x42ff,         0xf,  4,        true,      0x424f },
		{  true,      0x4242,      0x42ff,        0xff,  8,        true,      0x42ff },
		{  true,      0x4242,      0x4341,        0x41,  8,        true,      0x4341 },
		{  true,      0x4242,      0x42ff,        0x41,  8,       false,         0x0 },
		/* small interval (wraparound) */
		{  true,  0xfffffffd,        0xff,         0x0,  0,        true,  0xfffffffd },
		{  true,  0xfffffffd,        0xff,         0x1,  1,        true,  0xfffffffd },
		{  true,  0xfffffffd,        0xff,         0x0,  1,        true,  0xfffffffe },
		{  true,  0xfffffffd,        0xff,         0xf,  4,        true,  0xffffffff },
		{  true,  0xfffffffd,        0xff,        0xff,  8,        true,  0xffffffff },
		{  true,  0xfffffffd,        0xff,        0x41,  8,        true,        0x41 },
		{  true,  0xfffffffd,        0x40,        0x41,  8,       false,         0x0 },
		/* end of tests */
		{ false,         0x0,         0x0,         0x0,  0,       false,         0x0 },
	};
	struct rohc_lsb_decode *lsb;
	size_t test_num;

	lsb = rohc_lsb_new(ROHC_LSB_SHIFT_RTP_TS, 32);
	assert_true(lsb != NULL);

	rohc_lsb_set_ref(lsb, 0, false);

	for(test_num = 0; tests[test_num].used; test_num++)
	{
		uint32_t decoded;
		bool ret;

		printf("decode %zu-bit m 0x%08x in interval [0x%08x ; 0x%08x] (expected %s)\n",
		       tests[test_num].k, tests[test_num].m, tests[test_num].min,
		       tests[test_num].max, tests[test_num].exp_status ? "success" : "failure");

		expect_value(__wrap_rohc_f_32bits, v_ref, 0);
		expect_value(__wrap_rohc_f_32bits, k, tests[test_num].k);
		expect_value(__wrap_rohc_f_32bits, p, ROHC_LSB_SHIFT_RTP_TS);
		will_return(__wrap_rohc_f_32bits, tests[test_num].min);
		will_return(__wrap_rohc_f_32bits, tests[test_num].max);
		ret = rohc_lsb_decode(lsb, ROHC_LSB_REF_0, 0, tests[test_num].m,
		                      tests[test_num].k, ROHC_LSB_SHIFT_RTP_TS,
		                      &decoded);
		assert_true(ret == tests[test_num].exp_status);
		if(ret)
		{
			assert_true(decoded == tests[test_num].exp_value);
		}
		printf("\n");
	}

	rohc_lsb_free(lsb);
}


/**
 * @brief Test LSB encoding/decoding
 *
 * @param argc  The number of command line arguments
 * @param argv  The command line arguments
 * @return      0 if test succeeds, non-zero if test fails
 */
int main(int argc, char *argv[])
{
	const UnitTest tests[] = {
		unit_test(test_lsb_new),
		unit_test(test_lsb_decode),
	};
	return run_tests(tests);
}

