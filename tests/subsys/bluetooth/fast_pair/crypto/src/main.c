/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <ztest.h>
#include "fp_crypto.h"

static void test_sha256(void)
{
	const uint8_t input_data[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

	const uint8_t hashed_result[] = {0xBB, 0x00, 0x0D, 0xDD, 0x92, 0xA0, 0xA2, 0xA3, 0x46, 0xF0,
					 0xB5, 0x31, 0xF2, 0x78, 0xAF, 0x06, 0xE3, 0x70, 0xF8, 0x69,
					 0x32, 0xCC, 0xAF, 0xCC, 0xC8, 0x92, 0xD6, 0x8D, 0x35, 0x0F,
					 0x80, 0xF8};

	uint8_t result_buf[FP_SHA256_HASH_LEN];

	zassert_equal(sizeof(result_buf), sizeof(hashed_result),
		      "Invalid size of expected result.");
	zassert_ok(fp_sha256(result_buf, input_data, sizeof(input_data)),
		   "Error during hashing data.");
	zassert_mem_equal(result_buf, hashed_result, sizeof(hashed_result),
			  "Invalid hashing result.");
}

static void test_aes128(void)
{
	const uint8_t plaintext[] = {0xF3, 0x0F, 0x4E, 0x78, 0x6C, 0x59, 0xA7, 0xBB, 0xF3, 0x87,
				     0x3B, 0x5A, 0x49, 0xBA, 0x97, 0xEA};

	const uint8_t key[] = {0xA0, 0xBA, 0xF0, 0xBB, 0x95, 0x1F, 0xF7, 0xB6, 0xCF, 0x5E, 0x3F,
			       0x45, 0x61, 0xC3, 0x32, 0x1D};

	const uint8_t ciphertext[] = {0xAC, 0x9A, 0x16, 0xF0, 0x95, 0x3A, 0x3F, 0x22, 0x3D, 0xD1,
				      0x0C, 0xF5, 0x36, 0xE0, 0x9E, 0x9C};

	uint8_t result_buf[FP_AES128_BLOCK_LEN];

	zassert_equal(sizeof(result_buf), sizeof(ciphertext), "Invalid size of expected result.");
	zassert_ok(fp_aes128_encrypt(result_buf, plaintext, key), "Error during value encryption.");
	zassert_mem_equal(result_buf, ciphertext, sizeof(ciphertext), "Invalid encryption result.");

	zassert_equal(sizeof(result_buf), sizeof(plaintext), "Invalid size of expected result.");
	zassert_ok(fp_aes128_decrypt(result_buf, ciphertext, key),
		   "Error during value decryption.");
	zassert_mem_equal(result_buf, plaintext, sizeof(plaintext), "Invalid decryption result.");
}

static void test_ecdh(void)
{
	const uint8_t bobs_private_key[] = {0x02, 0xB4, 0x37, 0xB0, 0xED, 0xD6, 0xBB, 0xD4, 0x29,
					    0x06, 0x4A, 0x4E, 0x52, 0x9F, 0xCB, 0xF1, 0xC4, 0x8D,
					    0x0D, 0x62, 0x49, 0x24, 0xD5, 0x92, 0x27, 0x4B, 0x7E,
					    0xD8, 0x11, 0x93, 0xD7, 0x63};

	const uint8_t bobs_public_key[] = {0xF7, 0xD4, 0x96, 0xA6, 0x2E, 0xCA, 0x41, 0x63, 0x51,
					   0x54, 0x0A, 0xA3, 0x43, 0xBC, 0x69, 0x0A, 0x61, 0x09,
					   0xF5, 0x51, 0x50, 0x06, 0x66, 0xB8, 0x3B, 0x12, 0x51,
					   0xFB, 0x84, 0xFA, 0x28, 0x60, 0x79, 0x5E, 0xBD, 0x63,
					   0xD3, 0xB8, 0x83, 0x6F, 0x44, 0xA9, 0xA3, 0xE2, 0x8B,
					   0xB3, 0x40, 0x17, 0xE0, 0x15, 0xF5, 0x97, 0x93, 0x05,
					   0xD8, 0x49, 0xFD, 0xF8, 0xDE, 0x10, 0x12, 0x3B, 0x61,
					   0xD2};

	const uint8_t alices_private_key[] = {0xD7, 0x5E, 0x54, 0xC7, 0x7D, 0x76, 0x24, 0x89, 0xE5,
					      0x7C, 0xFA, 0x92, 0x37, 0x43, 0xF1, 0x67, 0x77, 0xA4,
					      0x28, 0x3D, 0x99, 0x80, 0x0B, 0xAC, 0x55, 0x58, 0x48,
					      0x38, 0x93, 0xE5, 0xB0, 0x6D};

	const uint8_t alices_public_key[] = {0x36, 0xAC, 0x68, 0x2C, 0x50, 0x82, 0x15, 0x66, 0x8F,
					     0xBE, 0xFE, 0x24, 0x7D, 0x01, 0xD5, 0xEB, 0x96, 0xE6,
					     0x31, 0x8E, 0x85, 0x5B, 0x2D, 0x64, 0xB5, 0x19, 0x5D,
					     0x38, 0xEE, 0x7E, 0x37, 0xBE, 0x18, 0x38, 0xC0, 0xB9,
					     0x48, 0xC3, 0xF7, 0x55, 0x20, 0xE0, 0x7E, 0x70, 0xF0,
					     0x72, 0x91, 0x41, 0x9A, 0xCE, 0x2D, 0x28, 0x14, 0x3C,
					     0x5A, 0xDB, 0x2D, 0xBD, 0x98, 0xEE, 0x3C, 0x8E, 0x4F,
					     0xBF};

	const uint8_t shared_key[] = {0x9D, 0xAD, 0xE4, 0xF8, 0x6A, 0xC3, 0x48, 0x8B, 0xBA, 0xC2,
				      0xAC, 0x34, 0xB5, 0xFE, 0x68, 0xA0, 0xEE, 0x5A, 0x67, 0x06,
				      0xF5, 0x43, 0xD9, 0x06, 0x1A, 0xD5, 0x78, 0x89, 0x49, 0x8A,
				      0xE6, 0xBA};

	uint8_t bobs_result_buf[FP_ECDH_SHARED_KEY_LEN];
	uint8_t alices_result_buf[FP_ECDH_SHARED_KEY_LEN];

	zassert_equal(sizeof(bobs_result_buf), sizeof(shared_key),
		      "Invalid size of expected result.");
	zassert_ok(fp_ecdh_shared_secret(alices_public_key, bobs_private_key, bobs_result_buf),
		   "Error during key computing.");
	zassert_equal(sizeof(alices_result_buf), sizeof(shared_key),
		      "Invalid size of expected result.");
	zassert_ok(fp_ecdh_shared_secret(bobs_public_key, alices_private_key, alices_result_buf),
		   "Error during key computing.");
	zassert_mem_equal(bobs_result_buf, shared_key, sizeof(shared_key),
			  "Invalid key on Bob's side.");
	zassert_mem_equal(alices_result_buf, shared_key, sizeof(shared_key),
			  "Invalid key on Alice's side.");
}

void test_main(void)
{
	ztest_test_suite(fast_pair_crypto_tests,
			 ztest_unit_test(test_sha256),
			 ztest_unit_test(test_aes128),
			 ztest_unit_test(test_ecdh)
			 );

	ztest_run_test_suite(fast_pair_crypto_tests);
}
