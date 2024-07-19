/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <cracen_psa.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS		(0)
#define APP_ERROR		(-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)\
	({\
		LOG_INF("---- %s (len: %u): ----", p_label, len);\
		LOG_HEXDUMP_INF(p_text, len, "Content:");\
		LOG_INF("---- %s end  ----", p_label);\
	})

LOG_MODULE_REGISTER(eddsa, LOG_LEVEL_DBG);

/* Global variables/defines for the EDDSA example */

#define NRF_CRYPTO_EXAMPLE_EDDSA_TEXT_SIZE (100)

#define NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE (64)

/* Below text is used as plaintext for signing/verification */
static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_EDDSA_TEXT_SIZE] = {
	"Example string to demonstrate basic usage of EDDSA."
};

#define KMU_SLOT_NUM 100

static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE] = {
	0x81, 0xf5, 0x22, 0xd3, 0xa1, 0x6d, 0x26, 0x0d, 0xc8, 0xc4, 0xd6, 0xbd, 0x51, 0xf0, 0xf8, 0x46,
	0x09, 0xdc, 0x00, 0x85, 0x60, 0x56, 0x99, 0xbd, 0xc3, 0x97, 0x5e, 0xa6, 0x6f, 0x7d, 0x0c, 0x97,
	0xd9, 0xeb, 0xf0, 0x1c, 0xeb, 0xff, 0xbd, 0x6f, 0x16, 0x7b, 0xa8, 0x58, 0x7f, 0xc2, 0x86, 0xbb,
	0x5e, 0x8d, 0x46, 0xef, 0xf0, 0x58, 0x41, 0xe5, 0xac, 0x42, 0x2c, 0xd1, 0xed, 0x29, 0x74, 0x0e
};

/*
!!! DON'T USE THESE KEYS IN PRODUCTION !!!
This is a sample private key for demonstration purposes only.
In a real application, the private key should be securely generated and stored.

These keys are shown because the public key needs to be programmed to the device
in order to verify the signature.

static uint8_t m_priv_key[32] ={
	0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21
};

static uint8_t m_precalculated_pub_key[32] = {
	0x29, 0x06, 0xA6, 0xA5, 0x5F, 0x9E, 0xB0, 0x5E,
	0x19, 0xC0, 0x41, 0xB8, 0x58, 0xB1, 0xB9, 9x5D,
	0x51, 0xA3, 0xD9, 0x3F, 0x4D, 0x29, 0x0D, 0x86,
	0xBE, 0x7C, 0x96, 0xD6, 0x2D, 0x3B, 0xB2, 0x5E
};

*/

static psa_key_handle_t key_handle;

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_crypto_init failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}


int get_eddsa_pub_key(void)
{
	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	key_handle = PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(CRACEN_KMU_KEY_USAGE_SCHEME_RAW, KMU_SLOT_NUM);
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	if (psa_get_key_attributes(key_handle, &attr) != PSA_SUCCESS){
		LOG_INF("psa_get_key_attributes failed!");
		return APP_ERROR;

	}

	/* Reset key attributes and free any allocated resources. */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int verify_message(void)
{
	psa_status_t status;

	LOG_INF("Verifying EDDSA signature...");

	if(get_eddsa_pub_key() != APP_SUCCESS){
		LOG_INF("get_eddsa_pub_key failed!");
		return APP_ERROR;
	}

	/* Verify the signature of the message */
	status = psa_verify_message(key_handle,
				    PSA_ALG_PURE_EDDSA,
				    m_plain_text,
				    sizeof(m_plain_text),
				    m_signature,
				    NRF_CRYPTO_EXAMPLE_EDDSA_SIGNATURE_SIZE);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_message failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

int main(void)
{
	int status;

	LOG_INF("Starting EDDSA example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = verify_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
