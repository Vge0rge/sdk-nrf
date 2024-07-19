/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include <cracen_psa.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS	    (0)
#define APP_ERROR	    (-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE   "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)                                                            \
	({                                                                                         \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          \
		LOG_INF("---- %s end  ----", p_label);                                             \
	})

LOG_MODULE_REGISTER(nrf54l_kmu, LOG_LEVEL_DBG);

static psa_key_handle_t key_handle;

#define KMU_SLOT_NUM 100

/*
!!! DON'T USE THIS KEY IN PRODUCTION !!!
This is a sample public key for demonstration purposes only.
*/
static uint8_t m_pub_key[32] = {
	0x29, 0x06, 0xA6, 0xA5, 0x5F, 0x9E, 0xB0, 0x5E,
	0x19, 0xC0, 0x41, 0xB8, 0x58, 0xB1, 0xB9, 0x5D,
	0x51, 0xA3, 0xD9, 0x3F, 0x4D, 0x29, 0x0D, 0x86,
	0xBE, 0x7C, 0x96, 0xD6, 0x2D, 0x3B, 0xB2, 0x5E};

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int main(void)
{
	psa_status_t status;

	LOG_INF("Starting KMU keys example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_PURE_EDDSA);
	psa_set_key_type(&key_attributes,
			 PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
	psa_set_key_bits(&key_attributes, 255);

	/* Persistent key specific settings */
	psa_set_key_lifetime(&key_attributes,
			     PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
				     PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_CRACEN_KMU));
	psa_set_key_id(&key_attributes, PSA_KEY_HANDLE_FROM_CRACEN_KMU_SLOT(CRACEN_KMU_KEY_USAGE_SCHEME_RAW, KMU_SLOT_NUM));



	status = psa_import_key(&key_attributes, m_pub_key, sizeof(m_pub_key), &key_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key returned %d", status);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
