/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#include <zephyr/kernel.h>

#if defined(CONFIG_PSA_CRYPTO_DRIVER_CC3XX)

#include <nrf_cc3xx_platform_mutex.h>

typedef nrf_cc3xx_platform_mutex_t mbedtls_platform_mutex_t;

#else

typedef struct k_mutex *mbedtls_platform_mutex_t;

#endif

/* Unused, but needs to be defined. */
typedef int mbedtls_platform_condition_variable_t;

#endif /* MBEDTLS_THREADING_ALT_H */
