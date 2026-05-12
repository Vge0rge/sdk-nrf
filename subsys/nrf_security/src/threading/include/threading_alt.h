/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

#include <zephyr/kernel.h>

typedef struct k_mutex *mbedtls_platform_mutex_t;

/* Unused, but needs to be defined. */
typedef int mbedtls_platform_condition_variable_t;

#endif /* MBEDTLS_THREADING_ALT_H */
