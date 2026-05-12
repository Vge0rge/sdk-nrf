/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <mbedtls/threading.h>
#include <zephyr/kernel.h>

K_MUTEX_DEFINE(key_slot_mutex);
K_MUTEX_DEFINE(psa_globaldata_mutex);
K_MUTEX_DEFINE(psa_rngdata_mutex);
K_MUTEX_DEFINE(heap_mutex);

mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex = {
	.MBEDTLS_PRIVATE(mutex) = &key_slot_mutex,
};
mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex = {
	.MBEDTLS_PRIVATE(mutex) = &psa_globaldata_mutex,
};
mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex = {
	.MBEDTLS_PRIVATE(mutex) = &psa_rngdata_mutex,
};
mbedtls_threading_mutex_t mbedtls_threading_heap_mutex = {
	.MBEDTLS_PRIVATE(mutex) = &heap_mutex,
};

void mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	/* No need to do anything, the mutexes are already initialized by K_MUTEX_DEFINE(). */
}

void mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
}

int mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	return k_mutex_lock(mutex->MBEDTLS_PRIVATE(mutex), K_FOREVER);
}

int mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	return k_mutex_unlock(mutex->MBEDTLS_PRIVATE(mutex));
}
