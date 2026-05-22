/*
 * Copyright (c) 2026 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/*
 * To be used as MBEDTLS_PLATFORM_STD_PRINTF inside the TF-M secure image.
 * Without this, taking the address of libc printf (the mbedtls default) pulls
 * picolibc's stdio into tfm_s.
 *
 * When TF-M is built without secure log output (TFM_SP_LOG_RAW_ENABLED=OFF),
 * tfm_hal_output_sp_log() is not provided and tfm_vprintf_unpriv() cannot be
 * linked. In that case fall back to a silent no-op.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

int nrf_security_tfm_printf(const char *fmt, ...)
{
	(void)fmt;
	return 0;
}

#ifndef NRF_SECURITY_TFM_HAS_SP_LOG
/*
 * tfm_log_unpriv.o (linked in via the Zephyr-compat __assert.h shim and the
 * cracen driver) unconditionally references tfm_hal_output_sp_log(). That
 * symbol is only provided by TF-M when a secure UART is enabled
 * (TFM_SP_LOG_RAW_ENABLED=ON). Provide a silent stub so logging is dropped
 * instead of failing the link.
 */
int32_t tfm_hal_output_sp_log(const char *str, size_t len)
{
	(void)str;
	return (int32_t)len;
}
#endif




