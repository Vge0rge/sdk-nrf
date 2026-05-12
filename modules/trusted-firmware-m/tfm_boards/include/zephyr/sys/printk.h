/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef __ZEPHYR_SYS_PRINTK_H
#define __ZEPHYR_SYS_PRINTK_H

/* Compatebility header for using Zephyr API in TF-M.
 *
 * The macros and functions here can be used by code that is common for both
 * Zephyr and TF-M RTOS.
 *
 * The functionality will be forwarded to TF-M equivalent of the Zephyr API.
 */

/*
 * Forward-declare tfm_log_unpriv() instead of including <tfm_log_unpriv.h> so
 * that consumers of this Zephyr-compat shim header do not need the TF-M
 * unprivileged-log include path on their own target. The symbol is resolved
 * at link time by whichever component pulls in the tfm_log_unpriv library.
 */
#if defined(__ICCARM__)
#pragma __printf_args
void tfm_log_unpriv(const char *fmt, ...);
#else
__attribute__((format(printf, 1, 2)))
void tfm_log_unpriv(const char *fmt, ...);
#endif

#define printk(fmt, ...) tfm_log_unpriv(fmt, ##__VA_ARGS__)

#endif /* __ZEPHYR_SYS_PRINTK_H */
