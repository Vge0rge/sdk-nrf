/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef __ZEPHYR_LOGGING_LOG_H__
#define __ZEPHYR_LOGGING_LOG_H__

/* Compatebility header for using Zephyr API in TF-M.
 *
 * The macros and functions here can be used by code that is common for both
 * Zephyr and TF-M RTOS.
 *
 * The functionality will be forwarded to TF-M equivalent of the Zephyr API.
 */

/*
 * TF-M's old per-partition logger (tfm_sp_log.h) and SPM logger (tfm_spm_log.h)
 * were replaced by the new unprivileged logging API (tfm_log_unpriv.h) in
 * upstream commit 1f2c7fdb4 ("LIB: Move partitions to use new logging API").
 *
 * The macros LOG_ERRFMT/LOG_WRNFMT/LOG_INFFMT/LOG_DBGFMT and SPMLOG_*MSG no
 * longer exist; they are replaced by ERROR_UNPRIV/WARN_UNPRIV/INFO_UNPRIV/
 * VERBOSE_UNPRIV (and the *_RAW variants).
 *
 * Consumers of this header must link against a TF-M target that pulls in
 * tfm_log_unpriv_headers and defines LOG_LEVEL_UNPRIV (e.g. tfm_sprt or
 * tfm_config).
 */
#include "tfm_log_unpriv.h"

#define LOG_MODULE_DECLARE(...)
#define LOG_MODULE_REGISTER(...)

#define LOG_ERR(fmt, ...) ERROR_UNPRIV(fmt "\r\n", ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) WARN_UNPRIV(fmt "\r\n", ##__VA_ARGS__)
#define LOG_INF(fmt, ...) INFO_UNPRIV(fmt "\r\n", ##__VA_ARGS__)
#define LOG_DBG(fmt, ...) VERBOSE_UNPRIV(fmt "\r\n", ##__VA_ARGS__)

/* This can be used for simple messages before the SPM is initialized in thread
 * mode. The legacy SPMLOG_*MSG macros are no longer available; route these to
 * the unprivileged logging API as well, which is the closest equivalent.
 */
#define LOG_ERR_MSG(msg) ERROR_UNPRIV(msg "\r\n")
#define LOG_INF_MSG(msg) INFO_UNPRIV(msg "\r\n")
#define LOG_DBG_MSG(msg) VERBOSE_UNPRIV(msg "\r\n")

#endif /* __ZEPHYR_LOGGING_LOG_H__ */
