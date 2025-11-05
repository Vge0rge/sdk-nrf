/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef CRACEN_PSA_BUILTIN_IDS_H
#define CRACEN_PSA_BUILTIN_IDS_H

#include "common.h"
#include <psa/crypto.h>
#include <psa/crypto_values.h>
//#include <cracen/ec_helpers.h>
//#include <cracen/mem_helpers.h>
//#include <cracen/statuscodes.h>
//#include <cracen_psa.h>
//#include <cracen_psa_eddsa.h>
//#include <cracen_psa_ecdsa.h>
//#include <cracen_psa_montgomery.h>
//#include <cracen_psa_ikg.h>
//#include <cracen_psa_rsa_keygen.h>
//#include <nrf_security_mutexes.h>
//#include <silexpk/sxops/rsa.h>
//#include <silexpk/ik.h>
//#include <stddef.h>
//#include <string.h>

//#include "tfm_plat_crypto_keys.h"
//#include "tfm_builtin_key_ids.h"
//#include "tfm_builtin_key_loader.h"
//#include "psa_manifest/pid.h"
//#include "tfm_spm_log.h"
//#include "crypto_library.h"

//#include <identity_key.h>

#define NUMBER_OF_ELEMENTS_OF(x) sizeof(x)/sizeof(*x)

#define MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID (-0x3c000000)

typedef struct
{
    int32_t user;
    psa_drv_slot_number_t key_slot;
} cracen_builtin_ikg_key_policy_t;

typedef enum{
    KMU_ENTRY_SLOT_SINGLE,
    KMU_ENTRY_SLOT_RANGE,
} cracen_kmu_entry_type_t;

typedef struct
{
    int32_t user;
    psa_drv_slot_number_t key_slot_start;
    psa_drv_slot_number_t key_slot_end;
    cracen_kmu_entry_type_t kmu_entry_type;
} cracen_builtin_kmu_key_policy_t;

bool cracen_builtin_ikg_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes);

bool cracen_builtin_kmu_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes);

#endif /* CRACEN_PSA_BUILTIN_IDS_H */
