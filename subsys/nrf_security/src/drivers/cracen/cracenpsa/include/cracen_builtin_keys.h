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

#ifdef CONFIG_BUILD_WITH_TFM

typedef struct
{
    mbedtls_key_owner_id_t user;
    psa_drv_slot_number_t key_slot;
} cracen_builtin_ikg_key_policy_t;

typedef enum{
    KMU_ENTRY_SLOT_SINGLE,
    KMU_ENTRY_SLOT_RANGE,
} cracen_kmu_entry_type_t;

typedef struct
{
    mbedtls_key_owner_id_t user;
    psa_drv_slot_number_t key_slot_start;
    psa_drv_slot_number_t key_slot_end;
    cracen_kmu_entry_type_t kmu_entry_type;
} cracen_builtin_kmu_key_policy_t;

bool cracen_builtin_ikg_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes);

bool cracen_builtin_kmu_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes);

#else 

static inline bool cracen_builtin_ikg_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes)
{
    (void) slot_number;
    (void) attributes;
    return true;
}

static inline bool cracen_builtin_kmu_usage_allowed(psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes)
{
    (void) slot_number;
    (void) attributes;
    return true;
}

#endif /* CRACEN_PSA_BUILTIN_IDS_H */