/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#include "common.h"
#include <cracen/ec_helpers.h>
#include <cracen/mem_helpers.h>
#include <cracen/statuscodes.h>
#include <cracen_psa.h>
#include <cracen_psa_eddsa.h>
#include <cracen_psa_ecdsa.h>
#include <cracen_psa_montgomery.h>
#include <cracen_psa_ikg.h>
#include <cracen_psa_rsa_keygen.h>
#include <nrf_security_mutexes.h>
#include <silexpk/sxops/rsa.h>
#include <silexpk/ik.h>
#include <stddef.h>
#include <string.h>

#include "tfm_plat_crypto_keys.h"
#include "tfm_builtin_key_ids.h"
#include "tfm_builtin_key_loader.h"
#include "psa_manifest/pid.h"
#include "tfm_spm_log.h"
#include "crypto_library.h"

#include <identity_key.h>
#include <cracen_builtin_keys.h>

const cracen_builtin_ikg_key_policy_t g_builtin_ikg_policy[] = { 
    { .user = TFM_SP_ITS, .key_slot = TFM_BUILTIN_KEY_ID_HUK },
    { .user = TFM_SP_PS, .key_slot = TFM_BUILTIN_KEY_ID_HUK },
    { .user = TFM_SP_INITIAL_ATTESTATION, .key_slot = TFM_BUILTIN_KEY_ID_IAK },
    { .user = MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID, .key_slot = TFM_BUILTIN_KEY_ID_IAK }
};

const cracen_builtin_kmu_key_policy_t g_builtin_kmu_policy[] = { 
    { .user = TFM_SP_ITS, .key_slot_start = 0, .key_slot_end = 255, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE},
    { .user = TFM_SP_CRYPTO, .key_slot_start = 0, .key_slot_end = 255, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE},
    { .user = MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID, .key_slot_start = 0, .key_slot_end = 90, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE}
};


bool cracen_builtin_ikg_usage_allowed(psa_drv_slot_number_t slot_number, psa_key_attributes_t *attributes)
{
    tfm_crypto_library_key_id_t key_id = psa_get_key_id(attributes);

    for(uint32_t i = 0; i < NUMBER_OF_ELEMENTS_OF(g_builtin_ikg_policy); i++) {
        if( g_builtin_ikg_policy[i].user == CRYPTO_LIBRARY_GET_OWNER(key_id) && g_builtin_ikg_policy[i].key_slot == CRYPTO_LIBRARY_GET_KEY_ID(key_id)){
            return true;
        }
    }

    return false;
}

bool cracen_builtin_kmu_usage_allowed(psa_drv_slot_number_t slot_number, psa_key_attributes_t *attributes)
{
    tfm_crypto_library_key_id_t key_id = psa_get_key_id(attributes);

    volatile int32_t owner = CRYPTO_LIBRARY_GET_OWNER(key_id);

    while(owner == 0xF3F3F5F5)
    {
        return false;
    }

    for(uint32_t i = 0; i < NUMBER_OF_ELEMENTS_OF(g_builtin_kmu_policy); i++) {

        switch (g_builtin_kmu_policy[i].kmu_entry_type)
        {
        case KMU_ENTRY_SLOT_SINGLE:
            if(g_builtin_kmu_policy[i].user == CRYPTO_LIBRARY_GET_OWNER(key_id)  && g_builtin_kmu_policy[i].key_slot_start == slot_number)
            {
                return true;
            } 
            break;
        
        case KMU_ENTRY_SLOT_RANGE:
            if(g_builtin_kmu_policy[i].user == CRYPTO_LIBRARY_GET_OWNER(key_id)  && (g_builtin_kmu_policy[i].key_slot_start >= slot_number && g_builtin_kmu_policy[i].key_slot_end <= slot_number))
            {
                return true;
            } 
            break;
        default:
            break;
        }
    }

    return false;
}
