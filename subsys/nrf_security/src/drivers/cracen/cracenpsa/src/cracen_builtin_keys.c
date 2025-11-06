/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#include "common.h"

#include <psa/crypto.h>
#include <psa/crypto_values.h>
#include <stddef.h>
#include <string.h>

#include "psa_manifest/pid.h"
#include "tfm_builtin_key_ids.h"
#include <cracen_builtin_keys.h>

#define NUMBER_OF_ELEMENTS_OF(x) sizeof(x)/sizeof(*x)

#define MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID (-0x3c000000)

const cracen_builtin_ikg_key_policy_t g_builtin_ikg_policy[] = { 
    { .user = TFM_SP_ITS, .key_slot =  TFM_BUILTIN_KEY_ID_HUK},
    { .user = TFM_SP_PS, .key_slot = TFM_BUILTIN_KEY_ID_HUK },
    { .user = TFM_SP_INITIAL_ATTESTATION, .key_slot = TFM_BUILTIN_KEY_ID_IAK },
    { .user = MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID, .key_slot = TFM_BUILTIN_KEY_ID_IAK }
};

const cracen_builtin_kmu_key_policy_t g_builtin_kmu_policy[] = { 
    /* 0x0 is used by code that manually generate psa key_ids like the hardware unique library */
    { .user = 0x0, .key_slot_start = 0, .key_slot_end = 255, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE},
    { .user = TFM_SP_ITS, .key_slot_start = 0, .key_slot_end = 255, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE},
    { .user = TFM_SP_CRYPTO, .key_slot_start = 0, .key_slot_end = 255, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE},
    { .user = MAPPED_TZ_NS_AGENT_DEFAULT_CLIENT_ID, .key_slot_start = 0, .key_slot_end = 127, .kmu_entry_type = KMU_ENTRY_SLOT_RANGE}
};

static bool cracen_builtin_ikg_usage_allowed(mbedtls_key_owner_id_t owner, psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes)
{
    for(uint32_t i = 0; i < NUMBER_OF_ELEMENTS_OF(g_builtin_ikg_policy); i++) {
        if( g_builtin_ikg_policy[i].user == owner && g_builtin_ikg_policy[i].key_slot == slot_number ){
            return true;
        }
    }

    return false;
}

static bool cracen_builtin_kmu_usage_allowed(mbedtls_key_owner_id_t owner, psa_drv_slot_number_t slot_number, const psa_key_attributes_t *attributes)
{
    for(uint32_t i = 0; i < NUMBER_OF_ELEMENTS_OF(g_builtin_kmu_policy); i++) {

        switch (g_builtin_kmu_policy[i].kmu_entry_type)
        {
        case KMU_ENTRY_SLOT_SINGLE:
            if(g_builtin_kmu_policy[i].user == owner && g_builtin_kmu_policy[i].key_slot_start == slot_number)
            {
                return true;
            } 
            break;
        
        case KMU_ENTRY_SLOT_RANGE:
            if(g_builtin_kmu_policy[i].user == owner && (slot_number >= g_builtin_kmu_policy[i].key_slot_start  && slot_number <= g_builtin_kmu_policy[i].key_slot_end))
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


bool cracen_builtin_key_usage_allowed(psa_drv_slot_number_t slot_id, const psa_key_attributes_t *attributes)
{
    mbedtls_key_owner_id_t owner = MBEDTLS_SVC_KEY_ID_GET_OWNER_ID(psa_get_key_id(attributes));

	if (PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes)) ==
		PSA_KEY_LOCATION_CRACEN) {

		if(cracen_builtin_ikg_usage_allowed(owner, slot_id, attributes)){
			return true;
		}
	} else if (PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes)) ==
		PSA_KEY_LOCATION_CRACEN_KMU) {
		if(cracen_builtin_kmu_usage_allowed(owner, slot_id, attributes)){
			return true;
		}
	}

	return false;
}