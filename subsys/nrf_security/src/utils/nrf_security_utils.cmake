#
# Copyright (c) 2024 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

add_library(nrf_security_utils STATIC
  ${CMAKE_CURRENT_LIST_DIR}/nrf_security_mutexes.c
  ${CMAKE_CURRENT_LIST_DIR}/nrf_security_events.c
  ${CMAKE_CURRENT_LIST_DIR}/nrf_security_core.c
)

target_include_directories(psa_crypto_config
  INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_include_directories(psa_crypto_library_config
  INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

if(BUILD_INSIDE_TFM)
  target_sources(nrf_security_utils
    PRIVATE
      ${CMAKE_CURRENT_LIST_DIR}/nrf_security_tfm_printf.c
  )

  # tfm_vprintf_unpriv() ultimately calls tfm_hal_output_sp_log(), which is
  # only provided when TF-M is built with TFM_SP_LOG_RAW_ENABLED=ON (i.e. a
  # secure UART is enabled). When logging is silenced, compile the wrapper
  # as a no-op to avoid an undefined reference at link time.
  if(TFM_SP_LOG_RAW_ENABLED)
    set_property(SOURCE ${CMAKE_CURRENT_LIST_DIR}/nrf_security_tfm_printf.c
      APPEND PROPERTY COMPILE_DEFINITIONS NRF_SECURITY_TFM_HAS_SP_LOG)
  endif()

  # This gives access to cmsis, nrfx and mdk. Link tfm_log_unpriv to
  # resolve the tfm_log_unpriv() symbol forward-declared by the
  # Zephyr-compat <zephyr/sys/__assert.h> shim (the replacement
  # for the removed tfm_sp_log target). Using tfm_log_unpriv directly
  # rather than tfm_sprt avoids dragging the partition runtime into
  # this generic utility library.
  target_link_libraries(nrf_security_utils
    PUBLIC
      platform_s
      tfm_log_unpriv
      tfm_psa_rot_partition_crypto
  )
else()
  # Ensure that zephyr/heap_constants.h needed by zephyr/kernel.h
  # is generated first
  add_dependencies(nrf_security_utils zephyr_generated_headers)

  # This special linking is done to give access to the zephyr kernel library
  # which possibly isn't --whole-archived in the build. Trying to link to the 
  # kernel library directly will give cyclic dependency. The only way to avoid
  # it seems to be to link with a full path instead.
  target_link_libraries(nrf_security_utils
    PRIVATE
      ${Zephyr-Kernel_BINARY_DIR}/zephyr/kernel/libkernel.a
  )
endif()

nrf_security_add_zephyr_options_library(nrf_security_utils)
