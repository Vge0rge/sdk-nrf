.. _tfm_cert:

TF-M Certify sample
################

.. contents::
   :local:
   :depth: 2

short intro text

Requirements
************

The sample supports the following development kits:

.. table-from-sample-yaml::

Overview
********

overview text

Building and running
********************

Build and flash the identity_key_generation sample in order to provision the device
with an identity key.

west build -b nrf5340dk_nrf5340_cpuapp samples/keys/identity_key_generation -d build_id_key_gen
west flash --erase -d build_id_key_gen

Build and flash the TF-M certify sample, flash with --force to ignore warning about UICR needing
erasing. Do not flash with --erase or the provisioned identity key will be lost.

west build -b nrf5340dk_nrf5340_cpuapp_ns samples/tfm/tfm_cert
west flash --force

Firmware Upgrade
****************

The sample supports firmware upgrade of both the application and TF-M, and the second stage bootloader.
The firmware update process requires signature verification keys in order to sign the images used in the firmware update process.
The sample is supplied with its own set of private keys for signing.
These keys can be replaced with custom keys.

.. code-blok:: console

    west build -b nrf5340dk_nrf5340_cpuapp_ns zephyr/tfm/tfm_cert -- \
    -DCONFIG_BOOT_SIGNATURE_KEY_FILE="/home/user/ncs/_keys/nsib_priv.pem"
    -Dmcuboot_CONFIG_BOOT_SIGNATURE_KEY_FILE=\"/home/user/ncs/_keys/mcuboot_priv.pem\" \

See :ref:`ug_fw_update_keys` for information on how to generate custom keys for a project.

The bootloader and application can be updated using the The :file:`mcumgr` command-line tool.
See :ref:`smp_svr_sample` for installation instructions and usage instructions.

Application and TF-M Firmware upgrade
*************************************


-DCONFIG_MCUBOOT_IMAGE_VERSION=\"0.1.2\+3\"
TODO: Figure out string escape-hell
TODO: Document +3 number not being used for downgrade prevention
TODO: Check equal version but different hash (build timestamp) replace possebility.

mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image list
mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image test <hash>
mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image upload build_update/zephyr/app_update.bin

Bootloader Firmware upgrade
***************************

-DCONFIG_BUILD_S1_VARIANT=y
-DFW_INFO_FIRMWARE_VERSION=2

mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image list
mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image test <hash>
mcumgr --conntype serial --connstring dev=/dev/ttyACM2,baud=115200,mtu=512 image upload build/zephyr/signed_by_mcuboot_and_b0_s1_image_update.bin


TODO: Can the include text be customized?
.. |sample path| replace:: :file:`samples/tfm/tfm_cert`

.. include:: /includes/build_and_run.txt

Testing
=======

After programming the sample, the following output is displayed in the console:

.. code-block:: console

    Hello World! nrf5340dk_nrf5340_cpuapp

Dependencies
*************

This sample uses the TF-M module that can be found in the following location in the |NCS| folder structure:

* ``modules/tee/tfm/``
TODO: NSIB, MCUBoot

TODO: This sample uses the following libraries:

* :ref:`lib_tfm_ioctl_api`
