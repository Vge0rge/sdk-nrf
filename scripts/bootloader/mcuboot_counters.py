#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause


from intelhex import IntelHex

import argparse
import struct
import os


def parse_args():
    parser = argparse.ArgumentParser(
        description='Generate the hex file containing the secure counters used by MCUBOOT.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--secure-cnt-addr', type=lambda x: int(x, 0),
                        required=True, help='Address at which to place the secure counter')
    parser.add_argument('-o', '--output', required=False, default='mcuboot_secure_counters.hex',
                        help='Output file name.')
    parser.add_argument('--max-size', required=False, type=lambda x: int(x, 0), default=0x1000,
                        help='Maximum total size of the provision data, including the counter slots.')
    parser.add_argument('--num-counters', required=True, type=int,
                        help='Number of monotonic counters required.')
    parser.add_argument('--counter-slots', required=True, type=int,
                        help='Number of slots asigned to each counter.')
    parser.add_argument('--b0-counter-present', required=False, type=bool,
                        help='Initialize a counter for secure bootloader')
    return parser.parse_args()


def main():
    args = parse_args()
    # Add addresses
    num_counters = args.num_counters
    counter_slots = args.counter_slots
    b0_counter_present = args.b0_counter_present
    max_size = args.max_size
    secure_cnt_addr = args.secure_cnt_addr
    output = args.output

    if(num_counters == 0 or counter_slots == 0):
        raise argparse.ArgumentTypeError("Number of counters and counters slots must be > 0")

    sec_cnt_data = struct.pack('H', 1) # Type "counter collection"

    if(b0_counter_present):
        sec_cnt_data += struct.pack('H', num_counters + 1)
    else:
        sec_cnt_data += struct.pack('H', num_counters)


    if counter_slots % 2 == 1:
        counter_slots+= 1
        print(f'Monotonic counter slots rounded up to {num_counter_slots_version}')

    if(b0_counter_present):
        sec_cnt_data += struct.pack('H', 0x10) # == COUNTER_DESC_VERSION
        sec_cnt_data += struct.pack('H', counter_slots)
        sec_cnt_data += bytes(2 * counter_slots * [0xFF])
        mcuboot_counters-=1


    for cnt_desc in range(0, num_counters):
        sec_cnt_data += struct.pack('H', cnt_desc) # == COUNTER_DESC_MCUBOOT_HW_COUNTER_ID*
        sec_cnt_data += struct.pack('H', counter_slots)
        sec_cnt_data += bytes(2 * counter_slots * [0xFF])


    assert len(sec_cnt_data) <= max_size, """Secure counters dont't fit.
Reduce the number of counter types or counter slots and try again."""

    ih = IntelHex()
    ih.frombytes(sec_cnt_data, offset=secure_cnt_addr)
    ih.write_hex_file(output)


if __name__ == '__main__':
    main()
