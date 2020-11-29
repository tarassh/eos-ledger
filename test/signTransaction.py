#!/usr/bin/env python
"""
/*******************************************************************************
*   Taras Shchybovyk
*   (c) 2018 Taras Shchybovyk
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
"""

import binascii
import json
import struct
from eosBase import Transaction, parse_bip32_path
from ledgerblue.comm import getDongle
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
parser.add_argument('--file', help="Transaction in JSON format")
args = parser.parse_args()

if args.path is None:
    args.path = "44'/194'/0'/0/0"

if args.file is None:
    args.file = 'transaction.json'

donglePath = parse_bip32_path(args.path)
pathSize = len(donglePath) // 4

with open(args.file) as f:
    obj = json.load(f)
    tx = Transaction.parse(obj)
    # tx_raw = tx.encode()
    tx_chunks = tx.encode()

    first = True
    dongle = getDongle(True)
    for tx_chunk in tx_chunks:

        offset = 0
        singSize = len(tx_chunk)
        sliceSize = 121
        while offset != singSize:
            if singSize - offset > sliceSize:
                transport_chunk = tx_chunk[offset: offset + sliceSize]
            else:
                transport_chunk = tx_chunk[offset:]

            if first:
                totalSize = len(donglePath) + 1 + len(transport_chunk)
                apdu = bytearray.fromhex("D4040000") + bytes([totalSize, pathSize]) + donglePath + transport_chunk
                first = False
            else:
                totalSize = len(transport_chunk)
                apdu = bytearray.fromhex("D4048000") + bytes([totalSize]) + transport_chunk

            offset += len(transport_chunk)
            result = dongle.exchange(bytes(apdu))
            print(binascii.hexlify(result))