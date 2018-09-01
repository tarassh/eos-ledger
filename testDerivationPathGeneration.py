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
from ledgerblue.comm import getDongle
import struct
from base58 import b58encode
import hashlib


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


dongle = getDongle(False)
path = "44'/194'/0'/0/"
for i in range(0, 20):
    derPath = path + str(i)
    print "------------- {} -------------".format(derPath)

    donglePath = parse_bip32_path(derPath)
    apdu = "D4020001".decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath

    result = dongle.exchange(bytes(apdu))
    offset = 1 + result[0]
    address = result[offset + 1: offset + 1 + result[offset]]

    public_key = result[1: 1 + result[0]]
    head = 0x03 if (public_key[64] & 0x01) == 1 else 0x02
    public_key_compressed = bytearray([head]) + public_key[1:33]

    print "           Public key: " + str(public_key).encode('hex')
    print "Public key compressed: " + str(public_key_compressed).encode('hex')

    ripemd = hashlib.new('ripemd160')
    ripemd.update(public_key_compressed)
    check = ripemd.digest()[:4]

    buff = public_key_compressed + check
    wif_public_key = "EOS" + b58encode(str(buff))
    print "Calculated from public key: Address " + wif_public_key
    print "      Received from ledger: Address " + str(address)
    assert wif_public_key == str(address)
