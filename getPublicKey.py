#!/usr/bin/env python
"""
*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
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
********************************************************************************
"""
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct
from base58 import b58encode
import hashlib
import binascii


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


parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to retrieve")
args = parser.parse_args()

if args.path == None:
    args.path = "0'/0'/0'/0/0"

donglePath = parse_bip32_path(args.path)
apdu = "E0020101".decode('hex') + chr(len(donglePath) + 1) + chr(len(donglePath) / 4) + donglePath

dongle = getDongle(True)
result = dongle.exchange(bytes(apdu))
offset = 1 + result[0]
address = result[offset + 1: offset + 1 + result[offset]]

public_key = result[1: 1 + result[0]];
public_key_compressed = bytearray([0x02]) + public_key[1:33]

print "Public key " + str(public_key).encode('hex')
print "Public key compressed " + str(public_key_compressed).encode('hex')

# public_key_compressed = binascii.hexlify(public_key_compressed)

ripemd = hashlib.new('ripemd160')
ripemd.update(public_key_compressed)
check = ripemd.digest()[:4]

buff = public_key_compressed + check
print "Address EOS" + b58encode(str(buff))

print "Address " + str(address)
