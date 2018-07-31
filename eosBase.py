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

from asn1 import Encoder, Numbers
from datetime import datetime
import struct
import binascii


class Transaction:
    def __init__(self):
        pass

    @staticmethod
    def char_to_symbol(c):
        if c >= 'a' and c <= 'z':
            return ord(c) - ord('a') + 6
        if c >= '1' and c <= '5':
            return ord(c) - ord('1') + 1
        return 0

    @staticmethod
    def name_to_number(name):
        length = len(name)
        value = 0

        for i in range(0, 13):
            c = 0
            if i < length and i < 13:
                c = Transaction.char_to_symbol(name[i])

            if i < 12:
                c &= 0x1f
                c <<= 64 - 5 * (i + 1)
            else:
                c &= 0x0f

            value |= c

        return struct.pack('Q', value)

    @staticmethod
    def symbol_from_string(p, name):
        length = len(name)
        result = 0
        for i in range(0, length):
            result |= ord(name[i]) << (8 *(i+1))

        result |= p
        return result

    @staticmethod
    def symbol_precision(sym):
        return pow(10, (sym & 0xff))

    @staticmethod
    def asset_to_number(asset):
        amount_str, symol_str = asset.split(' ')
        dot_pos = amount_str.find('.')

        # parse symbol
        if dot_pos != -1:
            precision_digit = len(amount_str) - dot_pos - 1
        else:
            precision_digit = 0

        sym = Transaction.symbol_from_string(precision_digit, symol_str)

        # parse amount
        if dot_pos != -1:
            int_part = int(amount_str[:dot_pos])
            fract_part = int(amount_str[dot_pos+1:])
            if int_part < 0:
                fract_part *= -1
        else:
            int_part = int(amount_str)

        amount = int_part
        amount *= Transaction.symbol_precision(sym)
        amount += fract_part

        data = struct.pack('Q', amount)
        data += struct.pack('Q', sym)
        return data

    @staticmethod
    def parse(json):
        tx = Transaction()
        tx.json = json

        tx.chain_id = binascii.unhexlify(json['chain_id'])

        body = json['transaction']

        expiration = int(datetime.strptime(body['expiration'], '%Y-%m-%dT%H:%M:%S').strftime("%s"))
        tx.expiration = struct.pack('I', expiration)
        tx.ref_block_num = struct.pack('H', body['ref_block_num'])
        tx.ref_block_prefix = struct.pack('I', body['ref_block_prefix'])
        tx.net_usage_words = struct.pack('B', body['net_usage_words'])
        tx.max_cpu_usage_ms = struct.pack('B', body['max_cpu_usage_ms'])
        tx.delay_sec = struct.pack('B', body['delay_sec'])

        tx.ctx_free_actions_size = struct.pack('B', len(body['context_free_actions']))
        tx.actions_size = struct.pack('B', len(body['actions']))

        action = body['actions'][0]
        tx.account = Transaction.name_to_number(action['account'])
        tx.name = Transaction.name_to_number(action['name'])

        tx.auth_size = struct.pack('B', len(action['authorization']))
        tx.auth = []
        for auth in action['authorization']:
            tx.auth.append((Transaction.name_to_number(auth['actor']), Transaction.name_to_number(auth['permission'])))

        data = action['data']
        parameters = Transaction.name_to_number(data['from'])
        parameters += Transaction.name_to_number(data['to'])
        parameters += Transaction.asset_to_number(data['quantity'])
        memo = data['memo']
        parameters += struct.pack('B', len(memo))
        if len(memo) > 0:
            parameters += struct.pack(str(len(memo)) + 's', str(data['memo']))

        tx.data_size = struct.pack('B', len(parameters))
        tx.data = parameters
        tx.tx_ext = struct.pack('B', len(body['transaction_extensions']))
        tx.cfd = binascii.unhexlify('00' * 32)

        return tx

    def encode(self):
        encoder = Encoder()

        encoder.start()
        encoder.write(self.chain_id, Numbers.OctetString)
        encoder.write(self.expiration, Numbers.OctetString)
        encoder.write(self.ref_block_num, Numbers.OctetString)
        encoder.write(self.ref_block_prefix, Numbers.OctetString)
        encoder.write(self.net_usage_words, Numbers.OctetString)
        encoder.write(self.max_cpu_usage_ms, Numbers.OctetString)
        encoder.write(self.delay_sec, Numbers.OctetString)

        encoder.write(self.ctx_free_actions_size, Numbers.OctetString)
        encoder.write(self.actions_size, Numbers.OctetString)
        encoder.write(self.account, Numbers.OctetString)
        encoder.write(self.name, Numbers.OctetString)
        encoder.write(self.auth_size, Numbers.OctetString)
        for auth in self.auth:
            (auth_actor, permission) = auth
            encoder.write(auth_actor, Numbers.OctetString)
            encoder.write(permission, Numbers.OctetString)
        encoder.write(self.data_size, Numbers.OctetString)
        encoder.write(self.data, Numbers.OctetString)
        encoder.write(self.tx_ext, Numbers.OctetString)
        encoder.write(self.cfd, Numbers.OctetString)

        return encoder.output()
