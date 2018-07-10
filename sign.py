# from asn1 import Encoder, Decoder, Numbers
import binascii
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct


class PermissionLevel:
    def __init__(self):
        self.name = binascii.unhexlify('deaddeade0e0e0e0')
        self.permission_name = binascii.unhexlify('e0e0e0e0deaddead')

    def encode(self, encoder):
        encoder.enter(Numbers.Sequence)
        encoder.write(self.name, Numbers.OctetString)
        encoder.write(self.permission_name, Numbers.OctetString)
        encoder.leave()

    @staticmethod
    def decode(decoder):
        pl = PermissionLevel()

        decoder.enter()
        tag, pl.name = decoder.read()
        tag, pl.permission_name = decoder.read()

        decoder.leave()
        return pl

    def __repr__(self):
        return "\n\t\tname:          {}\n" \
               "\t\tpermission_name: {}\n".format(
            binascii.hexlify(self.name),
            binascii.hexlify(self.permission_name)
        )


class Action:
    def __init__(self):
        self.account = binascii.unhexlify('beafbeafbeafbeaf')
        self.name = binascii.unhexlify('01234567abcdef01')
        self.authorization = [PermissionLevel()]
        self.bytes = binascii.unhexlify('123456789012345678901234567890')

    def encode(self, encoder):
        encoder.enter(Numbers.Sequence)

        encoder.write(self.account, Numbers.OctetString)
        encoder.write(self.name, Numbers.OctetString)

        encoder.enter(Numbers.Sequence)
        encoder.write(bin(len(self.authorization)), Numbers.OctetString)
        for perm in self.authorization:
            perm.encode(encoder)
        encoder.leave()

        encoder.write(self.bytes, Numbers.OctetString)
        encoder.leave()

    @staticmethod
    def decoder(decoder):
        action = Action()

        decoder.enter()
        tag, action.account = decoder.read()
        tag, action.name = decoder.read()
        decoder.enter()
        tag, size = decoder.read()
        while not decoder.eof():
            action.authorization.append(PermissionLevel.decode(decoder))
        decoder.leave()
        tag, action.bytes = decoder.read()
        decoder.leave()

        return action

    def __repr__(self):
        return "\n\taccount:       {}\n" \
               "\tname:          {}\n" \
               "\tauthorisation: {}\n" \
               "\tbytes:         {}\n".format(
            binascii.hexlify(self.account),
            binascii.hexlify(self.name),
            self.authorization,
            binascii.hexlify(self.bytes)
        )


class Transaction:
    def __init__(self):
        self.expiration = binascii.unhexlify('01020304')
        self.ref_block_num = binascii.unhexlify('0102')
        self.ref_block_prefix = binascii.unhexlify('0a0b0c0d')
        self.max_net_usage_word = binascii.unhexlify('01020304')
        self.max_cpu_usage_ms = binascii.unhexlify('00')
        self.delay_sec = binascii.unhexlify('0f0e0d0c')
        self.ctx_free_actions = []
        self.actions = [Action()]
        self.tx_extensions = []
        self.ctx_free_data = []

    def encode(self, encoder):
        encoder.enter(Numbers.Sequence)

        encoder.write(self.expiration, Numbers.OctetString)
        encoder.write(self.ref_block_num, Numbers.OctetString)
        encoder.write(self.ref_block_prefix, Numbers.OctetString)
        encoder.write(self.max_net_usage_word, Numbers.OctetString)
        encoder.write(self.max_cpu_usage_ms, Numbers.OctetString)
        encoder.write(self.delay_sec, Numbers.OctetString)

        encoder.enter(Numbers.Sequence)
        for ctx_free_action in self.ctx_free_actions:
            ctx_free_action.encode(encoder)
        encoder.leave()

        encoder.enter(Numbers.Sequence)
        for action in self.actions:
            action.encode(encoder)
        encoder.leave()

        encoder.enter(Numbers.Sequence)
        for tx_extension in self.tx_extensions:
            tx_extension.encode(encoder)
        encoder.leave()

        encoder.leave()

    @staticmethod
    def decode(decoder):
        tx = Transaction()

        decoder.enter()
        tag, tx.expiration = decoder.read()
        tag, tx.ref_block_num = decoder.read()
        tag, tx.ref_block_prefix = decoder.read()
        tag, tx.max_net_usage_word = decoder.read()
        tag, tx.max_cpu_usage_ms = decoder.read()
        tag, tx.delay_sec = decoder.read()

        decoder.enter()
        while not decoder.eof():
            tx.ctx_free_actions.append(Action.decoder(decoder))
        decoder.leave()

        decoder.enter()
        while not decoder.eof():
            tx.actions.append(Action.decoder(decoder))
        decoder.leave()

        decoder.enter()
        decoder.leave()

        decoder.leave()
        return tx

    def __repr__(self):
        return "expiration:         {}\n" \
               "ref_block_num:      {}\n" \
               "ref_block_prefix:   {}\n" \
               "max_net_usage_word: {}\n" \
               "max_cpu_usage_ms:   {}\n" \
               "delay_sec:          {}\n" \
               "ctx_free_actions:   {}\n" \
               "actions:            {}\n" \
               "tx_extensions       {}\n" \
               "ctx_free_data:     {}\n".format(
            binascii.hexlify(self.expiration),
            binascii.hexlify(self.ref_block_num),
            binascii.hexlify(self.ref_block_prefix),
            binascii.hexlify(self.max_net_usage_word),
            binascii.hexlify(self.max_cpu_usage_ms),
            binascii.hexlify(self.delay_sec),
            self.ctx_free_actions,
            self.actions,
            self.tx_extensions,
            self.ctx_free_data
        )


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

if args.path is None:
    args.path = "44'/194'/0'/0/0"

donglePath = parse_bip32_path(args.path)
print binascii.hexlify(donglePath)
pathSize = len(donglePath) / 4

signData = "0420038f4b0fc8ff18a4f0842a8f0564611f6e96e8535901dd45e43ac8691a1c4dca04046db5435b0402315e0404ed3f5fed040100040100040100040100040101040800a6823403ea30550408000000572d3ccdcd040101040810fc7566d15cfd45040800000000a8ed3232040129042910fc7566d15cfd45a0229bfa4d37a98b102700000000000004454f530000000008746573747465737404010004200000000000000000000000000000000000000000000000000000000000000000".decode('hex')
# signData = "0420038f4b0fc8ff18a4f0842a8f0564611f6e96e8535901dd45e43ac8691a1c4dca0404ae81445b0402bce30404ece2fd1004010004010004010004010004010104080000000000ea30550408c08fca86a9a8d2d4040101040810fc7566d15cfd45040800000000a8ed3232040130043010fc7566d15cfd4510fc7566d15cfd45a08601000000000004454f5300000000a08601000000000004454f530000000004010004200000000000000000000000000000000000000000000000000000000000000000".decode('hex')
singSize = len(signData)
print "size ", singSize

dongle = getDongle(True)
offset = 0
first = True
while offset != singSize:
    if singSize - offset > 200:
        chunk = signData[offset: offset + 200]
    else:
        chunk = signData[offset:]

    if first:
        totalSize = len(donglePath) + 1 + len(chunk)
        apdu = "D4040000".decode('hex') + chr(totalSize) + chr(pathSize) + donglePath + chunk
        first = False
    else:
        totalSize = len(chunk)
        apdu = "D4048000".decode('hex') + chr(totalSize) + chunk

    offset += len(chunk)
    result = dongle.exchange(bytes(apdu))
    print binascii.hexlify(result)

