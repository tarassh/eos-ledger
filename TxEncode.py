from asn1 import Encoder, Decoder, Numbers
import binascii

encoder = Encoder()
chain_id = binascii.unhexlify("99"*32)

encoder.start()
encoder.write(chain_id, Numbers.OctetString)

encoded_bytes = encoder.output()
print binascii.hexlify(encoded_bytes)