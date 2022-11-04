from base58 import b58encode
from contextlib import contextmanager
from enum import IntEnum
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from typing import List, Generator
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from ragger.backend.interface import BackendInterface, RAPDU


class INS(IntEnum):
    INS_GET_PUBLIC_KEY = 0x02
    INS_SIGN_MESSAGE = 0x04
    INS_GET_APP_CONFIGURATION = 0x06


CLA = 0xD4

P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01

P2_NO_CHAINCODE = 0x00
P2_CHAINCODE = 0x01

P1_FIRST = 0x00
P1_MORE = 0x80

MAX_CHUNK_SIZE = 255

STATUS_OK = 0x9000


class ErrorType:
    NO_APP_RESPONSE = 0x6700
    SDK_EXCEPTION = 0x6801
    SDK_INVALID_PARAMETER = 0x6802
    SDK_EXCEPTION_OVERFLOW = 0x6803
    SDK_EXCEPTION_SECURITY = 0x6804
    SDK_INVALID_CRC = 0x6805
    SDK_INVALID_CHECKSUM = 0x6806
    SDK_INVALID_COUNTER = 0x6807
    SDK_NOT_SUPPORTED = 0x6808
    SDK_INVALID_STATE = 0x6809
    SDK_TIMEOUT = 0x6810
    SDK_EXCEPTION_PIC = 0x6811
    SDK_EXCEPTION_APP_EXIT = 0x6812
    SDK_EXCEPTION_IO_OVERFLOW = 0x6813
    SDK_EXCEPTION_IO_HEADER = 0x6814
    SDK_EXCEPTION_IO_STATE = 0x6815
    SDK_EXCEPTION_IO_RESET = 0x6816
    SDK_EXCEPTION_CX_PORT = 0x6817
    SDK_EXCEPTION_SYSTEM = 0x6818
    SDK_NOT_ENOUGH_SPACE = 0x6819
    NO_APDU_RECEIVED = 0x6982
    USER_CANCEL = 0x6985
    UNIMPLEMENTED_INSTRUCTION = 0x6d00
    INVALID_CLA = 0x6e00


class EosClient:
    client: BackendInterface

    def __init__(self, client):
        self._client = client

    def compute_adress_from_public_key(self, public_key):

        head = 0x03 if (public_key[64] & 0x01) == 0x01 else 0x02
        public_key_compressed = bytearray([head]) + public_key[1:33]

        ripemd = hashlib.new('ripemd160')
        ripemd.update(public_key_compressed)
        check = ripemd.digest()[:4]

        buff = b58encode(public_key_compressed + check).decode("ascii")
        return "EOS" + buff

    def parse_get_public_key_response(self, response: bytes, request_chaincode) -> (bytes, str, bytes):
        # response = public_key_len (1) ||
        #            public_key (var) ||
        #            address_len (1) ||
        #            address (var) ||
        #            chain_code (32)
        offset: int = 0

        public_key_len: int = response[offset]
        offset += 1
        public_key: bytes = response[offset:offset + public_key_len]
        offset += public_key_len
        address_len: int = response[offset]
        offset += 1
        address: str = response[offset:offset + address_len].decode("ascii")
        offset += address_len
        if request_chaincode:
            chaincode: bytes = response[offset:offset + 32]
            offset += 32
        else:
            chaincode = None

        assert len(response) == offset
        assert len(public_key) == 65
        assert self.compute_adress_from_public_key(public_key) == address

        return public_key, address, chaincode

    def _get_public_key_params(self, derivation_path: bytes, confirm: bool, request_chaincode: bool):
        p1 = P1_CONFIRM if confirm else P1_NON_CONFIRM
        p2 = P2_CHAINCODE if request_chaincode else P2_NO_CHAINCODE
        return CLA, INS.INS_GET_PUBLIC_KEY, p1, p2, derivation_path

    def send_get_public_key_non_confirm(self, derivation_path: bytes, request_chaincode: bool) -> RAPDU:
        apdu_params = self._get_public_key_params(derivation_path, False, request_chaincode)
        return self._client.exchange(*apdu_params)

    @contextmanager
    def send_async_get_public_key_confirm(self, derivation_path: bytes, request_chaincode: bool):
        apdu_params = self._get_public_key_params(derivation_path, True, request_chaincode)
        with self._client.exchange_async(*apdu_params):
            yield

    def split_message(self, message: bytes) -> List[bytes]:
        return [message[x:x + MAX_CHUNK_SIZE] for x in range(0, len(message), MAX_CHUNK_SIZE)]

    def _send_sign_message(self, message: bytes, first: bool):
        if first:
            p1 = P1_FIRST
        else:
            p1 = P1_MORE
        self._client.exchange(CLA, INS.INS_SIGN_MESSAGE, p1, 0, message)

    @contextmanager
    def _send_async_sign_message(self, message: bytes, first: bool):
        if first:
            p1 = P1_FIRST
        else:
            p1 = P1_MORE
        with self._client.exchange_async(CLA, INS.INS_SIGN_MESSAGE, p1, 0, message):
            yield

    def send_async_sign_message(self,
                                derivation_path: bytes,
                                message: bytes) -> Generator[None, None, None]:
        messages = self.split_message(derivation_path + message)
        first = True

        if len(messages) > 1:
            self._send_sign_message(messages[0], True)
            for m in messages[1:-1]:
                self._send_sign_message_more(m, False)
            first = False

        return self._send_async_sign_message(messages[-1], first)

    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response

    def check_canonical(self, signature: bytes):
        assert (signature[1] & 0x80) == 0
        assert signature[1] != 0 or (signature[2] & 0x80) != 0

        assert signature[33] & 0x80 == 0
        assert signature[33] != 0 or (signature[34] & 0x80) != 0

    def verify_signature(self, derivation_path: bytes, signing_digest: bytes, signature: bytes):
        self.check_canonical(signature)

        v = signature[0]
        r = int.from_bytes(signature[1:33], "big")
        s = int.from_bytes(signature[33:], "big")

        assert 27 <= v <= 35
        parity = v - 27 - 4

        # Retrieve public key from signature
        recovered_pub_keys = secp256k1_generator.possible_public_pairs_for_signature(
                        int.from_bytes(signing_digest, "big"), (r, s), parity)
        assert len(recovered_pub_keys) == 1
        x, y = recovered_pub_keys[0]

        # Also retrieve public key from INS_GET_PUBLIC_KEY for comparison
        rapdu = self.send_get_public_key_non_confirm(derivation_path, False)
        assert rapdu.status == STATUS_OK
        public_key_bytes, _, _ = self.parse_get_public_key_response(rapdu.data, False)

        # Check that both public key matches
        assert x.to_bytes(32, byteorder='big') == public_key_bytes[1:33]
        assert y.to_bytes(32, byteorder='big') == public_key_bytes[33:]

        # Verify signature validity
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        public_key = public_numbers.public_key(default_backend())
        der_signature = encode_dss_signature(r, s)
        hash_alg = ec.ECDSA(Prehashed(hashes.SHA256()))
        public_key.verify(der_signature, signing_digest, hash_alg)
