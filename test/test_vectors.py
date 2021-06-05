# -*- coding: utf-8 -*-
# © Toons

import os
import io
import binascii
from pySecp256k1 import schnorr


with io.open(
    os.path.join(os.path.dirname(__file__), "test_vectors.csv"), "r"
) as test_vectors:
    SCHNORR_TEST_VECTORS = test_vectors.read().split("\n")

VECTORS = []
header = [e.strip() for e in SCHNORR_TEST_VECTORS[0].split(";")]
for column in SCHNORR_TEST_VECTORS[1:]:
    VECTORS.append(dict(zip(header, column.split(";"))))


class TestSchnorrVectors:

    def testVector1to4(self):
        for v in VECTORS[:4]:
            secret0 = binascii.unhexlify(v["secret key"])
            pubkey = binascii.unhexlify(v["public key"])
            msg = binascii.unhexlify(v["message"])
            sig = binascii.unhexlify(v["signature"])
            rnd = binascii.unhexlify(v["aux_rand"])
            result = v["verification result"].lower() == 'true'

            assert pubkey == schnorr.bytes_from_point(
                schnorr.PublicKey.from_seed(secret0)
            )
            assert sig == schnorr.sign(msg, secret0, rnd)
            assert result == schnorr.verify(msg, pubkey, sig)

    def testVector4(self):
        v = VECTORS[3]
        pubkey = binascii.unhexlify(v["public key"])
        msg = binascii.unhexlify(v["message"])
        sig = binascii.unhexlify(v["signature"])

        msg_mod_p = schnorr.bytes_from_int(
            schnorr.int_from_bytes(msg) % schnorr.p
        )
        assert not schnorr.verify(msg_mod_p, pubkey, sig)
        msg_mod_n = schnorr.bytes_from_int(
            schnorr.int_from_bytes(msg) % schnorr.n
        )
        assert not schnorr.verify(msg_mod_n, pubkey, sig)

    def testVector5(self):
        v = VECTORS[4]
        pubkey = binascii.unhexlify(v["public key"])
        msg = binascii.unhexlify(v["message"])
        sig = binascii.unhexlify(v["signature"])
        result = v["verification result"].lower() == 'true'
        assert result == schnorr.verify(msg, pubkey, sig)
