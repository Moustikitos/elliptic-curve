# -*- coding: utf-8 -*-
# © Toons

# import unittest
import pySecp256k1 as secp256k1
from pySecp256k1 import ecdsa
from pySecp256k1 import schnorr


class TestSecp256k1Signatures: #(unittest.TestCase):

    def testBcrypto410Schnorr(self):
        msg = secp256k1.hash_sha256("message to sign".encode())
        pr_key = secp256k1.hash_sha256("secret".encode())
        pu_key = secp256k1.encoded_from_point(
            secp256k1.G * secp256k1.int_from_bytes(pr_key)
        )
        assert schnorr.bcrypto410_verify(
                msg, pu_key,
                schnorr.bcrypto410_sign(msg, pr_key)
            ) is True

        # self.assertEqual(
        #     True,
        #     schnorr.bcrypto410_verify(
        #         msg, pu_key,
        #         schnorr.bcrypto410_sign(msg, pr_key)
        #     )
        # )

    def testSecp256k1Ecdsa(self, benchmark):
        msg = secp256k1.hash_sha256("message to sign".encode())
        pr_key = secp256k1.hash_sha256("secret".encode())
        pu_key = secp256k1.encoded_from_point(
            secp256k1.G * secp256k1.int_from_bytes(pr_key)
        )
        sig = benchmark(ecdsa.sign, msg, pr_key)
        # self.assertEqual(
        #     True,
        #     ecdsa.verify(msg, pu_key, sig)
        # )
        # self.assertEqual(
        #     True,
        #     ecdsa.verify(msg, pu_key, ecdsa.sign(msg, pr_key, canonical=False))
        # )

    def testSecp256k1Rfc6979Ecdsa(self):
        msg = secp256k1.hash_sha256("message to sign".encode())
        pr_key = secp256k1.hash_sha256("secret".encode())
        pu_key = secp256k1.encoded_from_point(
            secp256k1.G * secp256k1.int_from_bytes(pr_key)
        )
        # self.assertEqual(
        #     True,
        #     ecdsa.verify(msg, pu_key, ecdsa.rfc6979_sign(msg, pr_key))
        # )
        # self.assertEqual(
        #     True,
        #     ecdsa.verify(msg, pu_key, ecdsa.rfc6979_sign(
        #         msg, pr_key, canonical=False)
        #     )
        # )
