# -*- encoding:utf-8 -*-

from . import *


# Note that bip schnorr uses a very different public key format (32 bytes) than
# the ones used by existing systems (which typically use elliptic curve points
# as public keys, 33-byte or 65-byte encodings of them). A side effect is that
# `PubKey(sk) = PubKey(bytes(n-int(sk))`, so every public key has two
# corresponding private keys.

def bytes_from_point(P):
    """
    Encode a public key as defined in `BIP schnorr <https://github.com/bitcoin\
/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        P (:class:`Point`): secp256k1 curve point
    Returns:
        :class:`bytes`: encoded public key
    """
    return bytes_from_int(P[0])


def point_from_bytes(pubkeyB):
    """
    Decode a public key as defined in `BIP schnorr <https://github.com/bitcoin\
/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        pubkeyB (:class:`bytes`): encoded public key
    Returns:
        :class:`Point`: secp256k1 curve point
    """
    x = int_from_bytes(pubkeyB)
    y = y_from_x(x)
    if not y:
        return None
    return [x, y]


# https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js
def bcrypto410_sign(msg, seckey0):
    """
    Generate message signature according to `Bcrypto 4.10 schnorr <https://git\
hub.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        secret0 (:class:`bytes`): private key
    Returns:
        :class:`bytes`: RAW signature
    """
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')

    seckey = int_from_bytes(seckey0)
    if not (1 <= seckey <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.'
        )

    k0 = int_from_bytes(hash_sha256(seckey0 + msg)) % n
    if k0 == 0:
        raise RuntimeError(
            'Failure. This happens only with negligible probability.'
        )

    R = G * k0
    Rraw = bytes_from_int(R.x)
    e = int_from_bytes(
        hash_sha256(Rraw + encoded_from_point(G*seckey) + msg)
    ) % n

    k = n - k0 if not is_quad(R.y) else k0
    s = (k + e * seckey) % n

    return Rraw + bytes_from_int(s)


def bcrypto410_verify(msg, pubkey, sig):
    """
    Check if public key match message signature according to `Bcrypto 4.10 sch\
norr <https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js>`_
    spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        pubkey (:class:`bytes`): encoded public key
        sig (:class:`bytes`): signature
    Returns:
        :class:`bool`: True if match
    """
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')

    P = PublicKey.decode(pubkey)
    r, s = int_from_bytes(sig[:32]), int_from_bytes(sig[32:])
    if r >= p or s >= n:
        return False

    e = int_from_bytes(hash_sha256(sig[0:32] + pubkey + msg)) % n
    R = Point(*(G*s + point_mul(P, n-e)))  # P*(n-e) does not work...
    if R is None or not is_quad(R.y) or R.x != r:
        return False

    return True


def sign(msg, seckey0, aux_rand=None):
    """
    Generate message signature according to `BIP schnorr <https://github.com/b\
itcoin/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        seckey0 (:class:`bytes`): private key
    Returns:
        :class:`bytes`: RAW signature
    """
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')

    seckey0 = int_from_bytes(seckey0)
    if not (1 <= seckey0 <= n - 1):
        raise ValueError(
            'The secret key must be an integer in the range 1..n-1.'
        )

    P = G * seckey0
    seckey = seckey0 if has_even_y(P) else n - seckey0

    t = xor_bytes(
        bytes_from_int(seckey),
        tagged_hash(
            "BIP0340/aux",
            bytes_from_int(rand_k()) if aux_rand is None
            else aux_rand
        )
    )
    k0 = int_from_bytes(
        tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)
    ) % n
    if k0 == 0:
        raise RuntimeError(
            'Failure. This happens only with negligible probability.'
        )

    R = G * k0
    k = n - k0 if not has_even_y(R) else k0
    r = bytes_from_point(R)
    e = int_from_bytes(
        tagged_hash("BIP0340/challenge", r + bytes_from_point(P) + msg)
    ) % n

    return r + bytes_from_int((k + e * seckey) % n)


def verify(msg, pubkey, sig):
    """
    Check if public key match message signature according to `BIP schnorr <htt\
ps://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>`_ spec.

    Args:
        msg (:class:`bytes`): sha256 message-hash
        pubkey (:class:`bytes`): encoded public key
        sig (:class:`bytes`): signature
    Returns:
        :class:`bool`: True if match
    """
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')

    P = lift_x(pubkey)
    if (P is None):
        return False

    r, s = int_from_bytes(sig[:32]), int_from_bytes(sig[32:])
    if (r >= p or s >= n):
        return False

    e = int_from_bytes(
        tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)
    ) % n
    R = Point(*(G * s + point_mul(P, n-e)))  # P*(n-e) does not work...
    if R is None or not has_even_y(R) or R.x != r:
        return False

    return True
