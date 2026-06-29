import os
import hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigdecode_der, sigencode_der, randrange_from_seed__trytryagain
from Crypto.Hash import RIPEMD160
import base58

# Generate a new private key
private_key = SigningKey.generate(curve=SECP256k1)

# Generate a public key
public_key = private_key.get_verifying_key()

# Public key in hex format (compressed) Remove '#' if you want the uncompressed public key, Realign the code in line and add the print statement.
#public_key_uncompressed = b'\x04' + public_key.to_string()
public_key_compressed = b'\x02' + public_key.to_string()[:32] if public_key.to_string()[-1] % 2 == 0 else b'\x03' + public_key.to_string()[:32]

# Generate Bitcoin addresses
def ripemd160(x):
    d = RIPEMD160.new()
    d.update(x)
    return d.digest()

def sha256(x):
    return hashlib.sha256(x).digest()

def generate_btc_address(public_key):
    pk_hash = ripemd160(sha256(public_key))
    version = b'\x00'
    checksum = sha256(sha256(version + pk_hash))[:4]
    address = version + pk_hash + checksum
    return base58.b58encode(address).decode()

btc_address = generate_btc_address(public_key_compressed)

private_key_hex = private_key.to_string().hex()
