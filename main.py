import os
import hashlib
import elliptic
import base58

# Constants
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
generator = (
  55066263022277343669578718895168534326250603453777594175500187360389116729240,
  32670510020758816978083085130507043184471273380659243275938904335757337482424
)
# 1. Generate randomness and hash it with sha256 algorithm.
private_key = None
while True:
    entropy = os.urandom(256)
    private_key = hashlib.sha256(entropy).hexdigest()
    if int(private_key, 16) < n:
        break


# 2. Calculate the Public key from the Private key with Elliptic Curve.
#public_key = elliptic.EccMultiply(generator, int(private_key, 16))

# 3. Generate a compressed and uncompressed private key

