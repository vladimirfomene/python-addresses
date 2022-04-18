import os
import hashlib
import elliptic
import base58
from binascii import unhexlify as decode_hex


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
public_key = elliptic.EccMultiply(generator, int(private_key, 16))

# 3. Generate a compressed and uncompressed private key
def generate_base58_format(payload, prefix, suffix = ""):
    hash256 = hashlib.sha256(decode_hex(prefix + payload)).hexdigest()
    checksum = hashlib.new('ripemd160', decode_hex(hash256)).hexdigest()
    checksum = checksum[:8]
    formatted_key = prefix + payload + suffix + checksum
    return base58.b58encode(decode_hex(formatted_key))



wip_key_compressed = generate_base58_format(private_key, "80", "01")
wip_key_uncompressed = generate_base58_format(private_key, "80")

print("WIP Private key Compressed:", wip_key_compressed)
print("WIP Private key Uncompressed:", wip_key_uncompressed)

uncompressed_public_key = "04" + str(public_key[0]) + str(public_key[1])
prefix_compressed_public_key = "02" if public_key[1] % 2 == 0 else "03"
compressed_public_key = prefix_compressed_public_key + str(public_key[0])
print("Uncompressed Public key: ", uncompressed_public_key)
print("Compressed Public key: ", compressed_public_key)
print(public_key)
print(str(hex(public_key[0])))
print("Uncompressed Bitcoin Address: ", generate_base58_format(str(public_key[0]) + str(public_key[1]), "04"))
print("Compressed Bitcoin Address: ", generate_base58_format(str(public_key[0]), prefix_compressed_public_key))