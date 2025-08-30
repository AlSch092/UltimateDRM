# dump_xy.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import binascii, sys
pub = serialization.load_pem_public_key(open("vendor_pub.pem","rb").read())
nums = pub.public_numbers()
print("X=", binascii.hexlify(nums.x.to_bytes(32,'big')).decode())
print("Y=", binascii.hexlify(nums.y.to_bytes(32,'big')).decode())
