from base64 import b64encode, b64decode
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt_asym(data: bytes, foreign_public_key: bytes):
    key = RSA.import_key(foreign_public_key)
    cipher = PKCS1_OAEP.new(key)
    ct_bytes = cipher.encrypt(data)
    return ct_bytes


def decrypt_asym(data: bytes):
    with open('Keys/asymkeys.pem', 'rb') as f:
        key = RSA.import_key(f.read())
        f.close()
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(data)
