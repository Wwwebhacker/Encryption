from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def create_sym_key():
    return get_random_bytes(16)


def create_private_key():
    keypair = RSA.generate(2048)
    f = open('Keys/asymkeys.pem', 'wb')
    f.write(keypair.export_key('PEM'))
    f.close()
