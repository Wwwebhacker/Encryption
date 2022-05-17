from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


def create_keys():
    symkey = get_random_bytes(16)
    k = open('Keys/symkey.txt', 'wb')
    k.write(symkey)
    k.close()

    keypair = RSA.generate(2048)
    f = open('Keys/asymkeys.pem', 'wb')
    f.write(keypair.export_key('PEM'))
    f.close()
