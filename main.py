from AsymmetricEnc.PrivPub import *
from SymmetricEnc.CBC_AES import *
from create_keys import *

if __name__ == '__main__':
    create_keys()
    encryptCBC_AES("FileToEncrypt/2023-BMW-7.jpg", "EncryptedFile")
    decryptCBC_AES("EncryptedFile/2023-BMW-7.json", "OutputFile")

    encryptPubPriv("Keys/symkey.txt", "EncryptedFile")

    decryptPubPriv("EncryptedFile/symkey.json", "OutputFile")
