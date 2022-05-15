
from SymmetricEnc.CBC_AES import *
if __name__ == '__main__':
    key=encrypt("FileToEncrypt/2023-BMW-7.jpg")
    decrypt(key,"EncryptedFile/2023-BMW-7.json")
