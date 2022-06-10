from my_AES import *
from create_keys import *
from pathlib import Path


def main():
    path = Path('Keys/asymkeys.pem')
    if not path.is_file():
        create_private_key()

    with open('Keys/asymkeys.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
        pub_key=private_key.public_key()
        foreign_public_key=pub_key.exportKey()
        encrypt_aes("FileToEncrypt/2023-BMW-7.jpg",foreign_public_key, AES.MODE_CFB)

    decrypt_aes("FileToEncrypt/2023-BMW-7.json")


if __name__ == '__main__':
    main()