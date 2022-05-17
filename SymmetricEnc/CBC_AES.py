import json
import os
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt(dir: str):
    with open(dir, "rb") as file:
        data = file
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC)

        ct_bytes = cipher.encrypt(pad(data.read(), AES.block_size))

        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')

        file_name = os.path.basename(dir)
        file_name, file_extension=os.path.splitext(file_name)
        result = json.dumps({'file_extension': file_extension, 'iv': iv, 'ciphertext': ct})
        with open('EncryptedFile/' + file_name + '.json', 'w') as c_file:
            c_file.write(result)


    return key


def decrypt(key, dir: str):
    with open(dir, 'rb') as c_file:

        json_input = c_file.read()
        try:
            b64 = json.loads(json_input)

            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)

            file_name = os.path.basename(dir)
            file_name, _ = os.path.splitext(file_name)
            file_extension = b64['file_extension']

            with open("OutputFile/" + file_name + file_extension, "wb") as outFile:
                outFile.write(pt)


        except (ValueError, KeyError):
            print("Incorrect decryption")
