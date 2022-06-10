from Crypto.Cipher import AES
from create_keys import *
from asymmetric_encryption import *
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json
import os


def encrypt_aes(original_file_path: str, foreign_public_key: bytes, aes_symmetric_mode: int):
    with open(original_file_path, "rb") as file:
        data = file

        sym_key = create_sym_key()

        cipher = AES.new(sym_key, aes_symmetric_mode)

        ct_bytes = cipher.encrypt(pad(data.read(), AES.block_size))

        encrypted_sym_key = encrypt_asym(sym_key, foreign_public_key)

        esk = b64encode(encrypted_sym_key).decode('utf-8')
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')

        file_name = os.path.basename(original_file_path)
        file_name, file_extension = os.path.splitext(file_name)
        result = json.dumps(
            {'file_extension': file_extension, 'AES_MODE': aes_symmetric_mode, 'iv': iv, 'encrypted_sym_key': esk,
             'ciphertext': ct})
        with open(os.path.dirname(original_file_path) + '/' + file_name + '.json', 'w') as c_file:
            c_file.write(result)


def decrypt_aes(encrypted_file_path: str):
    with open(encrypted_file_path, 'rb') as c_file:

        json_input = c_file.read()
        try:
            b64 = json.loads(json_input)
            encrypted_sym_key = b64decode(b64['encrypted_sym_key'])

            sym_key = decrypt_asym(encrypted_sym_key)

            iv = b64decode(b64['iv'])
            ct = b64decode(b64['ciphertext'])
            aes_mode = int(b64['AES_MODE'])

            cipher = AES.new(sym_key, aes_mode, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)

            file_name = os.path.basename(encrypted_file_path)
            file_name, _ = os.path.splitext(file_name)
            file_extension = b64['file_extension']

            with open(os.path.dirname(encrypted_file_path) + "/" + "decrypted_" + file_name + file_extension, "wb") as outFile:
                outFile.write(pt)

        except (ValueError, KeyError):
            print("Incorrect decryption")
