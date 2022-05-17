from base64 import b64encode, b64decode
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def encryptPubPriv(path:str,outputfolder:str):
    with open(path, "rb") as file:
        data = file.read()

        with open('Keys/asymkeys.pem', 'rb') as f:
            key = RSA.import_key(f.read())
            f.close()
            key=key.public_key()
            cipher = PKCS1_OAEP.new(key)
            ct_bytes = cipher.encrypt(data)


            ct = b64encode(ct_bytes).decode('utf-8')

            file_name = os.path.basename(path)
            file_name, file_extension = os.path.splitext(file_name)
            result = json.dumps({'file_extension': file_extension, 'ciphertext': ct})
            with open(outputfolder+'/' + file_name + '.json', 'w') as c_file:
                c_file.write(result)


def decryptPubPriv(path: str,outputfolder:str):
    with open(path, "rb") as c_file:
        json_input = c_file.read()
        try:
            b64 = json.loads(json_input)

            with open('Keys/asymkeys.pem', 'rb') as f:
                key = RSA.import_key(f.read())
                f.close()
            ct = b64decode(b64['ciphertext'])
            cipher = PKCS1_OAEP.new(key)
            pt=cipher.decrypt(ct)

            file_name = os.path.basename(path)
            file_name, _ = os.path.splitext(file_name)
            file_extension = b64['file_extension']

            with open(outputfolder+"/" + file_name + file_extension, "wb") as outFile:
                outFile.write(pt)


        except (ValueError, KeyError):
            print("Incorrect decryption")
