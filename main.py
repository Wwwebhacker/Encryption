from tkinter import filedialog

from create_keys import *
import tkinter as tk
from tkinter import filedialog
import platform
from my_AES import *
from create_keys import *
from pathlib import Path
from tkinter import messagebox

if __name__ == '__main__':

    def refresh_text_input():
        global foreign_public_key
        foreign_public_key = txt_user_input.get("1.0", tk.END)

    def refresh_widgets():
        global symmetric_mode
        if var_mode.get() == 1:
            symmetric_mode = AES.MODE_ECB
        if var_mode.get() == 2:
            symmetric_mode = AES.MODE_CBC
        if var_mode.get() == 3:
            symmetric_mode = AES.MODE_CTR
        if var_mode.get() == 4:
            symmetric_mode = AES.MODE_CFB

        if var_action.get() == 1:
            btn_proceed.pack_forget()
            frm_mode.pack_forget()
            txt_user_input.pack_forget()
            lbl_user_instruction.pack_forget()
            btn_proceed.pack()
        else:
            btn_proceed.pack_forget()
            frm_mode.pack()
            lbl_user_instruction.pack()
            txt_user_input.pack()
            btn_proceed.pack()

    def update_text_field():
        f = open('Keys/asymkeys.pem', 'rb')
        key = RSA.import_key(f.read())
        f.close()
        key = key.public_key().exportKey()
        #txt_public_key.delete("1.0", tk.END)
        #txt_public_key.insert("1.0", key)
        window.clipboard_clear()
        window.clipboard_append(key)
        window.update()

    def process_file():
        refresh_text_input()
        if var_action.get() == 1:
            if encrypted_file_path != "":
                res = decrypt(encrypted_file_path)
                if res:
                    tk.messagebox.showinfo("Decryption result", "You have decrypted selected file into the same folder where original was.")
                else:
                    tk.messagebox.showinfo("Decryption result", "You cannot decrypt that file")
            else:
                tk.messagebox.showinfo("Decryption result", "You have to choose file first!")
        else:
            if encrypted_file_path!= "" and foreign_public_key != "\n":
                tk.messagebox.showinfo("Encryption result", "You have encrypted selected file into the same folder where original was.")
                encypt_file(original_file_path, foreign_public_key, symmetric_mode)
            else:
                tk.messagebox.showinfo("Encryption result", "You have to choose file first and enter foreign public key!")

    def choose_file():
        window.withdraw()
        global encrypted_file_path
        encrypted_file_path = filedialog.askopenfilename(parent=window,title='Choose a file')
        global original_file_path
        original_file_path = encrypted_file_path
        lbl_file_path.config(text=encrypted_file_path)
        window.deiconify()

    def decrypt(encrypted_file_path):
        return decrypt_aes(encrypted_file_path)

    def encypt_file(original_file_path, foreign_public_key, symmetric_mode):
        return encrypt_aes(original_file_path, foreign_public_key, symmetric_mode)


    path = Path('Keys/asymkeys.pem')
    if not path.is_file():
        create_private_key()

    foreign_public_key = "\n"
    symmetric_mode = AES.MODE_ECB
    original_file_path = ""
    encrypted_file_path = ""

    #encypt_file(original_file_path, foreign_public_key, symmetric_mode); (#encrypted_sym_key = encrypt_asym(sym_key);#sym_key = create_sym_key();) -> inside encrypt_file
    #decrypt(encrypted_file_path)

    window = tk.Tk()
    window.geometry("700x400")
    window.title("File encryption")

    btn_public_key = tk.Button(text="Copy your public key to clipboard", command = update_text_field)
    #txt_public_key = tk.Text(width=75, height=10)
    update_text_field()
    btn_public_key.pack()
    #txt_public_key.pack()

    frm_central = tk.Frame()
    frm_central.pack()

    btn_browse = tk.Button(frm_central, text="Browse file", command=choose_file)
    btn_browse.pack(anchor=tk.W, side=tk.LEFT)

    lbl_file_path = tk.Label(frm_central, text="You haven't chosen file yet.");
    lbl_file_path.pack()

    lbl_action = tk.Label(text="What do you want to do?")
    lbl_action.pack()
    frm_encryption_decryption = tk.Frame()
    frm_encryption_decryption.pack()
    var_action = tk.IntVar(None, 2)
    R1_action = tk.Radiobutton(frm_encryption_decryption, text="Decryption", variable=var_action, value=1, command=refresh_widgets)
    R1_action.pack(anchor=tk.W, side=tk.LEFT)
    R2_action = tk.Radiobutton(frm_encryption_decryption, text="Encryption", variable=var_action, value=2, command=refresh_widgets)
    R2_action.pack(anchor=tk.W)

    frm_mode = tk.Frame()
    frm_mode.pack()

    lbl_mode = tk.Label(frm_mode, text="Choose cryptography mode")
    lbl_mode.pack()

    var_mode = tk.IntVar(None, 1)
    R1_mode = tk.Radiobutton(frm_mode, text="ECB", variable=var_mode, value=1, command=refresh_widgets)
    R1_mode.pack(anchor=tk.W, side=tk.LEFT)
    R2_mode = tk.Radiobutton(frm_mode, text="CBC", variable=var_mode, value=2, command=refresh_widgets)
    R2_mode.pack(anchor=tk.W, side=tk.LEFT)
    R3_mode = tk.Radiobutton(frm_mode, text="CTR", variable=var_mode, value=3, command=refresh_widgets)
    R3_mode.pack(anchor=tk.W, side=tk.LEFT)
    R4_mode = tk.Radiobutton(frm_mode, text="CFB", variable=var_mode, value=4, command=refresh_widgets)
    R4_mode.pack(anchor=tk.W, side=tk.LEFT)

    lbl_user_instruction = tk.Label(text="Provide a key to encrypt the file:")
    lbl_user_instruction.pack()

    txt_user_input = tk.Text(width=75, height=10)
    txt_user_input.pack()

    btn_proceed = tk.Button(text = "Proceed", command = process_file)
    btn_proceed.pack()

    #encryptCBC_AES("FileToEncrypt/2023-BMW-7.jpg", "EncryptedFile")
    #decryptCBC_AES("EncryptedFile/2023-BMW-7.json", "OutputFile")


    #encryptPubPriv("Keys/symkey.txt", "EncryptedFile")
    #decryptPubPriv("EncryptedFile/symkey.json", "OutputFile")
    window.mainloop()