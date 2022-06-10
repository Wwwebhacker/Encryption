from create_keys import *
import tkinter as tk




if __name__ == '__main__':


    def refresh_widgets():
        if var_action.get() == 1:
            if var_method.get() == 2:
                lbl_user_instruction.config(text="Provide the key to decrypt the file:")
                btn_proceed.pack_forget()
                txt_user_input.pack()
                btn_proceed.pack()
            else:
                lbl_user_instruction.config(text="")
                btn_proceed.pack_forget()
                txt_user_input.pack_forget()
                btn_proceed.pack()
        else:
            if var_method.get() == 1:
                lbl_user_instruction.config(text="Public key for encryption provided by other person:")
                btn_proceed.pack_forget()
                txt_user_input.pack()
                btn_proceed.pack()
            else:
                lbl_user_instruction.config(text="The key to decrypt the file:")
                txt_user_input.delete("1.0", tk.END)
                txt_user_input.insert("1.0", sym_key)
                txt_user_input.pack()
                btn_proceed.pack()
    create_keys()


    def update_text_field():
        f = open('Keys/asymkeys.pem', 'rb')
        key = RSA.import_key(f.read())
        f.close()
        key = key.public_key().exportKey()
        txt_public_key.delete("1.0", tk.END)
        txt_public_key.insert("1.0", key)

    def process_file():
        if var_action.get() == 1:
            if var_method.get() == 1:
                tk =34
            else:
                tk = 34
        else:
            if var_method.get() == 1:
                tk = 34
            else:
                tk = 34


    key = 34
    k = open('Keys/symkey.txt', 'rb')
    sym_key = k.read()
    k.close()



    window = tk.Tk()
    window.title("File encryption")


    btn_public_key = tk.Button(text="Show your public key: ", command = update_text_field)
    txt_public_key = tk.Text(width=75, height=10)
    update_text_field()
    btn_public_key.pack()
    txt_public_key.pack()

    #
    lbl_action = tk.Label(text="What do you want to do?")
    lbl_action.pack()
    frm_encryption_decryption = tk.Frame()
    frm_encryption_decryption.pack()
    var_action = tk.IntVar(None, 1)
    R1_action = tk.Radiobutton(frm_encryption_decryption, text="Decryption", variable=var_action, value=1, command=refresh_widgets)
    R1_action.pack(anchor=tk.W, side=tk.LEFT)
    R2_action = tk.Radiobutton(frm_encryption_decryption, text="Encryption", variable=var_action, value=2, command=refresh_widgets)
    R2_action.pack(anchor=tk.W)
    lbl_method = tk.Label(text = "Choose cryptography method")
    lbl_method.pack()

    frm_method = tk.Frame()
    frm_method.pack()
    var_method = tk.IntVar(None, 1)
    R1_method = tk.Radiobutton(frm_method, text="Asymmetrical", variable=var_method, value=1, command=refresh_widgets)
    R1_method.pack(anchor=tk.W, side=tk.LEFT)
    R2_method = tk.Radiobutton(frm_method, text="Symmetrical", variable=var_method, value=2, command=refresh_widgets)
    R2_method.pack(anchor=tk.W)

    #
    lbl_user_instruction = tk.Label(text = "")
    lbl_user_instruction.pack()

    txt_user_input = tk.Text(width=75, height=10)
    #txt_user_input.pack()

    btn_proceed = tk.Button(text = "Proceed", command = process_file)
    btn_proceed.pack()

    #encryptCBC_AES("FileToEncrypt/2023-BMW-7.jpg", "EncryptedFile")
    #decryptCBC_AES("EncryptedFile/2023-BMW-7.json", "OutputFile")


    #encryptPubPriv("Keys/symkey.txt", "EncryptedFile")
    #decryptPubPriv("EncryptedFile/symkey.json", "OutputFile")
    window.mainloop()
