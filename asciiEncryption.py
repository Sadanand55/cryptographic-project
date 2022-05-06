import tkinter as tk

FONT = ("Garamond", 20, "bold","italic")
 
class CryptoGUI:
    def __init__(self, master):
        master.title("Cryptography Machine")
        self.Message = tk.StringVar(master, value="")
        self.ciphertext = tk.StringVar(master, value="")
        self.key = tk.IntVar(master)

        # Message controls
        self.plain_label = tk.Label(master, text="Message", fg="green", font=FONT).grid(row=0, column=0)
        self.plain_entry = tk.Entry(master,
                                    textvariable=self.Message, width=50, font=FONT)
        self.plain_entry.grid(row=0, column=1,padx=20)
        self.encrypt_button = tk.Button(master, text="Encrypt",
                                        command=lambda: self.encrypt_callback(), font=FONT).grid(row=0, column=2)
        
        # Key controls
        self.key_label = tk.Label(master, text="Key", font=FONT).grid(row=1, column=0)
        self.key_entry = tk.Entry(master, textvariable=self.key, width=10, font=FONT).grid(row=1, column=1,
                                                                                           sticky=tk.W, padx=20)

        # Ciphertext controls
        self.cipher_label = tk.Label(master, text="Ciphertext", fg="red", font=FONT).grid(row=2, column=0)
        self.cipher_entry = tk.Entry(master,
                                     textvariable=self.ciphertext, width=50, font=FONT)
        self.cipher_entry.grid(row=2, column=1, padx=20)
        self.decrypt_button = tk.Button(master, text="Decrypt",
                                        command=lambda: self.decrypt_callback(), font=FONT).grid(row=2, column=2)
       

    

    def get_key(self):
       
         key_val = self.key.get()
         return key_val
       

    def encrypt_callback(self):
        key = self.get_key()
        ciphertext = encrypt(self.plain_entry.get(), key)
        self.cipher_entry.delete(0, tk.END)
        self.cipher_entry.insert(0, ciphertext)

    def decrypt_callback(self):
        key = self.get_key()
        Message = decrypt(self.cipher_entry.get(), key)
        self.plain_entry.delete(0, tk.END)
        self.plain_entry.insert(0, Message)

def encrypt(Message, key):    
    ciphertext = ""
    for i in Message:
        ciphertext += chr(ord(i)+key)
    return ciphertext

def decrypt(ciphertext, key):
    Message = ""
    for i in ciphertext:
        Message += chr(ord(i)-key)
    return Message


if __name__ == "__main__":
    
    root = tk.Tk()
    window = CryptoGUI(root)
    root.mainloop()

