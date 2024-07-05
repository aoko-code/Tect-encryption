import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import getpass

class AesApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Encryption and Decryption tool")
        self.geometry("400x300")
        self.mode_variable = tk.StringVar(value="encrypt")
        self.create_widgets()
    def encrypt(message, password):
        salt = get_random_bytes(16)
        key = derive_key(password, salt)
        init_vector = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
        return salt + init_vector + cipher_text

    def decrypt(encrypted_hex, password):
        salt = encrypted_bytes[:16]
        encrypted_bytes = binascii.unhexlify(encrypted_hex)
        init_vector = encrypted_bytes[16:32]
        key = derive_key(password, salt)

        cipher = AES.new(key, AES.MODE_CBC, init_vector)
        decrypted = unpad(cipher.decrypt(encrypted_bytes[32:]), AES.block_size)

        return decrypted.decode()

    def create_widgets(self):
        ttk.Radiobutton(self, text="Encrypt", variable=self.mode_variable, value="encrypt").pack(pady=5)
        ttk.Radiobutton(self, text="Decrypt", variable=self.mode_variable, value="decrypt").pack(pady=5)

        ttk.Label(self, text="Message:").pack(pady=5)
        self.message_entry = ttk.Entry(self, width=50)
        self.message_entry.pack(pady=5)

        ttk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self, show="*", width=50)
        self.password_entry.pack(pady=5)

        ttk.Button(self, text="Process", command=self.process).pack(pady=20)

        self.result_text = tk.Text(self, height=5, width=50)
        self.result_text.pack(pady=5)


    def process(self):
        mode = self.mode_variable.get()
        message = self.message_entry.get()
        password = self.password_entry.get()

        try:
            if mode == "encrypt":
                result = encrypt(message, password)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"Encrypted(hex): {result.hex()}")
            
            else:
                result = decrypt(encrypted_hex, password)
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"Decrypted: {result}")
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = AesApp()
    app.mainloop()

