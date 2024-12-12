import tkinter as tk
from tkinter import messagebox, filedialog
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# AES Functions
def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def aes_decrypt(encrypted_text, key):
    data = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# DES Functions
def des_encrypt(text, key):
    cipher = DES.new(key, DES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def des_decrypt(encrypted_text, key):
    data = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = data[:8], data[8:16], data[16:]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# RSA Functions
def rsa_encrypt(text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(encrypted_text, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(encrypted_text)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Tkinter UI
def perform_encryption():
    text = input_text.get("1.0", tk.END).strip()
    method = encryption_method.get()
    key = key_entry.get().encode('utf-8')

    try:
        if method == "AES":
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long.")
            encrypted = aes_encrypt(text, key)
        elif method == "DES":
            if len(key) != 8:
                raise ValueError("DES key must be 8 bytes long.")
            encrypted = des_encrypt(text, key)
        elif method == "RSA":
            key_file = filedialog.askopenfilename(title="Select RSA Public Key File")
            with open(key_file, "rb") as f:
                public_key = RSA.import_key(f.read())
            encrypted = rsa_encrypt(text, public_key)
        else:
            raise ValueError("Invalid encryption method selected.")

        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", encrypted)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def perform_decryption():
    encrypted_text = input_text.get("1.0", tk.END).strip()
    method = encryption_method.get()
    key = key_entry.get().encode('utf-8')

    try:
        if method == "AES":
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long.")
            decrypted = aes_decrypt(encrypted_text, key)
        elif method == "DES":
            if len(key) != 8:
                raise ValueError("DES key must be 8 bytes long.")
            decrypted = des_decrypt(encrypted_text, key)
        elif method == "RSA":
            key_file = filedialog.askopenfilename(title="Select RSA Private Key File")
            with open(key_file, "rb") as f:
                private_key = RSA.import_key(f.read())
            decrypted = rsa_decrypt(encrypted_text, private_key)
        else:
            raise ValueError("Invalid decryption method selected.")

        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", decrypted)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Main application
root = tk.Tk()
root.title("Text Encryption and Decryption")

# UI Elements
tk.Label(root, text="Input Text:").pack()
input_text = tk.Text(root, height=10, width=50)
input_text.pack()

tk.Label(root, text="Key (for AES/DES):").pack()
key_entry = tk.Entry(root, width=50)
key_entry.pack()

tk.Label(root, text="Encryption Method:").pack()
encryption_method = tk.StringVar(value="AES")
tk.OptionMenu(root, encryption_method, "AES", "DES", "RSA").pack()

tk.Button(root, text="Encrypt", command=perform_encryption).pack()
tk.Button(root, text="Decrypt", command=perform_decryption).pack()

tk.Label(root, text="Output Text:").pack()
output_text = tk.Text(root, height=10, width=50)
output_text.pack()

root.mainloop()
