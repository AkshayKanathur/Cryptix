import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64
import os

from cryptography.fernet import Fernet
from Crypto.Cipher import DES, Blowfish
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
import pyperclip

# === Encrypt/Decrypt Functions ===

def encrypt_aes(text, key):
    f = Fernet(key.encode())
    return f.encrypt(text.encode()).decode()

def decrypt_aes(token, key):
    f = Fernet(key.encode())
    return f.decrypt(token.encode()).decode()

def encrypt_des(text, key_hex):
    key = bytes.fromhex(key_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(text.encode(), 8)
    ct = cipher.encrypt(padded)
    return ct.hex()

def decrypt_des(ciphertext_hex, key_hex):
    key = bytes.fromhex(key_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    ct = bytes.fromhex(ciphertext_hex)
    pt = unpad(cipher.decrypt(ct), 8)
    return pt.decode()

def encrypt_blowfish(text, key_b64):
    key = base64.b64decode(key_b64)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    padded = pad(text.encode(), Blowfish.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def decrypt_blowfish(cipher_b64, key_b64):
    key = base64.b64decode(key_b64)
    data = base64.b64decode(cipher_b64)
    iv = data[:8]
    encrypted = data[8:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), Blowfish.block_size)
    return decrypted.decode()

def encrypt_rsa(text, public_pem):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    ciphertext = public_key.encrypt(
        text.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_rsa(cipher_b64, private_pem):
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    ciphertext = base64.b64decode(cipher_b64.encode())
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# === GUI ===

def browse_file():
    filepath = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filepath)

def copy_result():
    pyperclip.copy(result_text.get("1.0", tk.END).strip())
    messagebox.showinfo("Copied", "Result copied to clipboard.")

def process():
    algo = algo_var.get()
    mode = mode_var.get()
    text = text_entry.get("1.0", tk.END).strip()
    filepath = file_entry.get()
    key = key_entry.get("1.0", tk.END).strip()

    if not algo or not mode or not key:
        messagebox.showerror("Error", "Algorithm, Mode, and Key are required.")
        return

    try:
        result = ""
        if filepath:
            with open(filepath, "rb") as f:
                raw = f.read()
                data = base64.b64encode(raw).decode()
        else:
            data = text

        if mode == "Encrypt":
            if algo == "aes":
                result = encrypt_aes(data, key)
            elif algo == "des":
                result = encrypt_des(data, key)
            elif algo == "rsa":
                result = encrypt_rsa(data, key)
            elif algo == "blowfish":
                result = encrypt_blowfish(data, key)
        else:
            if algo == "aes":
                result = decrypt_aes(data, key)
            elif algo == "des":
                result = decrypt_des(data, key)
            elif algo == "rsa":
                result = decrypt_rsa(data, key)
            elif algo == "blowfish":
                result = decrypt_blowfish(data, key)

        if filepath and mode == "Decrypt":
            # Save decoded binary
            output_path = filepath + "_output"
            with open(output_path, "wb") as f:
                f.write(base64.b64decode(result.encode()))
            result = f"Decrypted binary saved to: {output_path}"

        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, result)

    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")

# === Layout ===

root = tk.Tk()
root.title("Cryptix GUI - Encrypt / Decrypt Tool")
root.geometry("600x500")

ttk.Label(root, text="Algorithm:").pack()
algo_var = tk.StringVar()
algo_menu = ttk.Combobox(root, textvariable=algo_var, values=["aes", "des", "rsa", "blowfish"])
algo_menu.pack()

ttk.Label(root, text="Mode:").pack()
mode_var = tk.StringVar()
mode_menu = ttk.Combobox(root, textvariable=mode_var, values=["Encrypt", "Decrypt"])
mode_menu.pack()

ttk.Label(root, text="Text (or leave blank for file):").pack()
text_entry = tk.Text(root, height=3)
text_entry.pack()

ttk.Label(root, text="File (optional):").pack()
file_entry = tk.Entry(root, width=60)
file_entry.pack()
ttk.Button(root, text="Browse", command=browse_file).pack()

ttk.Label(root, text="Key:").pack()
key_entry = tk.Text(root, height=4)
key_entry.pack()

ttk.Button(root, text="Run", command=process).pack(pady=10)

result_text = tk.Text(root, height=6, bg="#f0f0f0")
result_text.pack()

ttk.Button(root, text="Copy Result", command=copy_result).pack(pady=5)

root.mainloop()
