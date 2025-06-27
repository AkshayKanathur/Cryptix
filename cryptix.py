import argparse
import pyperclip
from binaryornot.check import is_binary

# AES
from cryptography.fernet import Fernet

# DES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# RSA
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

# ================= AES =================

def generate_key_aes():
    """
    Generate a symmetric AES key using Fernet (base64 encoded).
    """
    return Fernet.generate_key().decode()

def encrypt_aes(text, key):
    """
    Encrypt a string using AES (Fernet).
    :param text: Plain text to encrypt
    :param key: AES key (base64 encoded)
    :return: Encrypted text (base64 encoded)
    """
    f = Fernet(key.encode())
    return f.encrypt(text.encode()).decode()

def decrypt_aes(token, key):
    """
    Decrypt an AES encrypted string.
    :param token: Encrypted text (base64 encoded)
    :param key: AES key (base64 encoded)
    :return: Decrypted plain text
    """
    f = Fernet(key.encode())
    return f.decrypt(token.encode()).decode()

# ================= RSA =================

def generate_key_rsa():
    """
    Generate an RSA private and public key pair.
    :return: Tuple (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem

def encrypt_rsa(text, public_pem):
    """
    Encrypt text using RSA public key.
    :param text: Plain text to encrypt
    :param public_pem: Public key in PEM format
    :return: Encrypted text (base64 encoded)
    """
    public_key = serialization.load_pem_public_key(public_pem.encode())
    ciphertext = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def decrypt_rsa(cipher_b64, private_pem):
    """
    Decrypt RSA encrypted base64 string using private key.
    :param cipher_b64: Encrypted text (base64 encoded)
    :param private_pem: Private key in PEM format
    :return: Decrypted plain text
    """
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    ciphertext = base64.b64decode(cipher_b64.encode())
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# ================= DES =================

def generate_key_des():
    """
    Generate an 8-byte DES key (hex).
    """
    return os.urandom(8).hex()

def encrypt_des(text, key_hex):
    key = bytes.fromhex(key_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text.encode(), 8)
    ct = cipher.encrypt(padded_text)
    return ct.hex()

def decrypt_des(ciphertext_hex, key_hex):
    key = bytes.fromhex(key_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    ct = bytes.fromhex(ciphertext_hex)
    pt = unpad(cipher.decrypt(ct), 8)
    return pt.decode()

# =================== FILE OPS ===================

def read_file(file):
    with open(file, "r") as file:
        return file.read()
    
def write_file(file, content):
    with open(file, "w") as file:
        file.write(content)

# =================== FILE ENC DEC ===================

def encrypt_file(file, key, algo):
    text = read_file(file)  # returns string

    if algo == "aes":
        enc_text = encrypt_aes(text, key)
    elif algo == "des":
        enc_text = encrypt_des(text, key)
    elif algo == "rsa":
        enc_text = encrypt_rsa(text, key)

    out_file = file.replace("_dec_" + algo, "").replace("_enc_" + algo, "") + f"_enc_{algo}"
    write_file(out_file, enc_text)
    print(f"Encrypted file saved to {out_file}")

def decrypt_file(file, key, algo):
    text = read_file(file)

    if algo == "aes":
        dec_text = decrypt_aes(text, key)
    elif algo == "des":
        dec_text = decrypt_des(text, key)
    elif algo == "rsa":
        dec_text = decrypt_rsa(text, key)

    out_file = file.replace("_dec_" + algo, "").replace("_enc_" + algo, "") + f"_dec_{algo}"
    write_file(out_file, dec_text)
    print(f"Decrypted file saved to {out_file}")

# =================== CLI Parser ===================

parser = argparse.ArgumentParser(description="Encrypt/Decrypt Tool")
parser.add_argument("mode", choices=["encrypt", "decrypt", "genkey"], help="Operation mode")
parser.add_argument("--text", help="Text to encrypt or decrypt")
parser.add_argument("--file", help="File to encrypt or decrypt")
parser.add_argument("--algo", required=True, choices=["aes", "des", "rsa"], help="Encryption algorithm to use")
parser.add_argument("--key", help="Key used for encryption/decryption")

args = parser.parse_args()

# Handle key generation
if args.mode == "genkey":
    if args.algo == "aes":
        key = generate_key_aes()
        print("Generated Key:", key)
        choice = input("Do you want to copy the key to clipboard? [y/n] ")
        if choice.upper() == "Y":
            pyperclip.copy(key)
            print("Key copied to clipboard")
    elif args.algo == "des":
        key = generate_key_des()
        print("Generated Key:", key)
        choice = input("Do you want to copy the key to clipboard? [y/n] ")
        if choice.upper() == "Y":
            pyperclip.copy(key)
            print("Key copied to clipboard")
    elif args.algo == "rsa":
        priv, pub = generate_key_rsa()
        print("Private Key:\n", priv)
        print("\nPublic Key:\n", pub)
        choice = input("Do you want to copy the key to clipboard? [y/n] ")
        if choice.upper() == "Y":
            priv_or_pub = input("Which key you want to copy? [1 for private/2 for public] ").lower()
            if priv_or_pub == "1":
                pyperclip.copy(priv)
                print("Private key copied to clipboard.")
            elif priv_or_pub == "2":
                pyperclip.copy(pub)
                print("Public key copied to clipboard.")

# Handle encryption and decryption
elif args.mode in ["encrypt", "decrypt"]:
    if args.algo == "rsa":
        if args.mode == "encrypt" and not args.key:
            print("Error: RSA encryption requires public key via --key")
            exit()
        elif args.mode == "decrypt" and not args.key:
            print("Error: RSA decryption requires private key via --key")
            exit()
        elif args.file and is_binary(args.file):
            print("Error: Binary file not supported.")
            exit()
    else:
        if not (args.text or args.file) or not args.key:
            print("Error: Either --text or --file and --key are required.")
            exit()
        elif args.file and is_binary(args.file):
            print("Error: Binary file not supported.")
            exit()

    try:
        if args.mode == "encrypt":
            if args.algo == "aes":
                if args.file:
                    encrypt_file(args.file, args.key, args.algo)
                else:
                    cipher_text = encrypt_aes(args.text, args.key)
                    print("Encrypted:", cipher_text)
                    choice = input("Do you want to copy the encrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(cipher_text)
                        print("Encrypted text copied to clipboard")
            elif args.algo == "des":
                if args.file:
                    encrypt_file(args.file, args.key, args.algo)
                else:
                    cipher_text = encrypt_des(args.text, args.key)
                    print("Encrypted:", cipher_text)
                    choice = input("Do you want to copy the encrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(cipher_text)
                        print("Encrypted text copied to clipboard")
                        
            elif args.algo == "rsa":
                if args.file:
                    encrypt_file(args.file, args.key, args.algo)
                else:
                    cipher_text = encrypt_rsa(args.text, args.key)
                    print("Encrypted:", cipher_text)
                    choice = input("Do you want to copy the encrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(cipher_text)
                        print("Encrypted text copied to clipboard")
        else:
            if args.algo == "aes":
                if args.file:
                    decrypt_file(args.file, args.key, args.algo)
                else:
                    plain_text = decrypt_aes(args.text, args.key)
                    print("Decrypted:", plain_text)
                    choice = input("Do you want to copy the decrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(plain_text)
                        print("Decrypted text copied to clipboard")
            elif args.algo == "des":
                if args.file:
                    decrypt_file(args.file, args.key, args.algo)
                else:
                    plain_text = decrypt_des(args.text, args.key)
                    print("Decrypted:", plain_text)
                    choice = input("Do you want to copy the decrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(plain_text)
                        print("Decrypted text copied to clipboard")
            elif args.algo == "rsa":
                if args.file:
                    decrypt_file(args.file, args.key, args.algo)
                else:
                    plain_text = decrypt_rsa(args.text, args.key)
                    print("Decrypted:", plain_text)
                    choice = input("Do you want to copy the decrypted text? [y/n] ").upper()
                    if choice == "Y":
                        pyperclip.copy(plain_text)
                        print("Decrypted text copied to clipboard")
    except Exception as e:
        print("Error:", e)