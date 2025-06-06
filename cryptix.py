import argparse

# AES
from cryptography.fernet import Fernet

# DES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
    Generate a random 8-byte DES key (returned as hex).
    """
    return os.urandom(8).hex()

def encrypt_des(text, key_hex):
    """
    Encrypt plain text using DES with ECB mode.
    :param text: Plain text to encrypt
    :param key_hex: 8-byte key in hex format
    :return: Encrypted hex string
    """
    key = bytes.fromhex(key_hex)
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded = pad(text.encode())
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct.hex()

def decrypt_des(ciphertext_hex, key_hex):
    """
    Decrypt DES encrypted hex string.
    :param ciphertext_hex: Encrypted hex string
    :param key_hex: 8-byte key in hex format
    :return: Decrypted plain text
    """
    key = bytes.fromhex(key_hex)
    ct = bytes.fromhex(ciphertext_hex)
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    return unpad(padded).decode()

def pad(data):
    """
    Pad data to make it a multiple of 8 bytes (DES block size).
    :param data: Byte string
    :return: Padded byte string
    """
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """
    Remove padding added to DES encrypted data.
    :param data: Padded byte string
    :return: Original byte string
    """
    return data[:-data[-1]]

# =================== CLI Parser ===================

parser = argparse.ArgumentParser(description="Encrypt/Decrypt Tool")
parser.add_argument("mode", choices=["encrypt", "decrypt", "genkey"], help="Operation mode")
parser.add_argument("--text", help="Text to encrypt or decrypt")
parser.add_argument("--algo", required=True, choices=["aes", "des", "rsa"], help="Encryption algorithm to use")
parser.add_argument("--key", help="Key used for encryption/decryption")

args = parser.parse_args()

# Handle key generation
if args.mode == "genkey":
    if args.algo == "aes":
        print("Generated Key:", generate_key_aes())
    elif args.algo == "des":
        print("Generated Key:", generate_key_des())
    elif args.algo == "rsa":
        priv, pub = generate_key_rsa()
        print("Private Key:\n", priv)
        print("\nPublic Key:\n", pub)

# Handle encryption and decryption
elif args.mode in ["encrypt", "decrypt"]:
    if args.algo == "rsa":
        if args.mode == "encrypt" and not args.key:
            print("Error: RSA encryption requires public key via --key")
            exit()
        elif args.mode == "decrypt" and not args.key:
            print("Error: RSA decryption requires private key via --key")
            exit()
    else:
        if not args.text or not args.key:
            print("Error: --text and --key are required.")
            exit()

    try:
        if args.mode == "encrypt":
            if args.algo == "aes":
                print("Encrypted:", encrypt_aes(args.text, args.key))
            elif args.algo == "des":
                print("Encrypted:", encrypt_des(args.text, args.key))
            elif args.algo == "rsa":
                print("Encrypted:", encrypt_rsa(args.text, args.key))
        else:
            if args.algo == "aes":
                print("Decrypted:", decrypt_aes(args.text, args.key))
            elif args.algo == "des":
                print("Decrypted:", decrypt_des(args.text, args.key))
            elif args.algo == "rsa":
                print("Decrypted:", decrypt_rsa(args.text, args.key))
    except Exception as e:
        print("Error:", e)