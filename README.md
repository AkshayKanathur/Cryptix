# Cryptix
Cryptix – Encryption/Decryption Tool (Text + File + Binary Support)
A command-line encryption tool supporting AES, DES, RSA, and Blowfish, with binary file handling, text support, key generation, and clipboard copy.

Supported Algorithms : 
AES (Fernet 256-bit)

DES (ECB mode)

RSA (2048-bit)

Blowfish (CBC mode)

Features :
✅ Encrypt/Decrypt text

✅ Encrypt/Decrypt files (including binary files like .jpg, .pdf, .exe)

✅ Detects binary files automatically

✅ Base64 encoding for safe binary encryption

✅ Clipboard copy support (pyperclip)

✅ Key generation for all algorithms

✅ Clean output filenames: _enc_algo, _dec_algo

🧪 Installation
bash
Copy
Edit
pip install pycryptodome cryptography pyperclip
🚀 Usage Examples
🔑 Generate Keys
bash
Copy
Edit
python cryptix_perfect_final.py genkey --algo aes
python cryptix_perfect_final.py genkey --algo des
python cryptix_perfect_final.py genkey --algo rsa
python cryptix_perfect_final.py genkey --algo blowfish
📝 Text Encryption
bash
Copy
Edit
python cryptix_perfect_final.py encrypt --text "hello world" --algo aes --key YOUR_AES_KEY
python cryptix_perfect_final.py decrypt --text ENCRYPTED_TEXT --algo aes --key YOUR_AES_KEY

File Encryption (Text or Binary): 
bash
Copy
Edit
# AES
python cryptix_perfect_final.py encrypt --file myfile.txt --algo aes --key YOUR_AES_KEY
python cryptix_perfect_final.py decrypt --file myfile_enc_aes --algo aes --key YOUR_AES_KEY

# Blowfish
python cryptix_perfect_final.py encrypt --file image.png --algo blowfish --key YOUR_BLOWFISH_KEY
python cryptix_perfect_final.py decrypt --file image_enc_blowfish --algo blowfish --key YOUR_BLOWFISH_KEY
⚠️ RSA Limitation
RSA only supports text, not binary files.

Encrypt small strings only (e.g., passwords, keys).

 Clipboard Copy
After encryption or key generation, you'll be asked:

Do you want to copy to the clipboard? [y/n]

 Output File Naming
The script will automatically generate:

filename_enc_aes → for encrypted files

filename_dec_aes → for decrypted files

 Intern-Friendly Design
Clear CLI for text/file modes

Fully explained code and reusable functions

Safe to use in internships, demos, or real-world scenarios
