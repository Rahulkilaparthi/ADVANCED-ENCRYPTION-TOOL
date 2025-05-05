# AES-256 Encryption Tool

This is a simple and robust file encryption and decryption tool built with Python. It uses the AES-256 algorithm for strong encryption and provides a user-friendly graphical interface.

## Features
- Encrypt any file using AES-256 (CBC mode)
- Decrypt previously encrypted files
- Password-based encryption (PBKDF2 key derivation)
- Simple and intuitive GUI (built with tkinter)

## Requirements
- Python 3.x
- cryptography library

## Setup
1. Clone or download this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the application:
   ```bash
   python main.py
   ```
2. In the GUI:
   - Click **Browse** to select a file to encrypt or decrypt.
   - Enter a password (remember it, as it is required for decryption).
   - Click **Encrypt** to create an encrypted file (`yourfile.ext.enc`).
   - Click **Decrypt** to decrypt an `.enc` file (creates `yourfile.ext.dec`).

## Test File
A sample file `testfile.txt` is included for testing. Try encrypting and then decrypting it to verify the tool works.

## Notes
- The password is not stored anywhere. If you forget it, you cannot decrypt your files.
- Encrypted files have the `.enc` extension. Decrypted files have the `.dec` extension.

## License
This project is for educational and internship purposes. 