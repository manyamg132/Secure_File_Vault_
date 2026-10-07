# Implementation of Secure File Vault

A secure desktop-based file encryption application developed for the Cryptography and Network Security course [BCS703].

## Project Overview

The Secure File Vault provides secure file encryption and decryption using modern cryptographic techniques. The project is designed to protect files from unauthorized access and detect unauthorized modification.

The application uses AES-256-GCM for authenticated encryption, SHA-256 for integrity verification, and PBKDF2-HMAC-SHA256 for deriving a secure encryption key from a password.

## Features

- AES-256-GCM file encryption
- AES-256-GCM file decryption
- SHA-256 integrity verification
- PBKDF2-HMAC-SHA256 key derivation
- Random salt generation
- Random nonce generation
- Tampering detection
- User registration
- Password authentication
- Email OTP verification
- SQLite database for user information
- GUI-based application using CustomTkinter
- Support for different file types

## Security Techniques

### AES-256-GCM

AES-256-GCM is used to encrypt files and provide authenticated encryption. It protects the confidentiality of the file and detects unauthorized modification of encrypted data.

### SHA-256

SHA-256 is used to calculate the hash of the original file. The hash is used to verify file integrity after decryption.

### PBKDF2-HMAC-SHA256

PBKDF2-HMAC-SHA256 is used to derive a 256-bit encryption key from the user's password.

The implementation uses:

- SHA-256
- 600,000 PBKDF2 iterations
- 16-byte random salt
- 32-byte derived key

### Salt and Nonce

A random salt is generated for key derivation and a random nonce is generated for AES-GCM encryption.

## Project Modules

```text
SecureFileVault/
│
├── main.py
├── crypto_utils.py
├── file_manager.py
├── database.py
├── auth_manager.py
├── otp_manager.py
├── config.example.py
├── requirements.txt
├── README.md
└── .gitignore

Working Flow
User Registration
       ↓
Email OTP Verification
       ↓
Login
       ↓
Select File
       ↓
Password
       ↓
PBKDF2 Key Derivation
       ↓
AES-256-GCM Encryption
       ↓
Encrypted .vault File
       ↓
Decryption
       ↓
SHA-256 Integrity Verification
Installation
1. Clone the repository
git clone https://github.com/manyamg132/SecureFileVault.git
2. Open the project
cd SecureFileVault
3. Create a virtual environment
python -m venv venv
4. Activate the virtual environment

On Windows PowerShell:

.\venv\Scripts\Activate.ps1
5. Install dependencies
pip install -r requirements.txt
6. Run the application
python main.py
