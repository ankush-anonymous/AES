# AES Encryption and Decryption

This Python command-line tool allows you to perform AES encryption and decryption. It uses AES-256, provides key generation, and supports file output. It's a simple and secure solution for encrypting your data.

## Features

- AES-256 encryption and decryption
- Key generation if not provided for encryption
- Command-line interface for easy usage
- Supports plaintext and ciphertext input
- Output results to a file

## Usage

1. Install the required dependencies: `pip install pycryptodome`
2. Run the script with the desired options:
   - For encryption: `python secureCLI.py -e [-k "your-key"] -t "plaintext" -o output.txt`
   - For decryption: `python secureCLI.py -d -k "your-key" -c "ciphertext" -o output.txt`
   - Output file can be specified with the `-o` option

Note: If the key is not provided for encryption, the program will generate a random key.

Please refer to the script's help section for more details and options.


