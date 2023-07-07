import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

KEY_LENGTH_AES_256 = 32

class KeyLengthError(Exception):
    pass

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def main():
    parser = argparse.ArgumentParser(description='AES Encryption and Decryption',
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-e', '--encrypt', action='store_true', help='Perform encryption')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Perform decryption')

    parser.add_argument('-k', '--key', help='Encryption/Decryption key\n'
                                             f'Required for decryption\n'
                                             f'Must be a 64-byte (512-bit) hexadecimal string')

    parser.add_argument('-t', '--plaintext', help='Plaintext (for encryption)\n'
                                                   'Enclose in double quotes ("")')
    parser.add_argument('-c', '--ciphertext', help='Ciphertext (for decryption)')
    parser.add_argument('-o', '--output', help='Output file path')

    args = parser.parse_args()

    output_data = ''

    if args.encrypt and args.plaintext:
        if args.key and len(args.key) == KEY_LENGTH_AES_256 * 2:
            key = bytes.fromhex(args.key)
        else:
            key = get_random_bytes(KEY_LENGTH_AES_256)
            output_data += f'Generated Key: {key.hex()}\n'

        plaintext = args.plaintext.encode()
        ciphertext = encrypt(key, plaintext)

        output_data += 'Encryption:\n'
        output_data += f'Key: {key.hex()}\n'
        output_data += f'Plaintext: {args.plaintext}\n'
        output_data += f'Ciphertext: {ciphertext.hex()}\n'

    elif args.decrypt and args.key and args.ciphertext:
        if len(args.key) != KEY_LENGTH_AES_256 * 2:
            raise KeyLengthError('Key length is not 64 bytes (512 bits)')
        key = bytes.fromhex(args.key)
        ciphertext = bytes.fromhex(args.ciphertext)

        if len(ciphertext) % AES.block_size != 0:
            raise ValueError('Invalid ciphertext length')

        try:
            plaintext = decrypt(key, ciphertext)
            output_data += 'Decryption:\n'
            output_data += f'Key: {args.key}\n'
            output_data += f'Ciphertext: {args.ciphertext}\n'
            output_data += f'Plaintext: {plaintext.decode()}\n'
        except ValueError:
            output_data += 'Decryption failed. Invalid key or ciphertext.\n'

    else:
        parser.print_help()

    if args.output:
        with open(args.output, 'w') as file:
            file.write(output_data)

    print(output_data, end='')

if __name__ == '__main__':
    try:
        main()
    except KeyLengthError as e:
        print('Error:', str(e))
