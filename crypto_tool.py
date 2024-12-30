"""
CryptoTool - A File Encryption/Decryption Tool
Made by Reo-0x (https://github.com/Reo-0x)
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import os
import hashlib
import argparse
import time
import sys

class CryptoTool:
    def __init__(self):
        self.salt = os.urandom(16)
        self.rsa_private_key = None
        self.rsa_public_key = None

    def generate_key_from_password(self, password):
        """Generate a Fernet key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def generate_rsa_keys(self):
        """Generate RSA key pair."""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def load_private_key(self, key_file):
        """Load RSA private key from file."""
        with open(key_file, 'rb') as f:
            private_key_data = f.read()
            self.rsa_private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None
            )

    def calculate_checksum(self, data):
        """Calculate SHA-256 checksum of data."""
        return hashlib.sha256(data).hexdigest()

    def encrypt_file_aes(self, input_file, output_file, password):
        """Encrypt a file using AES (Fernet) with password protection."""
        try:
            # Generate key from password
            fernet = self.generate_key_from_password(password)
            
            # Read input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Calculate original checksum
            original_checksum = self.calculate_checksum(data)
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(data)
            
            # Write encrypted data and metadata
            with open(output_file, 'wb') as f:
                f.write(self.salt)  # Write salt for key derivation
                f.write(original_checksum.encode())  # Write original checksum
                f.write(encrypted_data)  # Write encrypted data
            
            return True
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False

    def decrypt_file_aes(self, input_file, output_file, password):
        """Decrypt a file using AES (Fernet) with password verification."""
        try:
            with open(input_file, 'rb') as f:
                # Read salt and metadata
                self.salt = f.read(16)
                original_checksum = f.read(64).decode()  # SHA-256 is 64 chars in hex
                encrypted_data = f.read()

            # Generate key from password
            fernet = self.generate_key_from_password(password)
            
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Verify checksum
            if self.calculate_checksum(decrypted_data) != original_checksum:
                raise ValueError("File integrity check failed!")

            # Write decrypted data
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            return True
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False

    def encrypt_file_rsa(self, input_file, output_file):
        """Encrypt a file using RSA."""
        try:
            if not self.rsa_public_key:
                self.generate_rsa_keys()

            with open(input_file, 'rb') as f:
                data = f.read()

            # RSA can only encrypt small amounts of data, so we'll use hybrid encryption
            # Generate a random AES key
            aes_key = Fernet.generate_key()
            fernet = Fernet(aes_key)

            # Encrypt the data with AES
            encrypted_data = fernet.encrypt(data)

            # Encrypt the AES key with RSA
            encrypted_key = self.rsa_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Write encrypted key and data
            with open(output_file, 'wb') as f:
                f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
                f.write(encrypted_key)
                f.write(encrypted_data)

            # Save private key for later decryption
            with open(output_file + '.key', 'wb') as f:
                f.write(self.rsa_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            return True
        except Exception as e:
            print(f"RSA encryption error: {str(e)}")
            return False

    def decrypt_file_rsa(self, input_file, output_file, key_file):
        """Decrypt a file using RSA."""
        try:
            # Load the private key
            self.load_private_key(key_file)

            # Read the encrypted file
            with open(input_file, 'rb') as f:
                # Read the encrypted AES key length
                key_length = int.from_bytes(f.read(4), byteorder='big')
                # Read the encrypted AES key
                encrypted_key = f.read(key_length)
                # Read the encrypted data
                encrypted_data = f.read()

            # Decrypt the AES key using RSA
            aes_key = self.rsa_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Create Fernet instance with decrypted key
            fernet = Fernet(aes_key)

            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_data)

            # Write the decrypted data
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            return True
        except Exception as e:
            print(f"RSA decryption error: {str(e)}")
            return False

# [Previous imports and CryptoTool class remain exactly the same until the print_with_delay function]

def print_with_delay(text, delay=0.03):
    """Print text with a faster, smoother typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_encryption_animation():
    frames = [
        """
        ╔════════════════════════════╗
        ║       ENCRYPTING...        ║
        ║           🔑               ║
        ║     [▱▱▱▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       ENCRYPTING...        ║
        ║           🔑               ║
        ║     [▰▱▱▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       ENCRYPTING...        ║
        ║           🔒               ║
        ║     [▰▰▰▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       ENCRYPTING...        ║
        ║           🔒               ║
        ║     [▰▰▰▰▰▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       ENCRYPTING...        ║
        ║           🔒               ║
        ║     [▰▰▰▰▰▰▰▰]             ║
        ╚════════════════════════════╝
        """
    ]

    for frame in frames:
        print("\033[H\033[J")  # Clear screen
        print(frame)
        time.sleep(0.5)  # Increased from 0.3 to 0.5 seconds

def show_decryption_animation():
    frames = [
        """
        ╔════════════════════════════╗
        ║       DECRYPTING...        ║
        ║           🔒               ║
        ║     [▱▱▱▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       DECRYPTING...        ║
        ║           🔑               ║
        ║     [▰▱▱▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       DECRYPTING...        ║
        ║           🔓               ║
        ║     [▰▰▰▱▱▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       DECRYPTING...        ║
        ║           🔓               ║
        ║     [▰▰▰▰▰▱▱▱]             ║
        ╚════════════════════════════╝
        """,
        """
        ╔════════════════════════════╗
        ║       DECRYPTING...        ║
        ║           🔓               ║
        ║     [▰▰▰▰▰▰▰▰]             ║
        ╚════════════════════════════╝
        """
    ]

    for frame in frames:
        print("\033[H\033[J")  # Clear screen
        print(frame)
        time.sleep(0.5)  # Increased from 0.3 to 0.5 seconds

def main():
    parser = argparse.ArgumentParser(description='File Encryption/Decryption Tool')
    parser.add_argument('mode', choices=['encrypt', 'decrypt'])
    parser.add_argument('algorithm', choices=['aes', 'rsa'])
    parser.add_argument('input_file')
    parser.add_argument('output_file')
    parser.add_argument('--password', help='Password for AES encryption/decryption')
    parser.add_argument('--key-file', help='Private key file for RSA decryption')
    
    args = parser.parse_args()
    
    crypto_tool = CryptoTool()
    
    if args.algorithm == 'aes':
        if not args.password:
            print("Password is required for AES encryption/decryption")
            return
            
        if args.mode == 'encrypt':
            show_encryption_animation()
            success = crypto_tool.encrypt_file_aes(args.input_file, args.output_file, args.password)
        else:
            show_decryption_animation()
            success = crypto_tool.decrypt_file_aes(args.input_file, args.output_file, args.password)
    else:  # RSA
        if args.mode == 'encrypt':
            show_encryption_animation()
            success = crypto_tool.encrypt_file_rsa(args.input_file, args.output_file)
        else:
            if not args.key_file:
                print("Private key file is required for RSA decryption")
                return
            show_decryption_animation()
            success = crypto_tool.decrypt_file_rsa(args.input_file, args.output_file, args.key_file)
    
    if not success:
        print(f"\n❌ Failed to {args.mode} file")
    else:
        print("\nMade by Reo-0x (https://github.com/Reo-0x)")

if __name__ == "__main__":
    main()