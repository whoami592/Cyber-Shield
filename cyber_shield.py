# Cyber Shield - A Cybersecurity Tool
# Created by Mr. Sabaz Ali Khan
# Features: Password Generation, File Encryption/Decryption, Basic Port Scanning

import string
import random
import socket
import os
from cryptography.fernet import Fernet
from datetime import datetime

class CyberShield:
    def __init__(self):
        self.key_file = "secret.key"
        self.fernet = None
        self.load_or_generate_key()

    def load_or_generate_key(self):
        """Load or generate a Fernet key for encryption/decryption."""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as file:
                key = file.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as file:
                file.write(key)
        self.fernet = Fernet(key)

    def generate_password(self, length=12):
        """Generate a random secure password."""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def encrypt_file(self, input_file, output_file):
        """Encrypt a file using Fernet symmetric encryption."""
        try:
            with open(input_file, "rb") as file:
                data = file.read()
            encrypted_data = self.fernet.encrypt(data)
            with open(output_file, "wb") as file:
                file.write(encrypted_data)
            print(f"File encrypted successfully: {output_file}")
        except Exception as e:
            print(f"Encryption failed: {e}")

    def decrypt_file(self, input_file, output_file):
        """Decrypt a file using Fernet symmetric encryption."""
        try:
            with open(input_file, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            with open(output_file, "wb") as file:
                file.write(decrypted_data)
            print(f"File decrypted successfully: {output_file}")
        except Exception as e:
            print(f"Decryption failed: {e}")

    def scan_port(self, target_ip, port):
        """Scan a single port on a target IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    def port_scanner(self, target_ip, port_range=(1, 100)):
        """Scan a range of ports on a target IP."""
        print(f"Scanning {target_ip} for open ports {port_range[0]}-{port_range[1]}...")
        open_ports = []
        for port in range(port_range[0], port_range[1] + 1):
            port, is_open = self.scan_port(target_ip, port)
            if is_open:
                open_ports.append(port)
                print(f"Port {port} is open")
        return open_ports

def main():
    print("Cyber Shield - Created by Mr. Sabaz Ali Khan")
    print("========================================")
    shield = CyberShield()

    while True:
        print("\nOptions:")
        print("1. Generate Password")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Scan Ports")
        print("5. Exit")
        choice = input("Select an option (1-5): ")

        if choice == "1":
            length = int(input("Enter password length (default 12): ") or 12)
            password = shield.generate_password(length)
            print(f"Generated Password: {password}")

        elif choice == "2":
            input_file = input("Enter input file path: ")
            output_file = input("Enter output file path (encrypted): ")
            shield.encrypt_file(input_file, output_file)

        elif choice == "3":
            input_file = input("Enter encrypted file path: ")
            output_file = input("Enter output file path (decrypted): ")
            shield.decrypt_file(input_file, output_file)

        elif choice == "4":
            target_ip = input("Enter target IP address: ")
            start_port = int(input("Enter start port (default 1): ") or 1)
            end_port = int(input("Enter end port (default 100): ") or 100)
            open_ports = shield.port_scanner(target_ip, (start_port, end_port))
            if not open_ports:
                print("No open ports found.")

        elif choice == "5":
            print("Exiting Cyber Shield. Stay secure!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()