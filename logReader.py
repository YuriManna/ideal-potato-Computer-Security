from cryptography.fernet import Fernet
import re

# Load and return the encryption key
def load_encryption_key():
    with open('log.key', 'rb') as key_file:
        key = key_file.read()
    return key  # Return the raw key

# Function to decrypt each log entry
def decrypt_logs(log_file_path, cipher_suite):
    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            # Extract the encrypted part of the log entry using regex
            match = re.search(r'gAAAAA[^\s]+', line)
            if match:
                encrypted_message = match.group(0)
                # print(f"Encrypted message: {encrypted_message}")  # Debugging statement
                try:
                    # Decrypt the message
                    decrypted_message = cipher_suite.decrypt(encrypted_message.encode()).decode()
                    print(f"Decrypted message: {decrypted_message}")  # Debugging statement
                except Exception as e:
                    # Skip logs that are not encrypted
                    print(f"Skipping non-encrypted log entry: {encrypted_message}")
                    print(f"Error: {e}")
            else:
                print(f"Skipping non-encrypted log entry: {line.strip()}")

# Usage
if __name__ == "__main__":
    # Initialize the cipher with the encryption key
    key = load_encryption_key()
    print(f"Encryption Key: {key}")  # Debugging statement
    cipher_suite = Fernet(key)

    # Path to your encrypted log file
    log_file_path = 'server.log'

    # Decrypt and print each log entry
    decrypt_logs(log_file_path, cipher_suite)