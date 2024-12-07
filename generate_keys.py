import os
from cryptography.fernet import Fernet

def generate_keys():
    """
    Generate a Flask secret key and a log encryption key.
    """
    # Generate a random Flask secret key
    secret_key = os.urandom(24).hex()

    # Generate a secure encryption key for logs
    log_key = Fernet.generate_key().decode()

    return secret_key, log_key

def save_to_file(secret_key, log_key):
    """
    Save the keys to a file with instructions.
    """
    with open("keys.txt", "w") as file:
        file.write("# Generated Keys\n")
        file.write("SECRET_KEY='{}'\n".format(secret_key))
        file.write("LOG_KEY='{}'\n".format(log_key))
        file.write("\n")
        file.write("## Instructions to Set Environment Variables ##\n")
        file.write("For Linux/Mac:\n")
        file.write("export SECRET_KEY='{}'\n".format(secret_key))
        file.write("export LOG_KEY='{}'\n".format(log_key))
        file.write("\n")
        file.write("For Windows (CMD):\n")
        file.write("set SECRET_KEY='{}'\n".format(secret_key))
        file.write("set LOG_KEY='{}'\n".format(log_key))
        file.write("\n")
        file.write("For Windows (Powershell - VS Terminal):\n")
        file.write("$env:SECRET_KEY='{}'\n".format(secret_key))
        file.write("$env:LOG_KEY='{}'\n".format(log_key))
        file.write("\n")
        file.write("Add these lines to your environment configuration if needed.\n")

if __name__ == "__main__":
    # Generate the keys
    secret_key, log_key = generate_keys()

    # Save keys to a file
    save_to_file(secret_key, log_key)

    print("Keys generated and saved to 'keys.txt'.")
    print("Follow the instructions in the file to set them as environment variables.")