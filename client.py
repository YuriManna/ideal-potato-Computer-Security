# Client application code.

# imports
import requests
import json
import time
import sys

# Load configuration
def load_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

def main(config):
    server_ip = config['server']['ip']
    server_port = config['server']['port']
    server_url = f"https://{server_ip}:{server_port}"

    client_id = config['id']
    password = config['password']
    delay = int(config['actions']['delay'])
    steps = config['actions']['steps']

    # TODO: Research security here
    # Create a session with SSL verification disabled for self-signed certs
    session = requests.Session()
    #session.verify = False  # Not recommended for production environments
    session.verify = 'server.crt'  # Path to the server's certificate

    # Authenticate with the server
    data = {'id': client_id, 'password': password}
    try:
        response = session.post(f"{server_url}/api/register", json=data)
    except requests.exceptions.SSLError as e:
        print(f"SSL Error: {e}")
        return

    if response.status_code == 200:
        print(f"Client {client_id}: Authenticated successfully.")
        token = response.json()['token']
    else:
        print(f"Client {client_id}: Authentication failed - {response.json()['message']}")
        return

    headers = {'Authorization': f'Bearer {token}'}

    # Perform actions with delays
    for action in steps:
        time.sleep(delay)
        data = {'action': action}
        response = session.post(f"{server_url}/action", json=data, headers=headers)
        if response.status_code == 200:
            new_value = response.json()['new_value']
            print(f"Client {client_id}: Action '{action}' performed. New counter value: {new_value}")
        else:
            print(f"Client {client_id}: Action failed - {response.json()['message']}")

    time.sleep(50) 

    # Log out from the server
    response = session.get(f"{server_url}/logout", headers=headers)
    if response.status_code == 200:
        print(f"Client {client_id}: Logged out successfully.")
    else:
        print(f"Client {client_id}: Logout failed - {response.text}")  # Print raw response

# Main function
# Usage: python client.py client_config.json
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python client.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    main(config)