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
        try:
            response = session.post(f"{server_url}/action", json=data, headers=headers)
        except requests.exceptions.SSLError as e:
            print(f"SSL Error during action '{action}': {e}")
            return

        if response.status_code == 200:
            try:
                new_value = response.json().get('new_value')
                print(f"Client {client_id}: Action '{action}' performed. New counter value: {new_value}")
            except ValueError:
                print(f"Client {client_id}: Received non-JSON response.")
                print(f"Response Text: {response.text}")
        else:
            try:
                error_message = response.json().get('message', 'No error message provided')
            except ValueError:
                error_message = 'Non-JSON error response'
            print(f"Client {client_id}: Action failed with status code {response.status_code} - {error_message}")
            print(f"Response Text: {response.text}")
            return  # Exit the loop or handle as needed
    
    time.sleep(5) 

    # Log out from the server
    try:
        response = session.get(f"{server_url}/logout", headers=headers)
    except requests.exceptions.SSLError as e:
        print(f"SSL Error during logout: {e}")
        return

    if response.status_code == 200:
        print(f"Client {client_id}: Logged out successfully.")
    else:
        try:
            error_message = response.json().get('message', 'No error message provided')
        except ValueError:
            error_message = 'Non-JSON error response'
        print(f"Client {client_id}: Logout failed with status code {response.status_code} - {error_message}")
        print(f"Response Text: {response.text}")

# Main function
# Usage: python client.py client_config.json
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python client.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    main(config)