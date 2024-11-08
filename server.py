# Server application code

# imports
from flask import Flask, render_template, request, jsonify
import threading
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s %(message)s')

clients = {}  # Stores client data:
lock = threading.Lock()  # Ensures thread-safe operations

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    client_id = data.get('id')
    password = data.get('password')
    
    with lock:
        # Check if client is already registered
        if client_id in clients:
            if clients[client_id]['password'] != password:
                return jsonify({'status': 'error', 'message': 'Incorrect password'}), 403
            else:
                # Increment connection count
                clients[client_id]['connections'] += 1
        else:
            # Register new client
            clients[client_id] = {'password': password, 'counter': 0, 'connections': 1}
    
    return jsonify({'status': 'success', 'message': 'Registered successfully'}), 200

@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    client_id = data.get('id')
    password = data.get('password')
    action = data.get('action')

    with lock:
        # Authenticate client
        client = clients.get(client_id)
        if not client or client['password'] != password:
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403

        # Parse and perform the action
        parts = action.split()
        command = parts[0].upper()
        if command in ['INCREASE', 'DECREASE'] and len(parts) == 2 and parts[1].isdigit():
            amount = int(parts[1])
            if command == 'INCREASE':
                client['counter'] += amount
            else:
                client['counter'] -= amount

            # Log the action
            logging.info(f"Client {client_id}: {action}. New counter value: {client['counter']}")

            return jsonify({'status': 'success', 'new_value': client['counter']}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action format'}), 400

@app.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    client_id = data.get('id')
    password = data.get('password')

    with lock:
        # Authenticate client
        client = clients.get(client_id)
        if not client or client['password'] != password:
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403

        # Decrement connections
        client['connections'] -= 1
        if client['connections'] <= 0:
            # Remove client data
            del clients[client_id]
    
    return jsonify({'status': 'success', 'message': 'Logged out successfully'}), 200

@app.route('/status', methods=['GET'])
def status():
    return render_template('status.html')

if __name__ == '__main__':
    context = ('server.crt', 'server.key')  # SSL certificate and key files
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
