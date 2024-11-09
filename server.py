# Server application code

# imports
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import threading
import logging
import time
import secrets

app = Flask(__name__)
# app.secret_key = secrets.token_hex(16) # Generate a random secret key 
app.secret_key = '3f41d5d0b1633b8c03ded3b3db4410e7' #TODO: generate one and store safely
# print(app.secret_key)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s %(message)s')

clients = {}  # Stores client data:
lock = threading.Lock()  # Ensures thread-safe operations

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        client_id = request.form.get('id')
        password = request.form.get('password')

        with lock:
            if client_id in clients:
                if clients[client_id]['password'] != password:
                    message = 'Incorrect password.'
                    return render_template('register.html', message=message)
                else:
                    # Increment connection count
                    clients[client_id]['connections'] += 1
                    message = 'Existing client logged in successfully.'
                    time.sleep(1)
                    session['client_id'] = client_id
                    session['message'] = message
                    return redirect(url_for('status'))
            else:
                # Register new client
                clients[client_id] = {'password': password, 'counter': 0, 'connections': 1}
                message = 'New client registered successfully.'
                time.sleep(1)
                session['client_id'] = client_id
                session['message'] = message
                return redirect(url_for('status'))
    else:
        return render_template('register.html')

@app.route('/api/register', methods=['POST'])
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
        if not client:
            return jsonify({'status': 'error', 'message': 'Client not registered'}), 403
        elif client['password'] != password:
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
    client_id = session.get('client_id')
    message = session.get('message')
    if client_id and client_id in clients:
        return render_template('status.html', client_id=client_id, message=message)
    else:
        return render_template('register.html', message=message)


if __name__ == '__main__':
    context = ('server.crt', 'server.key')  # SSL certificate and key files
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
