# Server application code

# imports
import bcrypt # Secure password hashing library
from flask import Flask, render_template, request, jsonify, redirect, url_for, session # Web framework and session management
import threading # Ensures thread-safe operations
import logging # Logging module
import time
import secrets
import re # Regular expressions for input validation
# Form handling and validation
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Optional, ValidationError
# Rate limiting to prevent abuse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# app.secret_key = secrets.token_hex(16) # Generate a random secret key 
app.secret_key = '3f41d5d0b1633b8c03ded3b3db4410e7' #TODO: generate one and store safely
# print(app.secret_key)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO, format='%(asctime)s %(message)s')

clients = {}  # Keeps track of registered clients, their hashed passwords, personal counters, and the number of active connections
lock = threading.Lock()  # Ensures thread-safe operations

# Rate Limiter
# Rate limiting based on the client's IP address to prevent abuse and brute-force attacks
limiter = Limiter(
    key_func=get_remote_address
)
limiter.init_app(app)

#------------------------------------------------------------------------------------------------
# Functions

def is_valid_input(input_str):
    """
    Validates the input string.
    Prevents injection attacks and ensures expected input format.

    Criteria:
    - Must be at least 3 characters long.
    - Can contain alphanumeric characters and underscores only.
    - No spaces or special characters allowed.

    Returns:
        True if input is valid, False otherwise.
    """
    pattern = r'^\w{3,}$'
    return bool(re.match(pattern, input_str))

def parse_action(action_str):
    """
    Parses the action command.
    Ensures only valid action commands are processed.

    Expected format:
    - 'INCREASE [AMOUNT]'
    - 'DECREASE [AMOUNT]'

    AMOUNT must be a positive integer.

    Returns:
        Tuple (command, amount) if valid, (None, None) otherwise.
    """
    pattern = r'^(INCREASE|DECREASE)\s+(\d+)$'
    match = re.match(pattern, action_str.strip(), re.IGNORECASE)
    if match:
        command = match.group(1).upper()
        amount = int(match.group(2))
        return command, amount
    else:
        return None, None
    
#------------------------------------------------------------------------------------------------
# Forms

class RegistrationForm(FlaskForm):
    # Usename input validation
    client_id = StringField('Username', validators=[
        DataRequired(), # Ensure the field is not empty
        Length(min=3), # Minimum length of 3 characters
        Regexp('^\w{3,}$', message='Only alphanumeric characters and underscores are allowed.')
    ])
    # Password input validation
    password = PasswordField('Password', validators=[
        DataRequired(), # Ensure the field is not empty
        Length(min=3), # Minimum length of 3 characters
        Regexp('^\w{3,}$', message='Only alphanumeric characters and underscores are allowed.')
    ])
    submit = SubmitField('Register')

class ActionForm(FlaskForm):
    action_cmd = StringField('Action') # Input for the action command
    submit = SubmitField('Submit') # Button to submit the action
    logout = SubmitField('Logout') # Button to logout

    def validate_action_cmd(self, field):
        # validate the action command only when the Submit button is pressed
        if self.submit.data:
            #  Only when the Submit button is pressed
            if not field.data or not field.data.strip():
                raise ValidationError('This field is required.')
            else:
                # Use a regular expression to validate the action command
                pattern = re.compile(r'^(INCREASE|DECREASE) \d+$', re.IGNORECASE)
                if not pattern.match(field.data.strip()):
                    raise ValidationError('Invalid action format.')
        # No validation when Logout is pressed


#------------------------------------------------------------------------------------------------
# Routes

# Allow users to register/login via the API (cmd json format)
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() # Get the JSON data
    client_id = data.get('id') # Get the client ID
    password = data.get('password') # Get the password
    
    # Validate inputs
    if not is_valid_input(client_id) or not is_valid_input(password):
        return jsonify({'status': 'error', 'message': 'Invalid input'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    with lock:
        # Check if the client is already registered
        if client_id in clients:
            # Authenticate the client
            if not bcrypt.checkpw(password.encode('utf-8'), clients[client_id]['password']):
                return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403
            else:
                # Increment the number of connections
                clients[client_id]['connections'] += 1
        else:
            # Else register the client
            clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}

    return jsonify({'status': 'success', 'message': 'Registered successfully'}), 200

# Allow users to register/login via website
@limiter.limit("5 per minute") # Rate limit to prevent abuse
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm()
    if form.validate_on_submit(): # If the form is submitted
        client_id = form.client_id.data
        password = form.password.data

        # Validate inputs
        if not is_valid_input(client_id) or not is_valid_input(password):
            message = 'Invalid input. Only alphanumeric characters and underscores are allowed, minimum length 3.'
            return render_template('register.html', form=form, message=message)

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        with lock:
            # Check if the client is already registered
            if client_id in clients:
                # Authenticate the client
                if not bcrypt.checkpw(password.encode('utf-8'), clients[client_id]['password']):
                    message = 'Authentication failed.'
                    return render_template('register.html', form=form, message=message)
                else:
                    # Increment the number of connections
                    clients[client_id]['connections'] += 1
                    message = 'Logged in successfully.'
            else:
                # Else register the client
                clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}
                message = 'Registered successfully.'

        # Store the client ID and message in the session
        session['client_id'] = client_id
        session['message'] = message
        return redirect(url_for('perform_action'))

    return render_template('register.html', form=form)

# Allow users to perform actions via the API (cmd json format)
@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    client_id = data.get('id')
    password = data.get('password')
    action_cmd = data.get('action')

    with lock:
        # Authenticate client
        client = clients.get(client_id)
        if not client or not bcrypt.checkpw(password.encode('utf-8'), client['password']):
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403

        # Parse and perform the action
        command, amount = parse_action(action_cmd)
        if command:
            if command == 'INCREASE':
                client['counter'] += amount
            elif command == 'DECREASE':
                client['counter'] -= amount

            # Log the action
            logging.info(f"Client {client_id}: {action_cmd}. New counter value: {client['counter']}")

            return jsonify({'status': 'success', 'new_value': client['counter']}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action format'}), 400

# Allow users to perform actions via the website
@app.route('/perform_action', methods=['GET', 'POST'])
def perform_action():
    # Check if the client is registered
    client_id = session.get('client_id')
    if not client_id or client_id not in clients:
        return redirect(url_for('register_page'))

    form = ActionForm()
    message = ''
    counter_value = clients[client_id]['counter']

    if form.validate_on_submit():
        if form.submit.data:
            # Action submission
            action_cmd = form.action_cmd.data.strip()
            command, amount = parse_action(action_cmd)
            with lock:
                if command == 'INCREASE':
                    clients[client_id]['counter'] += amount
                elif command == 'DECREASE':
                    clients[client_id]['counter'] -= amount
                logging.info(f"Client {client_id}: {action_cmd}. New counter value: {clients[client_id]['counter']}")
                counter_value = clients[client_id]['counter']
                message = f"Action '{action_cmd}' performed. New counter value: {counter_value}"
        elif form.logout.data:
            # Logout button clicked
            return redirect(url_for('logout'))
    else:
        if form.submit.data:
            message = 'Please correct the errors below.'

    return render_template('actions.html', form=form, message=message, counter_value=counter_value)

# Log out the user and clear the session
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    client_id = session.get('client_id')
    if not client_id:
        return redirect(url_for('register_page'))

    with lock:
        client = clients.get(client_id)
        if client:
            client['connections'] -= 1 # Decrement the number of connections
            if client['connections'] <= 0: # If no active connections delete the client
                del clients[client_id]
    session.clear() # Clear the session
    return redirect(url_for('register_page'))


@app.route('/status', methods=['GET'])
def status():
    client_id = session.get('client_id')
    message = session.get('message')
    if client_id and client_id in clients:
        return render_template('status.html', client_id=client_id, message=message)
    else:
        return render_template('register.html', message=message)

# Ensure the server is running over HTTPS
@app.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

if __name__ == '__main__':
    context = ('server.crt', 'server.key')  # SSL certificate and key files
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
