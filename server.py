# Server application code

# imports
from datetime import datetime, timedelta
import bcrypt # Secure password hashing library
from flask import Flask, make_response, render_template, request, jsonify, redirect, url_for, session
import threading # Ensures thread-safe operations
import logging # Logging module\
import jwt  # For JSON Web Tokens
from functools import wraps
import re # Regular expressions for input validation
# Form handling and validation
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Optional, ValidationError
# Rate limiting to prevent abuse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Encryption Libraries
from cryptography.fernet import Fernet
import secrets

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

def is_valid_password(password):
    """
    Validates the password string.
    Ensures it meets the security criteria.

    Criteria:
    - Must be at least 8 characters long.
    - Must contain at least one uppercase letter.
    - Must contain at least one lowercase letter.
    - Must contain at least one digit.
    - Must contain at least one special character (@$!%*?&).
    - Can only contain alphanumeric characters and special characters (@$!%*?&).

    Returns:
        True if password is valid, False otherwise.
    """
    pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.match(pattern, password))

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
    
def generate_token(client_id):
    """Generates a JWT token."""
    payload = {
        'client_id': client_id,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token

def token_required(f):
    """Decorator to check for valid token in API requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Token can be passed in the header or cookies
        if 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization')
            token_parts = auth_header.split()
            if len(token_parts) == 2 and token_parts[0] == 'Bearer':
                token = token_parts[1]
                encrypt_and_log(f"Token extracted from Authorization header: {token}", level='debug')
        elif 'token' in request.cookies:
            token = request.cookies.get('token')
            encrypt_and_log(f"Token extracted from cookies: {token}", level='debug')

        if not token:
            encrypt_and_log(f"Token missing in request from IP {request.remote_addr}", level='warning')
            return jsonify({'status': 'error', 'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            client_id = data['client_id']
            encrypt_and_log(f"Token decoded successfully. Client ID: {client_id}", level='debug')
            # Check if client exists
            with lock:
                if client_id not in clients:
                    encrypt_and_log(f"Client ID '{client_id}' from token does not exist.", level='warning')
                    return jsonify({'status': 'error', 'message': 'Invalid token!'}), 401
        except jwt.ExpiredSignatureError:
            encrypt_and_log(f"Expired token used from IP {request.remote_addr}", level='warning')
            return jsonify({'status': 'error', 'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            encrypt_and_log(f"Invalid token used from IP {request.remote_addr}", level='warning')
            return jsonify({'status': 'error', 'message': 'Invalid token!'}), 401
        return f(client_id, *args, **kwargs)
    return decorated


# Token Authentication for Web Routes
def get_client_id_from_token():
    token = None
    # Check Authorization header first
    if 'Authorization' in request.headers:
        auth_header = request.headers.get('Authorization')
        token_parts = auth_header.split()
        if len(token_parts) == 2 and token_parts[0] == 'Bearer':
            token = token_parts[1]
            encrypt_and_log(f"Token extracted from Authorization header: {token}", level='debug')
    # If not found in header, check cookies
    if not token:
        token = request.cookies.get('token')
        if token:
            encrypt_and_log(f"Token extracted from cookies: {token}", level='debug')
    
    if not token:
        encrypt_and_log(f"Token missing in request from IP {request.remote_addr}", level='warning')
        return None
    
    try:
        data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        client_id = data['client_id']
        # Verify client exists
        with lock:
            if client_id not in clients:
                encrypt_and_log(f"Client ID '{client_id}' from token does not exist.", level='warning')
                return None
        return client_id
    except jwt.ExpiredSignatureError:
        encrypt_and_log(f"Expired token used for logout from IP {request.remote_addr}", level='warning')
    except jwt.InvalidTokenError:
        encrypt_and_log(f"Invalid token used for logout from IP {request.remote_addr}", level='warning')
    
    return None

def load_encryption_key():
    with open('log.key', 'rb') as key_file:
        logkey = key_file.read()
    return logkey

def encrypt_and_log(message, level='info'):
    encrypted_message = cipher_suite.encrypt(message.encode()).decode()
    if level == 'info':
        logging.info(encrypted_message)
    elif level == 'warning':
        logging.warning(encrypted_message)
    elif level == 'error':
        logging.error(encrypted_message)
    else:
        logging.debug(encrypted_message)

#------------------------------------------------------------------------------------------------
# Initialization

# Load the log encryption key
logKey = load_encryption_key()
cipher_suite = Fernet(logKey)

# Initialize the Flask application
app = Flask(__name__)

app.secret_key = '3f41d5d0b1633b8c03ded3b3db4410e7'
# Enable CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(filename='server.log', level=logging.DEBUG, format='%(asctime)s %(message)s')

clients = {}  # Keeps track of registered clients, their hashed passwords, personal counters, and the number of active connections
lock = threading.Lock()  # Ensures thread-safe operations

# Rate Limiter
# Rate limiting based on the client's IP address to prevent abuse and brute-force attacks
limiter = Limiter(
    key_func=get_remote_address
)
limiter.init_app(app)

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
        DataRequired(),  # Ensure the field is not empty
        Length(min=8, message='Password must be at least 8 characters long.'),  # Minimum length of 8 characters
        Regexp('(?=.*[A-Z])', message='Password must contain at least one uppercase letter.'),  # At least one uppercase letter
        Regexp('(?=.*[a-z])', message='Password must contain at least one lowercase letter.'),  # At least one lowercase letter
        Regexp('(?=.*\d)', message='Password must contain at least one digit.'),  # At least one digit
        Regexp('(?=.*[@$!%*?&])', message='Password must contain at least one special character (@$!%*?&).'),  # At least one special character
        Regexp('^[A-Za-z\d@$!%*?&]+$', message='Password can only contain alphanumeric characters and special characters (@$!%*?&).')  # Only allowed characters
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

@app.route('/csrf-token', methods=['GET'])
def csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

# Allow users to register/login via the API (cmd json format)
@limiter.limit("5 per minute") # Rate limit to prevent abuse
@csrf.exempt # Disable CSRF protection for this route
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json() # Get the JSON data
    client_id = data.get('id') # Get the client ID
    password = data.get('password') # Get the password
    
    # Validate inputs
    if not is_valid_input(client_id) or not is_valid_password(password):
        encrypt_and_log(f"Invalid input during registration from IP {request.remote_addr}", level='warning')
        return jsonify({'status': 'error', 'message': 'Invalid input'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    with lock:
        # Check if the client is already registered
        if client_id in clients:
            # Authenticate the client
            if not bcrypt.checkpw(password.encode('utf-8'), clients[client_id]['password']):
                encrypt_and_log(f"Failed login attempt for user '{client_id}' from IP {request.remote_addr}", level='warning')
                return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403
            else:
                # Increment the number of connections
                clients[client_id]['connections'] += 1
                encrypt_and_log(f"User '{client_id}' logged in successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}", level='info')
        else:
            # Else register the client
            clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}
            encrypt_and_log(f"User '{client_id}' registered successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}", level='info')

    token = generate_token(client_id)
    return jsonify({'status': 'success', 'message': 'Registered successfully', 'token': token}), 200

# Allow users to register/login via website
@limiter.limit("5 per minute") # Rate limit to prevent abuse
@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegistrationForm()
    message = ''
    if form.validate_on_submit(): # If the form is submitted
        client_id = form.client_id.data
        password = form.password.data

        # Validate inputs
        if not is_valid_input(client_id) or not is_valid_password(password):
            message = 'Invalid input. Only alphanumeric characters,underscores and special characters are allowed, minimum lenght is 8 characters.'
            return render_template('register.html', form=form, message=message)

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        with lock:
            # Check if the client is already registered
            if client_id in clients:
                # Authenticate the client
                if not bcrypt.checkpw(password.encode('utf-8'), clients[client_id]['password']):
                    message = 'Authentication failed.'
                    encrypt_and_log(f"Failed login attempt for user '{client_id}' from IP {request.remote_addr}", level='warning')
                    return render_template('register.html', form=form, message=message)
                else:
                    # Increment the number of connections
                    clients[client_id]['connections'] += 1
                    encrypt_and_log(f"User '{client_id}' logged in successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}", level='info')
                    message = 'Logged in successfully.'
            else:
                # Else register the client
                clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}
                encrypt_and_log(f"User '{client_id}' registered successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}", level='info')
                message = 'Registered successfully.'

        token = generate_token(client_id)
        response = redirect(url_for('perform_action'))
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax')
        return response

    return render_template('register.html', form=form, message=message)

@app.route('/action', methods=['POST'])
@limiter.limit("10 per minute")
@csrf.exempt
@token_required
def action(client_id):
    try:
        data = request.get_json()
        if not data or 'action' not in data:
            encrypt_and_log(f"Action missing in request from client '{client_id}'", level='warning')
            return jsonify({'status': 'error', 'message': 'No action provided'}), 400

        action_cmd = data.get('action')
        encrypt_and_log(f"Client '{client_id}' requested action: {action_cmd}", level='info')

        # Parse and perform the action
        command, amount = parse_action(action_cmd)
        if command:
            with lock:
                client = clients.get(client_id)
                if client is None:
                    encrypt_and_log(f"Client '{client_id}' not found during action processing.", level='error')
                    return jsonify({'status': 'error', 'message': 'Client not found'}), 404
                if command == 'INCREASE':
                    client['counter'] += amount
                elif command == 'DECREASE':
                    client['counter'] -= amount
                encrypt_and_log(f"Client '{client_id}' performed action '{action_cmd}'. New counter value: {client['counter']}", level='info')

                return jsonify({'status': 'success', 'new_value': client['counter']}), 200
        else:
            encrypt_and_log(f"Invalid action format from client '{client_id}': {action_cmd}", level='warning')
            return jsonify({'status': 'error', 'message': 'Invalid action format'}), 400
    except Exception as e:
        encrypt_and_log(f"Exception in /action route for client '{client_id}': {e}", level='error')
        return jsonify({'status': 'error', 'message': 'Server error occurred'}), 500

    

# Allow users to perform actions via the website
@limiter.limit("10 per minute")
@app.route('/perform_action', methods=['GET', 'POST'])
def perform_action():
    client_id = get_client_id_from_token()
    if not client_id:
        return redirect(url_for('register_page'))

    form = ActionForm()
    message = ''
    with lock:
        counter_value = clients[client_id]['counter']

    if form.validate_on_submit():
        if form.submit.data:
            # Action submission
            action_cmd = form.action_cmd.data.strip()
            command, amount = parse_action(action_cmd)
            if command:
                with lock:
                    if command == 'INCREASE':
                        clients[client_id]['counter'] += amount
                    elif command == 'DECREASE':
                        clients[client_id]['counter'] -= amount
                    counter_value = clients[client_id]['counter']
                encrypt_and_log(f"Client '{client_id}' performed action '{action_cmd}'. New counter value: {counter_value}", level='info')
                message = f"Action '{action_cmd}' performed. New counter value: {counter_value}"
            else:
                message = 'Invalid action format.'
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
    client_id = get_client_id_from_token()
    if not client_id:
        encrypt_and_log(f"Unauthorized logout attempt from IP {request.remote_addr}", level='warning')
        return jsonify({'status': 'error', 'message': 'Unauthorized logout attempt.'}), 401

    with lock:
        client = clients.get(client_id)
        if client:
            client['connections'] = 0  # Log out user from all connections
            if client['connections'] <= 0:
                del clients[client_id]  # Delete client data
                encrypt_and_log(f"All sessions for user '{client_id}' have ended. User data deleted.", level='info')
            else:
                encrypt_and_log(f"User '{client_id}' logged out, active connections: {client['connections']}", level='info')
    
    # Clear the token cookie if present
    response = make_response(jsonify({'status': 'success', 'message': 'Logged out successfully.'}), 200)
    response.delete_cookie('token')
    return response

@app.route('/status', methods=['GET'])
@csrf.exempt
def status():
    return render_template('status.html')


# Ensure the server is running over HTTPS
@app.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

if __name__ == '__main__':
    context = ('server.crt', 'server.key')  # SSL certificate and key files
    app.run(host='0.0.0.0', port=5000, ssl_context=context)
