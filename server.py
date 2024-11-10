# Server application code

# imports
from datetime import datetime, timedelta
import bcrypt # Secure password hashing library
from flask import Flask, make_response, render_template, request, jsonify, redirect, url_for, session # Web framework and session management
import threading # Ensures thread-safe operations
import logging # Logging module\
import jwt  # For JSON Web Tokens
from functools import wraps
import secrets
import re # Regular expressions for input validation
# Form handling and validation
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp, Optional, ValidationError
# Rate limiting to prevent abuse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
# app.secret_key = secrets.token_hex(16) # Generate a random secret key 
app.secret_key = '3f41d5d0b1633b8c03ded3b3db4410e7' #TODO: generate one and store safely
# print(app.secret_key)

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
                logging.debug(f"Token extracted from Authorization header: {token}")
        elif 'token' in request.cookies:
            token = request.cookies.get('token')
            logging.debug(f"Token extracted from cookies: {token}")

        if not token:
            logging.warning(f"Token missing in request from IP {request.remote_addr}")
            return jsonify({'status': 'error', 'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            client_id = data['client_id']
            logging.debug(f"Token decoded successfully. Client ID: {client_id}")
            # Check if client exists
            with lock:
                if client_id not in clients:
                    logging.warning(f"Client ID '{client_id}' from token does not exist.")
                    return jsonify({'status': 'error', 'message': 'Invalid token!'}), 401
        except jwt.ExpiredSignatureError:
            logging.warning(f"Expired token used from IP {request.remote_addr}")
            return jsonify({'status': 'error', 'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            logging.warning(f"Invalid token used from IP {request.remote_addr}")
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
            logging.debug("Token extracted from Authorization header.")
    # If not found in header, check cookies
    if not token:
        token = request.cookies.get('token')
        if token:
            logging.debug("Token extracted from cookies.")
    
    if not token:
        logging.warning(f"Token missing in logout request from IP {request.remote_addr}")
        return None
    
    try:
        data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        client_id = data['client_id']
        # Verify client exists
        with lock:
            if client_id not in clients:
                logging.warning(f"Client ID '{client_id}' from token does not exist.")
                return None
        return client_id
    except jwt.ExpiredSignatureError:
        logging.warning(f"Expired token used for logout from IP {request.remote_addr}")
    except jwt.InvalidTokenError:
        logging.warning(f"Invalid token used for logout from IP {request.remote_addr}")
    
    return None

    
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
    if not is_valid_input(client_id) or not is_valid_input(password):
        logging.warning(f"Invalid input during registration from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Invalid input'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    with lock:
        # Check if the client is already registered
        if client_id in clients:
            # Authenticate the client
            if not bcrypt.checkpw(password.encode('utf-8'), clients[client_id]['password']):
                logging.warning(f"Failed login attempt for user '{client_id}' from IP {request.remote_addr}")
                return jsonify({'status': 'error', 'message': 'Authentication failed'}), 403
            else:
                # Increment the number of connections
                clients[client_id]['connections'] += 1
                logging.info(f"User '{client_id}' logged in successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}")
        else:
            # Else register the client
            clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}
            logging.info(f"User '{client_id}' registered successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}")

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
                    logging.warning(f"Failed login attempt for user '{client_id}' from IP {request.remote_addr}")
                    return render_template('register.html', form=form, message=message)
                else:
                    # Increment the number of connections
                    clients[client_id]['connections'] += 1
                    logging.info(f"User '{client_id}' logged in successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}")
                    message = 'Logged in successfully.'
            else:
                # Else register the client
                clients[client_id] = {'password': hashed_password, 'counter': 0, 'connections': 1}
                logging.info(f"User '{client_id}' registered successfully from IP {request.remote_addr}, active connections: {clients[client_id]['connections']}")
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
            logging.warning(f"Action missing in request from client '{client_id}'")
            return jsonify({'status': 'error', 'message': 'No action provided'}), 400

        action_cmd = data.get('action')
        logging.debug(f"Client '{client_id}' requested action: {action_cmd}")

        # Parse and perform the action
        command, amount = parse_action(action_cmd)
        if command:
            with lock:
                client = clients.get(client_id)
                if client is None:
                    logging.error(f"Client '{client_id}' not found during action processing.")
                    return jsonify({'status': 'error', 'message': 'Client not found'}), 404
                if command == 'INCREASE':
                    client['counter'] += amount
                elif command == 'DECREASE':
                    client['counter'] -= amount

                logging.info(f"Client '{client_id}' performed action '{action_cmd}'. New counter value: {client['counter']}")

                return jsonify({'status': 'success', 'new_value': client['counter']}), 200
        else:
            logging.warning(f"Invalid action format from client '{client_id}': {action_cmd}")
            return jsonify({'status': 'error', 'message': 'Invalid action format'}), 400
    except Exception as e:
        logging.error(f"Exception in /action route for client '{client_id}': {e}")
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

                logging.info(f"Client '{client_id}' performed action '{action_cmd}'. New counter value: {counter_value}")
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
        logging.warning(f"Unauthorized logout attempt from IP {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'Unauthorized logout attempt.'}), 401

    with lock:
        client = clients.get(client_id)
        if client:
            client['connections'] = 0  # Log out user from all connections
            if client['connections'] <= 0:
                del clients[client_id]  # Delete client data
                logging.info(f"All sessions for user '{client_id}' have ended. User data deleted.")
            else:
                logging.info(f"User '{client_id}' logged out, active connections: {client['connections']}")
    
    # Clear the token cookie if present
    response = make_response(jsonify({'status': 'success', 'message': 'Logged out successfully.'}), 200)
    response.delete_cookie('token')
    return response


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
