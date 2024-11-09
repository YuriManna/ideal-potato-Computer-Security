# ideal-potato-Computer-Security

TODO:
Testing and Verification
- Server Logs: Check server.log to verify that actions are being logged correctly, implement different logging levels (DEBUG, INFO, WARNING, ERROR)
- Error Handling: Test scenarios like incorrect passwords, invalid actions, and multiple logins.
- Password Storage: Passwords are stored in plain text in this example. For enhanced security, consider hashing passwords using a secure algorithm!!!
- Input validation
- Implement Certificate Authority
- Research security vulnerability in the whole code


To run code:
- to start the flask server run server.py (or from cmd navigate to the directory and run python server.py)
- after the flask server is running you can check it with 127.0.0.1:5000/status in chrome or other browser (The register page should load)
- to test client run client.py <client_config.json> (in cmd python client.py), this should do actions specified in client_comfig.json