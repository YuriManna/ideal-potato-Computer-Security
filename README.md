# ideal-potato-Computer-Security

TODO:
Testing and Verification
- Server Logs: Check server.log to verify that actions are being logged correctly, implement different logging levels (DEBUG, INFO, WARNING, ERROR)
- Implement Certificate Authority
- Research security vulnerability in the whole code
- web success message after authentification/log out


To run code:
- to start the flask server run server.py (or from cmd navigate to the directory and run python server.py)
- after the flask server is running you can check it with 127.0.0.1:5000/status in chrome or other browser (The register page should load)
- to test client run client.py client_config.json (in cmd python client.py client_config.json), this should do actions specified in client_comfig.json

2 options of interaction:
1) CMD
    - after server is running, you can specify users and interactions in client_config.json
    - to perform actions run client.py client_config.json
2) browser
    - after server is running, open your favourite browser and type 127.0.0.1:5000/register. You should see a registration/login page
    - after successful registration/log in you can perform actions, or log out 