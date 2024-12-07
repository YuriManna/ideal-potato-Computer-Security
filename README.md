# ideal-potato-Computer-Security

To run code:
To install all libraries try running: pip install -r requirements.txt
Then set up the environmental variables by running generate_keys.py and follow the instructions

- to start the flask server run server.py (or from cmd navigate to the directory and run python server.py)
- after the flask server is running you can check it with 127.0.0.1:5000/status in chrome or other browser with https (on postman http won't work)
- you can interact with the server via web interface using 127.0.0.1:5000/register
- to test client run client.py <json file> (in cmd python client.py client_config.json), this should do actions specified in client_config.json

2 options of interaction:
1) CMD
    - after server is running, you can specify users and interactions in client_config.json
    - to perform actions run client.py client_config.json
2) browser
    - after server is running, open your favourite browser and type 127.0.0.1:5000/register. You should see a registration/login page
    - after successful registration/log in you can perform actions, or log out 