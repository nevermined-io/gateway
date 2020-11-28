import os
import logging
import sys
from authlib.integrations.flask_client import OAuth

from flask import Flask
from flask_cors import CORS



app = Flask(__name__)
CORS(app)



if 'CONFIG_FILE' in os.environ and os.environ['CONFIG_FILE']:
    app.config['CONFIG_FILE'] = os.environ['CONFIG_FILE']
else:
    app.config['CONFIG_FILE'] = 'config.ini'
