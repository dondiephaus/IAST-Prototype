from flask import Flask

app = Flask(__name__)

# prevent circular imports
from app import routes