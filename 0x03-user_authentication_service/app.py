#!/usr/bin/env python3
"""a simple flask app"""
from flask import Flask, jsonify
from auth import Auth


app = Flask(__name__)
AUTH = Auth()


@app.route('/', strict_slashes=False)
def index() -> str:
    """Returns a json message"""
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")