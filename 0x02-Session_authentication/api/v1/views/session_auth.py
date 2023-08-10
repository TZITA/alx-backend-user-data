#!/usr/bin/env python3
"""A view to handle session authentication"""
from flask import request, jsonify, abort
from api.v1.views import app_views
from models.user import User
from os import getenv


@app_views.route('/auth_session/login',
                 methods=['POST'], strict_slashes=False)
def login() -> str:
    """ POST - /api/v1/auth_session/login
    """
    email = request.form.get("email")
    if email is None:
        return jsonify({"error": "email missing"}), 400

    password = request.form.get("password")
    if password is None:
        return jsonify({"error": "password missing"}), 400

    try:
        users = User.search({"email": email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404

    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    for u in users:
        if not u.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

    from api.v1.app import auth

    user = users[0]
    sess_id = auth.create_session(user.id)

    SESSION_NAME = getenv("SESSION_NAME")
    resp = jsonify(user.to_json())
    resp.set_cookie(SESSION_NAME, sess_id)

    return resp


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """ DELETE /auth_session/logout
    """
    from api.v1.app import auth

    delete = auth.destroy_session(request)

    if delete is False:
        abort(404)

    return jsonify({}), 200
