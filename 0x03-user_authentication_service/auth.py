#!/usr/bin/env python3
"""auth module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Returns hashed value of a string password"""
    encoded = password.encode('UTF-8')
    return bcrypt.hashpw(encoded, bcrypt.gensalt())


class Auth:
    """Auth class"""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user"""
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_pswd = _hash_password(password)
            new_user = self._db.add_user(email, hashed_pswd)
            return new_user
        raise ValueError(f'User {email} already exists')

    def valid_login(self, email: str, password: str) -> bool:
        """Validates a user by its email and password"""
        try:
            user = self._db.find_user_by(email=email)
            encoded = password.encode('utf-8')
            if bcrypt.checkpw(encoded, user.hashed_password):
                return True
            return False
        except NoResultFound:
            return False
