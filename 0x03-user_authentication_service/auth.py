#!/usr/bin/env python3
"""auth module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union


def _hash_password(password: str) -> bytes:
    """Returns hashed value of a string password"""
    encoded = password.encode('UTF-8')
    return bcrypt.hashpw(encoded, bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate UUID"""
    return str(uuid4())


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

    def create_session(self, email: str) -> str:
        """Creates a session"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Returns user based on session id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a session"""
        if user_id:
            self._db.update_user(user_id, session_id=None)
            return
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a UUID"""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError()

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            new_hased_password = _hash_password(password)
            self._db.update_user(
                    user.id,
                    hashed_password=new_hased_password,
                    reset_token=None)
        except NoResultFound:
            raise ValueError()
