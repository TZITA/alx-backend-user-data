#!/usr/bin/env python3
"""SessionExpAuth class"""
from api.v1.auth.session_auth import SessionAuth
from os import getenv
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """SessionExpAuth class"""

    def __init__(self):
        """Initialize instance of SessionExpAuth"""
        try:
            self.session_duration = int(getenv('SESSION_DURATION', 0))
        except ValueError:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Create a Session ID"""
        sess_id = super().create_session(user_id)
        if sess_id is None:
            return None

        SessionExpAuth.user_id_by_session_id[sess_id] = {
            'user_id': user_id,
            'created_at': datetime.now()
        }

        return sess_id

    def user_id_for_session_id(self, session_id=None):
        """Return user ID associated with session ID"""
        if session_id is None:
            return None

        session_dict = SessionExpAuth.user_id_by_session_id.get(
            session_id, None)
        if session_dict is None:
            return None
        if 'created_at' not in session_dict:
            return None

        if self.session_duration <= 0:
            return session_dict.get('user_id')

        creation_time = session_dict.get('created_at')

        session_length = timedelta(seconds=self.session_duration)

        expiry_time = creation_time + session_length

        if expiry_time < datetime.now():
            return None
        return session_dict.get('user_id')
