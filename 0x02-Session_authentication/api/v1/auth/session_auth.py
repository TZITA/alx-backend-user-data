#!/usr/bin/env python3
"""Session Authentication"""
from api.v1.auth.auth import Auth
import uuid
from models.user import User


class SessionAuth(Auth):
    """Session Auth class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """creates a Session ID for a user_id"""
        if user_id is None or type(user_id) != str:
            return None
        session_id = str(uuid.uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns a User ID based on a Session ID"""
        if session_id is None or type(session_id) != str:
            return None

        try:
            u_id = SessionAuth.user_id_by_session_id[session_id]
            return u_id
        except Exception:
            return None

    def current_user(self, request=None):
        """Returns a User instance based on a cookie value"""
        sess_id = self.session_cookie(request)

        user_id = self.user_id_for_session_id(sess_id)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """deletes the user session / logout"""
        if request is None:
            return False

        sess_id = self.session_cookie(request)
        if request.cookies.get(sess_id) is None:
            return False

        user_id = self.user_id_for_session_id(sess_id)
        if user_id is None:
            return False

        try:
            del self.user_id_by_session_id[sess_id]
        except Exception:
            pass
        return True
