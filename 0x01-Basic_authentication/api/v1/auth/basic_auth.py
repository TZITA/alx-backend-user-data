#!/usr/bin/env python3
"""Basic Authorization"""
from api.v1.auth.auth import Auth
import base64


class BasicAuth(Auth):
    """BasicAuth inherits from Auth"""

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """Returns Base64 part of the Authorization header"""
        if authorization_header is None or\
           type(authorization_header) != str or\
           not authorization_header.startswith("Basic "):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """Returns the decoded value of a Base64 string
           base64_authorization_header
        """
        if base64_authorization_header is None or\
           type(base64_authorization_header) != str:
            return None
        try:
            b64_str = base64.b64decode(base64_authorization_header)
            utf_str = b64_str.decode('utf-8')
            return utf_str
        except Exception:
            pass
        return None
