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

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """Returns the user email and password
           from the Base64 decoded value.
        """
        short_var_name = decoded_base64_authorization_header
        if short_var_name is None or\
           type(short_var_name) != str or\
           ":" not in short_var_name:
            return (None, None)

        colon = short_var_name.index(':')
        return (short_var_name[0:colon], short_var_name[colon + 1:])
