#!/usr/bin/env python3
""" Auth class """
from flask import request
from typing import List, TypeVar


class Auth():
    """A class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Returns a boolean"""
        if path is not None and path[-1] != '/':
            path += '/'
        if path is None or excluded_paths is None or\
                len(excluded_paths) == 0:
            return True
        for p in excluded_paths:
            if p.startswith(path):
                return False
            if p[-2] == "*":
                if path.startswith(p[:-2]):
                    return False
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """Returns a str"""
        if request is None:
            return None
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
        return auth_header

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns a user"""
        return None
