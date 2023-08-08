#!/usr/bin/env python3
""" Auth class """
from flask import request
from typing import List, TypeVar


class Auth():
    """A class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Returns a boolean"""
        return False

    def authorization_header(self, request=None) -> str:
        """Returns a str"""
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Returns a user"""
        return None
