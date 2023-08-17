#!/usr/bin/env python3
"""auth module"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Returns hashed value of a string password"""
    encoded = password.encode('UTF-8')
    return bcrypt.hashpw(encoded, bcrypt.gensalt())
