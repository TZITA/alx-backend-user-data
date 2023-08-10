#!/usr/bin/env python3
"""UserSession class"""
from models.base import Base


class UserSession(Base):
    """UserSession inherits from Base"""

    def __init__(self, *args: list, **kwargs: dict):
        """Initialize class"""
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
