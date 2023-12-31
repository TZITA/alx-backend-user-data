#!/usr/bin/env python3
"""DB Module"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from user import Base
from user import User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Returns a User object"""
        user_to_add = User(email=email, hashed_password=hashed_password)
        self._session.add(user_to_add)
        self._session.commit()
        return user_to_add

    def find_user_by(self, **kwargs) -> User:
        """Returns the first row found in the users table"""
        if not kwargs:
            raise InvalidRequestError

        columns = User.__table__.columns.keys()
        for k in kwargs.keys():
            if k not in columns:
                raise InvalidRequestError

        user = self._session.query(User).filter_by(**kwargs).first()

        if user is None:
            raise NoResultFound

        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Returns None"""
        user = self.find_user_by(id=user_id)

        columns = User.__table__.columns.keys()
        for k in kwargs.keys():
            if k not in columns:
                raise ValueError

        for k, v in kwargs.items():
            setattr(user, k, v)

        self._session.commit()
