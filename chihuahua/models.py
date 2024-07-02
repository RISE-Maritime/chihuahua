"""SQLAlchemy ORM models"""

from sqlalchemy import Column, BigInteger, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from databases.backends.postgres import Record

Base = declarative_base()


class User(Base):  # pylint: disable=missing-class-docstring,too-few-public-methods
    __tablename__ = "users"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    username = Column(String(255), index=True, nullable=False, unique=True)
    firstname = Column(String(100), index=True, nullable=False)
    lastname = Column(String(100), index=True, nullable=False)
    email = Column(String(100), index=True, nullable=False)
    admin = Column(Boolean(), nullable=False)
    hashed_password = Column(String(255))
    token = Column(String(255))

    @classmethod
    def from_record(cls, record: Record):
        """Create a User instance from a asyncpg record

        Args:
            record (Record): AsyncPG record

        Returns:
            User: User instance
        """
        return cls(**dict(record))

    def to_dict(self):
        """Transform to dictionary"""
        dictionary = {}
        for column in self.__table__.columns:
            dictionary[column.name] = getattr(self, column.name)
        return dictionary


users = User.__table__
