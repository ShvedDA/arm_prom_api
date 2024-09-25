from app.database import Base
from sqlalchemy import Column, Integer, String, Boolean


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, nullable=False)
    username = Column(String(30), nullable=False, unique=True)
    fullname = Column(String(60), nullable=False)
    email = Column(String(30), nullable=False)
    hashed_password = Column(String, nullable=False)
    admin = Column(Boolean, nullable=False, default=False)


class Devices(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True, nullable=False)
    type = Column(String(60), nullable=False)
    uid = Column(String, nullable=False, unique=True)
    activated = Column(Boolean, nullable=True, default=False)
    date_of_activation = Column(String, nullable=True)
    description = Column(String(60), nullable=True)
    user = Column(String(30), nullable=False)
