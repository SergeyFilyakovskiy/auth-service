from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm  import declarative_base

Base = declarative_base()

class User(Base):
    """
    Docstring for User
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String, nullable=False)
    role  = Column()
    is_active = Column(Boolean, nullable=False)
    