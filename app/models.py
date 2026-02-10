"""
Docstring for app.models
"""
import enum
from sqlalchemy import Column, Integer, String, Boolean, Enum
from sqlalchemy.orm  import declarative_base


Base = declarative_base()

class UserRole(str, enum.Enum):

    """
    Класс, описывающий все возможные роли пользователя
    """

    super_admin = 'super_admin'
    admin = 'admin'
    user = 'user'


class User(Base):

    """
    Класс, описывающий структуру таблицы пользователей в БД
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String, nullable=False)
    role  = Column(Enum(UserRole), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    