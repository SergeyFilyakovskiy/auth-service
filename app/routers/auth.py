"""
Docstring for app.routers.auth

Authenfication router 
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from starlette import status
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import timedelta, timezone, datetime
from typing import Annotated
from ..config import SECRET_KEY, ALGORITHM
from ..database import db_dependency, get_db
from ..schemas import UserSchema, TokenData
from ..models import User, UserRole


router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

bcrypt_context = CryptContext(
    schemes=['bcrypt'],
    deprecated = "auto"
)

oauth2_brearer = OAuth2PasswordBearer(
    tokenUrl= 'auth/token'
)

class CreteUserRequest(BaseModel):
    """
    Docstring for CreteUserRequest
    """
    first_name: str = Field(min_length=2, max_length=30)
    last_name: str = Field(min_length=2, max_length=30)
    email: EmailStr 
    password: str = Field(min_length=3, max_length=30)

class Token(BaseModel):
    """
    Docstring for Token
    """
    access_token: str
    token_type: str



async def authenticate_user(
        email: str,
        password: str,
        db : AsyncSession = Depends(get_db)
) -> UserSchema | bool:

    """
    Выполняет поиск пользователя и проверку пароля
     
    :param email: Email пользователя
    :param password: Пароль пользователя в сыром виде
    :param db: открытая сессия БД
    """

    stmt = select(User).where(User.email == email)
    result = await db.execute(statement=stmt)
    user = result.scalar_one_or_none()
    if user is None:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user



def crate_access_token (
        email: str,
        user_id: int, 
        role: str,
        expires_delta: timedelta
)-> str:

    """
    Создает JWT токен
    
    :param email: Email пользователя
    :param user_id: ID пользователя в БД
    :param role: роль пользователя
    :param expires_delta: время жизни токена
    """

    expires = datetime.now(timezone.utc) + expires_delta
    encode = {'sub': email, 'id': user_id, 'role': role, 'exp': expires}
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)



@router.post("/", status_code=status.HTTP_201_CREATED) 
async def create_user (
    db: db_dependency,
    create_user_request: CreteUserRequest
) -> None:
    """
    Создает нового пользователя в БД
    
    :param db: открытая сессия БД
    :param create_user_request: Запрос оформленный согласно схеме CreteUserRequest
        прошедший валидацию
    """
    new_user = User(
        email = create_user_request.email,
        first_name = create_user_request.first_name,
        last_name = create_user_request.last_name,
        role = 'user',
        hashed_password = bcrypt_context.hash(create_user_request.password)
    )

    db.add(new_user)

    try:
        await db.commit()

    except IntegrityError:
        print("User with this email already exists")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists")


async def get_current_user(token: Annotated[str, Depends(oauth2_brearer)])-> TokenData:
    """
    Достает из  JWT данные
    
    :type token: Annotated[str, Depends(oauth2_brearer)]
    :rtype: TokenData
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get('sub')
        user_id = payload.get('id')
        user_role = payload.get('role')

        if user_email is None or user_id is None or user_role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail= "Could not validate user."
                )
        return TokenData(id=user_id, email= user_email, role=user_role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Could not validate user."
            )
    
@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm,Depends()],
    db: db_dependency    
):
    user = await authenticate_user(
        form_data.username,
        form_data.password,
        db
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Could not validate user."
        )
    token = crate_access_token(
        user.email,
        user.id,
        user.role,
        timedelta(hours=1)
    )
    return{'access_token':token, 'token_type': 'bearer'}