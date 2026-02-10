from fastapi import Depends, HTTPException, APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.schemas import ChangePasswordRequest, TokenData, UpdateProfileRequest, UserResponse
from starlette import status
from .auth import get_current_user, bcrypt_context
from  ..models import User, UserRole

class RoleChecker:

    """
    Класс для проверки роли пользователя
    """

    def __init__(self, allowed_roles: list[UserRole]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: TokenData = Depends(get_current_user)):
            

        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="Operation not permitted"
            )
        
        return current_user

router = APIRouter(
    prefix='/user',
    tags=['user']
)

# ========================================
# 1. Получение данных своего профиля
# ========================================
@router.get("/me", response_model=UserResponse)
async def read_user_profile(
    db: AsyncSession = Depends(get_db),
    token_data: TokenData = Depends(get_current_user)
):
    """
    Возвращает из БД все данные о пользователе
    
    :param db: Открытая сессия БД
    :param token_data: Данные из токена 
    """
    result = await db.execute(select(User).where(User.id == token_data.id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found")
        
    return user

# ==========================================
# 2. Изменить данные профиля
# ==========================================
@router.put("/me", response_model=UserResponse)
async def update_user_profile(
    update_data: UpdateProfileRequest,
    db: AsyncSession = Depends(get_db),
    token_data: TokenData = Depends(get_current_user)
) -> User:
    """
    Ручка для изменения данных профиля пользователя
    
    :param update_data: Данные для обновления
    :type update_data: UpdateProfileRequest
    :param db: Открытая сессия БД
    :param token_data: Данные из JWT
    :return: Возращает обновленный профиль
    :rtype: User
    """

    result = await db.execute(select(User).where(User.id == token_data.id))
    user_in_db = result.scalar_one_or_none()
    
    if not user_in_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found"
        )

    if update_data.email != user_in_db.email:
        email_check = await db.execute(select(User).where(User.email == update_data.email))
        if email_check.scalar_one_or_none():
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                                 detail="Email already registered")
        user_in_db.email = update_data.email

    # 3. Обновление полей
    if update_data.first_name is not None:
        user_in_db.first_name = update_data.first_name
    
    if update_data.last_name is not None:
        user_in_db.last_name = update_data.last_name

    db.add(user_in_db)
    await db.commit()
    await db.refresh(user_in_db)
    return user_in_db

# ==========================================
# 3. Изменить пароль
# ==========================================
@router.put("/password", status_code=status.HTTP_200_OK)
async def change_password(
    password_data: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    token_data: TokenData = Depends(get_current_user)
):
    """
    Ручка для смены пароля пользователя

    :param password_data: объект класса содержащий в
    себе старый и новый пароль
    :type password_data: ChangePasswordRequest
    """
 
    result = await db.execute(select(User).where(User.id == token_data.id))
    user_in_db = result.scalar_one_or_none()

    if not user_in_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found")

    if not bcrypt_context.verify(password_data.old_password, 
                                 user_in_db.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Invalid old password")
    
    user_in_db.hashed_password = bcrypt_context.hash(password_data.new_password)
    
    db.add(user_in_db)
    await db.commit()
    
    return {"message": "Password updated successfully"}


# ==========================================
# 4. Удалить аккаунт(Полное удаление)
# ==========================================
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    token_data: TokenData = Depends(get_current_user)
):
    """

    Полное удаление пользователя из БД
    Ручка доступна как админам, так и обычным пользователям,
    обычный пользователь может удалить только свой профиль
    админ может удалить любой профиль пользователя, но не админа

    :param user_id: id пользователя 
    :type user_id: int

    """

    if token_data.id != user_id and token_data.role != "admin":
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                              detail="Not authorized to delete this user")

    result = await db.execute(select(User).where(User.id == user_id))
    user_to_delete = result.scalar_one_or_none()

    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found")

    await db.delete(user_to_delete)
    await db.commit()