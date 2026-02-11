from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from starlette import status
from sqlalchemy.ext.asyncio import AsyncSession

from .user import RoleChecker
from app.database import get_db
from app.models import User
from app.schemas import TokenData


router = APIRouter(
    prefix='/admin',
    tags=['admin']
)

admin_only = RoleChecker(["admin", "super_admin"])


@router.get('/', status_code= status.HTTP_200_OK)
async def get_all_users(
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(admin_only)
):
    """

    Возвращает из БД список всех зарегистрированных
    пользователей
    
    """
    
    result = await db.execute(select(User))
    users = result.mappings().all()
    return users

@router.get('/{user_id}', status_code=status.HTTP_200_OK)
async def get_user(
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(admin_only)
):
    
    """

    Возвращает данные о пользователе по его ID

    :param current_user: Проверка роли админ/супер-админ

    """

# ==========================================
# Удалить аккаунт(Полное удаление)
# ==========================================
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(admin_only)
):
    """

    Полное удаление пользователя из БД. 
    Ручка доступна админам,
    админ может удалить любой профиль пользователя, но не админа

    :param user_id: id пользователя 
    :type user_id: int

    """

    result = await db.execute(select(User).where(User.id == user_id))
    user_to_delete = result.scalar_one_or_none()

    if user_to_delete.role == 'admin' or user_to_delete.role == 'super_admin':
        raise HTTPException(
            status_code= status.HTTP_403_FORBIDDEN,
            detail= 'You cannot delete user with role admin'
        )

    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found")

    await db.delete(user_to_delete)
    await db.commit()

