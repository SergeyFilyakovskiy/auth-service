from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from starlette import status
from sqlalchemy.ext.asyncio import AsyncSession

from .user import RoleChecker
from app.database import get_db
from app.models import User
from app.schemas import TokenData

router = APIRouter(
    prefix='/super-admin',
    tags=['super-admin']
)

super_admin_only = RoleChecker(["super_admin"])

# ==========================================
# Удалить аккаунт(Полное удаление)
# ==========================================
@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(super_admin_only)
):
    """

    Полное удаление пользователя из БД. 
    Ручка доступна супер-админам,
    супер-админ может удалить любой профиль

    :param user_id: id пользователя 
    :type user_id: int

    """

    result = await db.execute(select(User).where(User.id == user_id))
    user_to_delete = result.scalar_one_or_none()

    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail="User not found")

    await db.delete(user_to_delete)
    await db.commit()

# ===========================
# Мягкое удаление пользователя
# ===========================
@router.delete(
        "/soft-delete/{user_id}", 
        status_code=status.HTTP_204_NO_CONTENT
        )
async def soft_delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(super_admin_only),
   
) -> None:
    """
    
    Мягкое удаление профиля любого пользователя, 

    :param db: Открытая сессия БД
    :param token: Данные из JWT

    """
    result = await db.execute(select(User).where(User.id == token.id))
    user_in_db = result.scalar_one_or_none()
    if not user_in_db:
        raise HTTPException(
            status_code= status.HTTP_404_NOT_FOUND,
            detail= 'User not found'
        )
    
    if user_in_db.is_active == False:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User is already deleted'
        )
    
    user_in_db.is_active = False

    db.add(user_in_db)
    await db.commit()
    await db.refresh(user_in_db)