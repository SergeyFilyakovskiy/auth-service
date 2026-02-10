"""
Docstring for app.database
"""

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from typing import  Annotated
from fastapi import Depends
from .config import DATABASE_URL

async_engine = create_async_engine(DATABASE_URL)

async_session = async_sessionmaker(
    autoflush= False,
    autocommit= False,
    bind= async_engine,
    class_= AsyncSession,
    expire_on_commit= False
)

async def get_db():
    async with async_session() as session:
        try:
            yield  session
        finally:
            await session.aclose()

db_dependency = Annotated[AsyncSession, Depends(get_db)]
