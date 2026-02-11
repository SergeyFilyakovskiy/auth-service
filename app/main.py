"""
Docstring for app.main
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth, user, admin, super_admin

app = FastAPI()

app.include_router(router= auth.router)
app.include_router(router= user.router)
app.include_router(router= admin.router)
app.include_router(router= super_admin.router)

