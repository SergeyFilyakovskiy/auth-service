"""
Docstring for app.main
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from .routers import auth        

app = FastAPI()
app.include_router(router= auth.router)
