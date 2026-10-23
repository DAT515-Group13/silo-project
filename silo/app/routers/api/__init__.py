from fastapi import APIRouter

from app.routers.api import admin, auth, files, links, teams

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(files.router)
api_router.include_router(links.router)
api_router.include_router(teams.router)
api_router.include_router(admin.router)
