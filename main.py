from fastapi import FastAPI, APIRouter
from api.endpoints import contacts, birthdays, auth

app = FastAPI()
api_router = APIRouter()

app.include_router(contacts.router, prefix="/api")
app.include_router(birthdays.router, prefix="/api")
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(contacts.router, prefix="/contacts", tags=["contacts"])
api_router.include_router(birthdays.router, prefix="/birthdays", tags=["birthdays"])
