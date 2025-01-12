# main.py
from app.routers import users, records, personal_assistant
from fastapi import FastAPI


app = FastAPI()


app.include_router(users.router)
app.include_router(records.router)
app.include_router(personal_assistant.router)


@app.get("/")
async def read_root():
    return {"message": "Welcome to the Personal Finance API!"}
