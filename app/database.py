# app/database.py

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.server_api import ServerApi
import os


def get_database():
    uri = os.getenv("MONGO_URI")
    if not uri:
        raise ValueError("MONGO_URI environment variable is not set.")
    client = AsyncIOMotorClient(uri, server_api=ServerApi("1"))
    return client.get_database("personal_finance_db")


# Then retrieve your specific collections from the database:
db = get_database()
users_collection = db.get_collection("users")
records_collection = db.get_collection("records")


