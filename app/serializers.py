# app/serializers.py

from app.schemas import UserRead, RecordRead


def serialize_user(user: dict) -> UserRead:
    """
    Convert a MongoDB user document to a UserRead Pydantic model.

    Args:
        user (dict): The user document from MongoDB.

    Returns:
        UserRead: The serialized user data.
    """
    return UserRead(
        id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        created_at=user["created_at"],
        updated_at=user["updated_at"]
    )


def serialize_record(record: dict) -> RecordRead:
    """
    Convert a MongoDB record document to a RecordRead Pydantic model.

    Args:
        record (dict): The record document from MongoDB.

    Returns:
        RecordRead: The serialized record data.
    """
    return RecordRead(
        id=str(record["_id"]),
        user_id=record["user_id"],
        amount=record["amount"],
        category=record["category"],
        description=record.get("description"),
        date=record["date"]
    )
