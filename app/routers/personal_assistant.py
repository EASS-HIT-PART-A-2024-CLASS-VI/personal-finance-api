# app/routers/personal_assistant.py

from datetime import datetime, timedelta, timezone
from huggingface_hub import InferenceClient
from app.auth import get_current_user
from app.database import records_collection
from fastapi import APIRouter, Depends, HTTPException
from app.schemas import QuestionRequest
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize the Hugging Face InferenceClient
client = InferenceClient(api_key=os.getenv(
    "HF_API_TOKEN", "default_value"))

router = APIRouter(
    prefix="/personal_assistant",
    tags=["Personal Assistant"]
)


@router.post("/")
async def personal_assistant(
    request: QuestionRequest,
    current_user: dict = Depends(get_current_user)
):
    question = request.question  # Extract the question from the request body
    user_id = str(current_user["_id"])
    username = current_user.get("username", "User")

    # Retrieve recent transactions (e.g., last month)
    one_month_ago = datetime.now(timezone.utc) - timedelta(days=30)
    records_cursor = records_collection.find({
        "user_id": user_id,
        "date": {"$gte": one_month_ago}
    })
    records = await records_cursor.to_list(length=100)

    # Summarize the records for context
    records_summary = "\n".join([
        f"{record['date'].strftime('%Y-%m-%d')}: Spent ${record['amount']} on "
        f"{record.get('category', 'various')}."
        for record in records
    ])

    # Construct a detailed system message prompt
    system_message = (
        f"You are a highly knowledgeable personal finance assistant. "
        f"The user,{username}, has the following recent transaction history:\n"
        f"{records_summary}\n\n"
        "Use this transaction history to provide personalized financial advice, budgeting tips, "
        "and recommendations that consider the user's spending habits, savings goals, and patterns. "
        "Answer the following question based on this context."
        "Limit the response to 100 words"
    )

    # Create the message sequence for the API call
    messages = [
        {
            "role": "system",
            "content": system_message
        },
        {
            "role": "user",
            "content": question
        }
    ]

    try:
        completion = client.chat.completions.create(
            model="microsoft/Phi-3-mini-4k-instruct",
            messages=messages,
            max_tokens=500
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    response_message = completion.choices[0].message
    return {"response": response_message.content}
