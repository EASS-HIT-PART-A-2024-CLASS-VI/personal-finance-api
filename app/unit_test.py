# app/unit_test.py

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.utils import hash_password, verify_password, create_token, decode_access_token
from datetime import timedelta
import os
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

# Configure synchronous TestClient for utility tests
client = TestClient(app)

# Constants
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Synchronous tests for utility functions


def test_hash_password():
    password = "testpassword"
    hashed_password = hash_password(password)
    assert verify_password(password, hashed_password)


def test_create_token():
    data = {"sub": "testuser"}
    access_token = create_token(
        data,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access"
    )
    payload = decode_access_token(access_token)
    assert payload["sub"] == "testuser"

# Utility function to generate a unique email based on timestamp


def unique_email(base="testuser"):
    return f"{base}_{int(time.time() * 1000)}@example.com"

# Asynchronous tests for endpoints using pytest-asyncio and the async_client fixture


@pytest.mark.asyncio
async def test_user_registration(async_client):
    email = unique_email()
    payload = {
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    }
    response = await async_client.post("/users/signup", json=payload)
    assert response.status_code == 201, response.text
    json_resp = response.json()
    assert "access_token" in json_resp
    assert "refresh_token" in json_resp


@pytest.mark.asyncio
async def test_user_signin(async_client):
    # Ensure the user exists by registering with a unique email
    email = unique_email()
    registration_payload = {
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    }
    await async_client.post("/users/signup", json=registration_payload)

    signin_payload = {
        "email": email,
        "password": "testpassword"
    }
    response = await async_client.post("/users/signin", json=signin_payload)
    assert response.status_code == 200, response.text
    json_resp = response.json()
    assert "access_token" in json_resp
    assert "refresh_token" in json_resp


@pytest.mark.asyncio
async def test_create_record(async_client):
    # Register and sign in to get a fresh access token
    email = unique_email()
    await async_client.post("/users/signup", json={
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    })
    signin_response = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    access_token = signin_response.json()["access_token"]

    record_payload = {
        "amount": 100.0,
        "category": "Groceries",
        "description": "Weekly groceries"
    }
    response = await async_client.post(
        "/records/",
        json=record_payload,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 201, response.text
    assert response.json()["amount"] == 100.0


@pytest.mark.asyncio
async def test_get_records(async_client):
    email = unique_email()
    await async_client.post("/users/signup", json={
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    })
    signin_response = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    access_token = signin_response.json()["access_token"]

    response = await async_client.get(
        "/records/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_update_record(async_client):
    email = unique_email()
    await async_client.post("/users/signup", json={
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    })
    signin_response = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    access_token = signin_response.json()["access_token"]

    record_payload = {
        "amount": 100.0,
        "category": "Groceries",
        "description": "Weekly groceries"
    }
    create_response = await async_client.post(
        "/records/",
        json=record_payload,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    record_id = create_response.json()["id"]

    update_payload = {"amount": 150.0}
    update_response = await async_client.patch(
        f"/records/{record_id}",
        json=update_payload,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert update_response.status_code == 200, update_response.text
    assert update_response.json()["amount"] == 150.0


@pytest.mark.asyncio
async def test_delete_record(async_client):
    email = unique_email()
    await async_client.post("/users/signup", json={
        "username": "testuser",
        "email": email,
        "password": "testpassword"
    })
    signin_response = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    access_token = signin_response.json()["access_token"]

    record_payload = {
        "amount": 100.0,
        "category": "Groceries",
        "description": "Weekly groceries"
    }
    create_response = await async_client.post(
        "/records/",
        json=record_payload,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    record_id = create_response.json()["id"]

    delete_response = await async_client.delete(
        f"/records/{record_id}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert delete_response.status_code == 200, delete_response.text
    assert delete_response.json()["message"] == "Record deleted successfully."
