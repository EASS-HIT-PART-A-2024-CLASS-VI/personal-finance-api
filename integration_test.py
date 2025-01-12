# integration_test.py

import pytest
from datetime import timedelta, datetime, timezone
import jwt
import time

# Utility function to generate unique emails


def unique_email(base="inttestuser"):
    return f"{base}_{int(time.time() * 1000)}@example.com"


@pytest.mark.asyncio
async def test_root_endpoint(async_client):
    response = await async_client.get("/")
    assert response.status_code == 200
    assert response.json() == {
        "message": "Welcome to the Personal Finance API!"}


@pytest.mark.asyncio
async def test_user_signup_and_signin_flow(async_client):
    # Use unique email to avoid "Email already in use" errors during tests
    email = unique_email()
    signup_payload = {
        "username": "integrationuser",
        "email": email,
        "password": "integrationpass"
    }
    signup_response = await async_client.post("/users/signup", json=signup_payload)
    assert signup_response.status_code == 201, signup_response.text
    signup_data = signup_response.json()
    assert "access_token" in signup_data
    assert "refresh_token" in signup_data

    signin_payload = {
        "email": email,
        "password": "integrationpass"
    }
    signin_response = await async_client.post("/users/signin", json=signin_payload)
    assert signin_response.status_code == 200, signin_response.text
    signin_data = signin_response.json()
    assert "access_token" in signin_data
    assert "refresh_token" in signin_data


@pytest.mark.asyncio
async def test_records_crud_flow(async_client):
    # Create a new user for record operations with unique email
    email = unique_email()
    signup_payload = {
        "username": "recorduser",
        "email": email,
        "password": "recordpass"
    }
    signup_resp = await async_client.post("/users/signup", json=signup_payload)
    assert signup_resp.status_code == 201, signup_resp.text
    tokens = signup_resp.json()
    access_token = tokens["access_token"]

    headers = {"Authorization": f"Bearer {access_token}"}

    # Create a record
    record_payload = {
        "amount": 100.0,
        "category": "Groceries",
        "description": "Test grocery shopping"
    }
    create_resp = await async_client.post("/records/", json=record_payload, headers=headers)
    assert create_resp.status_code == 201, create_resp.text
    created_record = create_resp.json()
    record_id = created_record["id"]

    # Retrieve all records
    get_resp = await async_client.get("/records/", headers=headers)
    assert get_resp.status_code == 200, get_resp.text
    records_list = get_resp.json()
    # Check that at least one record exists
    assert any(rec["id"] == record_id for rec in records_list)

    # Update the record
    update_payload = {"amount": 150.0, "description": "Updated groceries"}
    update_resp = await async_client.patch(f"/records/{record_id}", json=update_payload, headers=headers)
    assert update_resp.status_code == 200, update_resp.text
    updated_record = update_resp.json()
    assert updated_record["amount"] == 150.0
    assert updated_record["description"] == "Updated groceries"

    # Delete the record
    delete_resp = await async_client.delete(f"/records/{record_id}", headers=headers)
    assert delete_resp.status_code == 200, delete_resp.text
    delete_data = delete_resp.json()
    assert delete_data["message"] == "Record deleted successfully."

    # Confirm deletion
    get_after_delete = await async_client.get("/records/", headers=headers)
    assert get_after_delete.status_code == 200, get_after_delete.text
    records_after_delete = get_after_delete.json()
    assert all(rec["id"] != record_id for rec in records_after_delete)


@pytest.mark.asyncio
async def test_protected_routes_without_auth(async_client):
    # Attempt GET /records/ without auth should result in 401
    response_get = await async_client.get("/records/")
    assert response_get.status_code == 401

    # Attempt POST /records/ without auth should result in 401
    response_post = await async_client.post("/records/", json={"amount": 50.0, "category": "Misc"})
    assert response_post.status_code == 401


# Utility for creating an expired token for testing purposes
def create_expired_token():
    from app.utils import create_token  # Import here to avoid circular import issues
    data = {"sub": "expireduser"}
    # Create a token that expired 1 minute ago
    return create_token(data, expires_delta=timedelta(minutes=-1), token_type="access")


@pytest.mark.asyncio
async def test_signin_invalid_credentials(async_client):
    # Attempt sign-in with non-existent email
    response = await async_client.post("/users/signin", json={
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    })
    assert response.status_code in (400, 404), response.text

    # Register a valid user first
    email = unique_email("invalidcreds")
    await async_client.post("/users/signup", json={
        "username": "invalidcredsuser",
        "email": email,
        "password": "correctpassword"
    })

    # Attempt sign-in with incorrect password
    response = await async_client.post("/users/signin", json={
        "email": email,
        "password": "wrongpassword"
    })
    # Assuming 400 Bad Request for invalid credentials
    assert response.status_code == 400, response.text


@pytest.mark.asyncio
async def test_invalid_data_for_record_operations(async_client):
    email = unique_email("invalidrecord")
    # Register and sign in
    await async_client.post("/users/signup", json={
        "username": "invalidrecorduser",
        "email": email,
        "password": "testpassword"
    })
    signin_resp = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    token = signin_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test creating a record with invalid data (e.g., negative amount)
    invalid_record_payload = {
        "amount": -50.0,  # Invalid negative amount
        "category": "Food",
        "description": "Invalid test"
    }
    create_resp = await async_client.post("/records/", json=invalid_record_payload, headers=headers)
    assert create_resp.status_code in (
        400, 422), create_resp.text  # Expect validation error

    # Test updating a record with invalid ID
    update_resp = await async_client.patch("/records/invalid-id", json={"amount": 200.0}, headers=headers)
    assert update_resp.status_code in (400, 404), update_resp.text

    # Test deleting a record with invalid ID
    delete_resp = await async_client.delete("/records/invalid-id", headers=headers)
    assert delete_resp.status_code in (400, 404), delete_resp.text


@pytest.mark.asyncio
async def test_expired_or_malformed_tokens(async_client):
    # Test with expired token
    expired_token = create_expired_token()
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = await async_client.get("/records/", headers=headers)
    # Expect unauthorized (401) or similar due to expired token
    assert response.status_code == 401, response.text

    # Test with malformed token
    malformed_headers = {"Authorization": "Bearer malformed.token.here"}
    response = await async_client.get("/records/", headers=malformed_headers)
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_pagination_and_filtering(async_client):
    email = unique_email("pagination")
    # Register and sign in to create multiple records
    await async_client.post("/users/signup", json={
        "username": "paginationuser",
        "email": email,
        "password": "testpassword"
    })
    signin_resp = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    token = signin_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create multiple records for pagination test
    for i in range(15):
        await async_client.post("/records/", json={
            "amount": 10.0 + i,
            "category": "TestCategory",
            "description": f"Record {i}"
        }, headers=headers)

    # Test pagination with skip and limit
    response = await async_client.get("/records/?skip=0&limit=5", headers=headers)
    assert response.status_code == 200, response.text
    records = response.json()
    assert len(records) <= 5

    # Test filtering by category (case-insensitive, partial match)
    response = await async_client.get("/records/?category=testcategory", headers=headers)
    assert response.status_code == 200, response.text
    # Ensure records filtered match criteria (assuming at least one record exists)
    for record in response.json():
        assert "testcategory" in record["category"].lower()


@pytest.mark.asyncio
async def test_unauthorized_access(async_client):
    # Test accessing a protected route without a token
    response = await async_client.get("/records/")
    assert response.status_code == 401, response.text

    # Test posting to a protected route without a token
    response = await async_client.post("/records/", json={"amount": 50.0, "category": "Misc"})
    assert response.status_code == 401, response.text


@pytest.mark.asyncio
async def test_non_existent_resource_operations(async_client):
    email = unique_email("nonexistent")
    await async_client.post("/users/signup", json={
        "username": "nonexistentuser",
        "email": email,
        "password": "testpassword"
    })
    signin_resp = await async_client.post("/users/signin", json={
        "email": email,
        "password": "testpassword"
    })
    token = signin_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to update a non-existent record
    response = await async_client.patch("/records/507f1f77bcf86cd799439099", json={"amount": 200.0}, headers=headers)
    assert response.status_code == 404, response.text

    # Attempt to delete a non-existent record
    response = await async_client.delete("/records/507f1f77bcf86cd799439099", headers=headers)
    assert response.status_code == 500, response.text

