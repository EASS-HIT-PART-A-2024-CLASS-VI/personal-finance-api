# Personal Finance Backend

A FastAPI-based personal finance backend with integrated language model capabilities. This project uses Docker for containerization, making it easy to build, run, and test in a consistent environment.

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [File Explanations](#file-explanations)
- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Building the Docker Image](#building-the-docker-image)
- [Running the Application](#running-the-application)
- [Running Tests](#running-tests)
- [Usage Example](#usage-example)
- [Troubleshooting](#troubleshooting)
- [Additional Notes](#additional-notes)
- [Contact](#contact)

## Features

- **User Authentication and Management:** Register, sign in, and manage user accounts.
- **CRUD Operations for Financial Records:** Create, read, update, and delete financial transactions.
- **Personalized Financial Advice:** Leverage Hugging Face's Phi model to provide tailored financial recommendations.
- **Dockerized Environment:** Simplifies setup, deployment, and testing.

## Project Structure

```
personal-finance-api/
├── app/
│   ├── __init__.py
│   ├── auth.py
│   ├── database.py
│   ├── main.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── personal_assistant.py
│   │   ├── records.py
│   │   └── users.py
│   ├── schemas.py
│   ├── serializers.py
│   ├── unit_tests.py
│   └── utils.py
├── conftest.py
├── integration_test.py
├── requirements.txt
├── Dockerfile
├── .env
└── README.md
```

## File Explanations

- **app/auth.py**: Contains functions for user authentication, token management, and dependencies like `get_current_user`.
- **app/database.py**: Manages connection to MongoDB using Motor, sets up access to collections.
- **app/main.py**: The main entry point. It creates the FastAPI instance, sets up routes, and configures middlewares.
- **app/routers/**: Contains API route definitions, split by functionality:
  - **personal_assistant.py**: Endpoints related to personal assistant features using the language model.
  - **records.py**: Endpoints for creating, reading, updating, and deleting financial records.
  - **users.py**: Endpoints for user-related operations like registration and login.
- **app/schemas.py**: Defines Pydantic models used for data validation in requests and responses.
- **app/serializers.py**: Provides functions to transform raw database documents into formatted response objects.
- **app/unit_tests.py**: Contains unit tests for individual functions and components.
- **app/utils.py**: General utility functions for tasks like hashing passwords and creating tokens.
- **conftest.py**: Pytest configuration file; defines fixtures that can be shared across multiple test files.
- **integration_test.py**: Contains integration tests that verify interactions between different parts of the application.
- **requirements.txt**: Lists all Python packages required by the project.
- **Dockerfile**: Contains instructions to build a Docker image for the application, including installing dependencies and running the server.
- **README.md**: This documentation file describing how to set up, run, and use the project.

## Prerequisites

- [Docker](https://www.docker.com/get-started) installed on your machine.
- A MongoDB Atlas account or a running MongoDB instance.
- Hugging Face API key for accessing the Phi model.

## Environment Variables

Environment variables are used to manage sensitive information securely. Follow these steps to set them up:

1. **Create a `.env` File:**

   - In the project root, create a file named `.env`.
   - Add variables with your actual values:
   - `.env.example` is provided as a template for required environment variables without sensitive data.

## Building the Docker Image

Follow these steps to build the Docker image for your application:

1. **Clone the Repository:**

   ```bash
   git clone <repository_url>.git
   cd personal-finance-api

   ```

2. **Set up Environment Variables:**

   ```bash
   cp .env.example .env
   ```

   - Edit `.env` and replace placeholder values with your actual credentials.

3. **Build the Docker Image:**
   ```bash
   docker build -t personal-finance-api .
   ```
   - This builds an image named `personal-finance-api` using the Dockerfile.

## Running the Application

Run the application container with:

```bash
docker run -p 8000:8000 --env-file .env personal-finance-api
```

- Maps port 8000 of the container to port 8000 on your host.
- Loads environment variables from `.env`.
- Access the app at [http://localhost:8000](http://localhost:8000).

## Running Tests

To execute tests inside a Docker container:

```bash
docker run --env-file .env personal-finance-api pytest .
```

- Runs `pytest` within the container using environment variables from `.env`.
- Displays test results in your terminal.

## Usage Example

### Personal Assistant Endpoint

- **Endpoint:** `POST /personal_assistant`
- **Headers:**
  - `Content-Type: application/json`
  - `Authorization: Bearer <your_jwt_token>`
- **Body:**
  ```json
  {
    "question": "How can I save more on groceries?"
  }
  ```

**Example using `curl`:**

```bash
curl -X POST "http://localhost:8000/personal_assistant" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <your_jwt_token>" \
     -d '{"question": "How can I save more on groceries?"}'
```

**Expected Response:**

```json
{
  "response": "Based on your recent spending, consider budgeting and looking for discounts..."
}
```

_Note: Response will vary based on model output and user data._

## Troubleshooting

- **Docker Build Errors:**
  - Verify `requirements.txt` and Dockerfile syntax.
- **Application Fails to Start:**
  - Confirm correct environment variable values in `.env`.
  - Check logs:
    ```bash
    docker logs <container_id>
    ```
- **Database Connection Issues:**
  - Validate `MONGO_URI`.
  - Ensure IP whitelist settings in MongoDB Atlas if needed.
- **Hugging Face API Errors:**
  - Check that `HF_API_TOKEN` is valid and within usage limits.
  - Verify network connectivity to Hugging Face's API.

## Additional Notes

- The `.env` file is not committed to version control. Use `.env.example` as a guide.
- The Docker container uses `--env-file` to load environment variables securely.
- Adjust model parameters and configuration in your code as necessary.

