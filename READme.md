# Asyncio Server JWT Authentication and Prediction API

This asyncio server application provides JWT-based authentication, data prediction, and a health check endpoint. It demonstrates secure login, access token and refresh token generation, and protected endpoints.

## Features

- JWT-based authentication with RSA asymmetric encryption
- Token-based access control for endpoints
- Predictive data processing using a machine learning model
- Health check endpoint
- Secure storage and handling of sensitive information

## Requirements

- Python 3.6+
- Asyncio
- PyJWT
- cryptography

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/HoangTienDuc/Asyncio-Server-JWT-Authentication-and-Prediction-API
    cd Asyncio-Server-JWT-Authentication-and-Prediction-API
    ```

2. **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
    Create a `.env` file with the following contents and fill in the appropriate values:
    ```env
    PRIVATE_KEY_PATH=/path/to/your/private_key.pem
    PUBLIC_KEY_PATH=/path/to/your/public_key.pem
    ```

5. **Run the application:**
    ```bash
    python3 server.py
    ```

## API Endpoints

### 1. Login

**Endpoint:**

POST /login


**Description:**

Authenticates a user and returns an access token and a refresh token.

**Request:**

```
{
    "username": "base64_encrypted_username",
    "user_id": "base64_encrypted_user_id",
    "password": "base64_encrypted_password"
}
```

**Response:**
```
{
    "access_token": "access_token",
    "refresh_token": "refresh_token"
}
```

### 2. Get Data
**Endpoint:**

POST /api/data

**Description:**

Processes input data and returns the prediction result. Requires an access token.

**Request:**

```
{
    'message_id': int(time.time()),
    'device_id': 'e5acd0ad-be8e-4793-947a-6643b0f23041',
    'camera_id': 'e5acd0ad-be8e-4793-947a-6643b0f23041',
    'image': base64_image
}
```

**Response:**
```
{
    "status": True, 
    "message": None, 
    "content": result, 
    "message_id": message_id, 
    "device_id": device_id, 
    "camera_id": camera_id, 
    "prompt": prompt
}
```

### 3. Refresh Token
**Endpoint:**

POST /refresh
**Description:**

Generates a new access token using a refresh token.

**Request:**
```
{
    "username": "base64_encrypted_username",
    "user_id": "base64_encrypted_user_id",
}
```

**Response:**
```
{
    'access_token': new_access_token
}
```

### 4. Health Check
**Endpoint:**
GET /health

**Description:**
Checks the health of the application. Requires an access token.

**Request:**
```
curl http://127.0.0.1:5000/health
```
**Response:**
```
{
    "status": "healthy",
    "message": "Application is running smoothly"
}
```