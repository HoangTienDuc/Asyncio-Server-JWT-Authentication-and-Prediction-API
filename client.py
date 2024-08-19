import requests
import json
import cv2
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
# Constants
LOGIN_URL = 'https://127.0.0.1:8443/login'
DATA_URL = 'https://127.0.0.1:8443/api/data'
REFRESH_URL = 'https://127.0.0.1:8443/refresh'
PUBLIC_KEY_FILE_PATH = "/develop/llm/llm/data/public_key.pem"
TOKEN_FILE_PATH = "common/tokens.json"

def encrypt_str(message, public_key):
    if not isinstance(message, bytes):
        message = message.encode('utf-8')
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def load_public_key(file_path):
    with open(file_path, 'rb') as f:
        pem = f.read()
    return serialization.load_pem_public_key(pem)

def get_tokens(login_url, encrypted_login_info):
    response = requests.post(login_url, json=encrypted_login_info, verify=False)
    if response.status_code == 200:
        try:
            return response.json()
        except json.JSONDecodeError as e:
            print("JSON decode error:", e)
            print("Response content:", response.text)
            return None
    else:
        print("Request failed with status code:", response.status_code)
        print("Response content:", response.text)
        return None

def refresh_access_token(refresh_url, refresh_token):
    headers = {'Authorization': refresh_token}
    response = requests.post(refresh_url, headers=headers, verify=False)
    if response.status_code == 200:
        try:
            return response.json()
        except json.JSONDecodeError as e:
            print("JSON decode error:", e)
            print("Response content:", response.text)
            return None
    else:
        print("Request failed with status code:", response.status_code)
        print("Response content:", response.text)
        return None

def create_encrypted_login_info(public_key, username, password, user_id):
    return {
        "username": encrypt_str(username, public_key),
        "password": encrypt_str(password, public_key),
        "user_id": encrypt_str(user_id, public_key),
    }

def send_data_request(data_url, access_token, form_data):
    headers = {'Authorization': access_token}
    response = requests.post(data_url, headers=headers, json=form_data, verify=False)
    return response

def encode_image_to_base64(image_path):
    image = cv2.imread(image_path)
    encoded_image = cv2.imencode('.jpg', image)[1].tobytes()
    return base64.b64encode(encoded_image).decode('ascii')

def save_tokens_to_file(file_path, tokens):
    with open(file_path, 'w') as f:
        json.dump(tokens, f)

def load_tokens_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def get_valid_access_token(login_url, refresh_url, encrypted_login_info, token_file_path):
    tokens = load_tokens_from_file(token_file_path)
    if tokens:
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        # Test if the token is valid
        test_response = send_data_request(DATA_URL, access_token, {})
        result = test_response.json()
        if result.get("content") != 403:
            return access_token
        else:
            # Try to refresh the access token using the refresh token
            new_tokens = refresh_access_token(refresh_url, refresh_token)
            if new_tokens:
                tokens['access_token'] = new_tokens.get('access_token')
                save_tokens_to_file(token_file_path, tokens)
                return new_tokens.get('access_token')

    # If no valid token, get a new one
    tokens = get_tokens(login_url, encrypted_login_info)
    if tokens:
        save_tokens_to_file(token_file_path, tokens)
        return tokens.get('access_token')
    else:
        print("Failed to obtain access token")
        return None

def main():
    public_key = load_public_key(PUBLIC_KEY_FILE_PATH)

    encrypted_login_info = create_encrypted_login_info(
        public_key, 
        "threatvision", 
        "!@mM@ver!ck", 
        "4aa0f6ff-cad4-4fbd-a143-e68971d87230"
    )

    print("encrypted_login_info: ", encrypted_login_info)

    access_token = get_valid_access_token(LOGIN_URL, REFRESH_URL, encrypted_login_info, TOKEN_FILE_PATH)
    if not access_token:
        return

    print("Access Token:", access_token)
    tic = time.time()
    base64_image = encode_image_to_base64("uploads/1718883347.103994|017ed5d1-23aa-4f81-aee8-384419aa176d|HAND_GUN|DETECTION.jpg")
    form_data = {
        'message_id': int(time.time()),
        'device_id': 'e5acd0ad-be8e-4793-947a-6643b0f23041',
        'camera_id': 'e5acd0ad-be8e-4793-947a-6643b0f23041',
        'image': base64_image
    }

    data_response = send_data_request(DATA_URL, access_token, form_data)
    if data_response.status_code != 200:
        print("Failed to send data, getting new token")
        tokens = get_tokens(LOGIN_URL, encrypted_login_info)
        if tokens:
            save_tokens_to_file(TOKEN_FILE_PATH, tokens)
            access_token = tokens['access_token']
            data_response = send_data_request(DATA_URL, access_token, form_data)
    toc = time.time()
    print("Processing time: ", toc - tic)
    
    print(data_response.json())

if __name__ == "__main__":
    main()
