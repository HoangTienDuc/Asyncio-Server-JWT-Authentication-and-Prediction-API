import aiohttp
from aiohttp import web
import jwt
import base64
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from .encrypt_controller import create_jwt  # Assuming this function is defined in encrypt_controller
from common.global_vars import *  # Assuming these are global variables used in the application
from utils.encrypt_controller import EncryptHandler
from utils.prediction import LvmHandler

class JWTManager:
    def __init__(self, app: web.Application, encrypt_handler: EncryptHandler, lvm_predictor: LvmHandler):
        """
        Initialize the JWTManager class with the provided application, encryption handler, and LVM predictor.

        Parameters:
        - app (web.Application): The aiohttp application instance.
        - encrypt_handler (EncryptHandler): An instance of the EncryptHandler class for handling encryption and decryption.
        - lvm_predictor (LvmHandler): An instance of the LvmHandler class for making predictions using LVM.

        The class initializes routes for login, data retrieval, token refresh, and health check.
        """
        self.app = app
        self.encrypt_handler = encrypt_handler
        self.lvm_predictor = lvm_predictor
        
        # Initialize routes
        app.router.add_post('/login', self.login)
        app.router.add_post('/api/data', self.get_data)
        app.router.add_post('/refresh', self.refresh)
        app.router.add_get('/health', self.healthcheck)

    async def decrypt_str(self, encrypted_message):
        decoded_encrypted_message = base64.b64decode(encrypted_message)
        decrypted_message = self.encrypt_handler.asymmetric_decrypt_message(decoded_encrypted_message)
        return decrypted_message.decode('utf-8')
    
    async def healthcheck(self, request):
        # Check database connection or other services
        return web.json_response({
            'status': 'healthy',
            'message': 'Application is running smoothly'
        })

    async def login(self, request):
        try:
            encrypted_login_info = await request.json()
            username = await self.decrypt_str(encrypted_login_info.get("username"))
            user_id = await self.decrypt_str(encrypted_login_info.get("user_id"))
            password = await self.decrypt_str(encrypted_login_info.get("password"))

            if username == 'threatvision' and password == '!@mM@ver!ck':
                access_token = await create_jwt(user_id, password, self.encrypt_handler.asymmetric_private_key, 15)  # Access token expires in 15 minutes
                refresh_token = await create_jwt(user_id, password, self.encrypt_handler.asymmetric_private_key, 1440)  # Refresh token expires in 1 day

                return web.json_response({
                    'access_token': access_token,
                    'refresh_token': refresh_token
                })
            else:
                return web.json_response({'message': 'Invalid credentials'}, status=403)

        except Exception as e:
            return web.json_response({'message': 'Error processing request', 'error': str(e)}, status=500)

    async def get_data(self, request):
        # Check for Authorization header
        token = request.headers.get('Authorization')
        if not token:
            return web.json_response({"status": False, "content": 403, 'message': 'Token is missing!'}, status=403)

        # Verify JWT token and extract payload
        try:
            decoded_payload = await self.verify_jwt_token(token)
            if not decoded_payload:
                return web.json_response({"status": False, "content": 403, 'message': 'Invalid token!'}, status=403)

            # Perform data processing (example using a predictor)
            data = await request.json()
            result = self.lvm_predictor.predict(data)
            return web.json_response(result)

        except Exception as e:
            return web.json_response({"status": False, "content": 403, 'message': str(e)}, status=403)

    async def verify_jwt_token(self, token):
        try:
            # Decode and verify JWT token
            decoded_payload = jwt.decode(token, self.encrypt_handler.asymmetric_public_key, algorithms=['RS256'])
            return decoded_payload
        except jwt.ExpiredSignatureError:
            raise web.HTTPForbidden(reason='Token has expired!')
        except jwt.InvalidTokenError:
            raise web.HTTPForbidden(reason='Invalid token!')
        except Exception as e:
            raise web.HTTPInternalServerError(reason=f'Error decoding token: {str(e)}')

    async def refresh(self, request):
        refresh_token = request.headers.get('Authorization')

        if not refresh_token:
            return web.json_response({'message': 'Refresh token is missing!'}, status=403)

        try:
            decoded_payload = await self.verify_jwt_token(refresh_token)
            user_id = decoded_payload['user_id']
            username = decoded_payload['username']
            new_access_token = await create_jwt(user_id, username, self.encrypt_handler.asymmetric_private_key, 15)  # Access token expires in 15 minutes
            return web.json_response({
                'access_token': new_access_token
            })
        except jwt.ExpiredSignatureError:
            return web.json_response({'message': 'Refresh token has expired!'}, status=403)
        except jwt.InvalidTokenError:
            return web.json_response({'message': 'Invalid refresh token!'}, status=403)
