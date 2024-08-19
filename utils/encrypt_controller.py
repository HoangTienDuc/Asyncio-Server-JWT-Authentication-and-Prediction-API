from utils import asymmetric_helper
from common.global_vars import *
import jwt
import datetime

async def create_jwt(user_id, username, private_key, exp_minutes):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_minutes)
    }
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

class EncryptHandler:
    def __init__(self):
        """
        Initialize the EncryptHandler class.

        If the asymmetric public and private key files do not exist, generate a new key pair,
        save the public key to the specified path, and save the private key to the specified path.
        Otherwise, load the existing public and private keys from the specified paths.

        Attributes:
        asymmetric_private_key: The private key for asymmetric encryption.
        asymmetric_public_key: The public key for asymmetric decryption.
        """
        if not ASYMMETRIC_PUBLIC_KEY_PATH.exists() or not ASYMMETRIC_PRIVATE_KEY_PATH.exists():
            self.asymmetric_private_key, self.asymmetric_public_key = asymmetric_helper.generate_key_pair()
            asymmetric_helper.save_public_key(self.asymmetric_public_key, ASYMMETRIC_PUBLIC_KEY_PATH)
            asymmetric_helper.save_private_key(self.asymmetric_private_key, ASYMMETRIC_PRIVATE_KEY_PATH)
        else:
            self.asymmetric_private_key = asymmetric_helper.load_private_key(ASYMMETRIC_PRIVATE_KEY_PATH)
            self.asymmetric_public_key = asymmetric_helper.load_public_key(ASYMMETRIC_PUBLIC_KEY_PATH)
            
    def asymmetric_encrypt_message(self, message):
        return asymmetric_helper.encrypt_message(message, self.asymmetric_public_key)

    def asymmetric_decrypt_message(self, ciphertext):
        return asymmetric_helper.decrypt_message(ciphertext, self.asymmetric_private_key)
        