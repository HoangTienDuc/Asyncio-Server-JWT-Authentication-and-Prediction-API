from flask import Flask, request, jsonify
import jwt
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

app = Flask(__name__)

class JwtHandler:
    def create_jwt(self, user_id, username, private_key, exp_minutes):
        payload = {
            'user_id': user_id,
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_minutes)
        }
        token = jwt.encode(payload, private_key, algorithm='RS256')
        return token

# Đọc khóa riêng từ file
with open("/develop/sample_encryption/data/private_key.pem", "rb") as f:
    private_key = f.read()

# Đọc khóa công khai từ file
with open("/develop/sample_encryption/data/public_key.pem", "rb") as f:
    public_key = f.read()

# Hàm tạo JWT
def create_jwt(user_id, username, private_key, exp_minutes):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_minutes)
    }
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

# Route để đăng nhập và tạo token
@app.route('/login', methods=['POST'])
def login():
    # Dữ liệu đăng nhập giả định
    user_data = {
        'user_id': 123,
        'username': 'john_doe'
    }

    access_token = create_jwt(user_data['user_id'], user_data['username'], private_key, 15)  # Access token hết hạn sau 15 phút
    refresh_token = create_jwt(user_data['user_id'], user_data['username'], private_key, 1440)  # Refresh token hết hạn sau 1 ngày

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    })

# Route để xác minh JWT và trả về dữ liệu
@app.route('/api/data', methods=['POST'])
def get_data():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token is missing!'}), 403

    try:
        decoded_payload = jwt.decode(token, public_key, algorithms=['RS256'])
        user_id = decoded_payload['user_id']
        username = decoded_payload['username']
        return jsonify({
            'message': 'Token is valid!',
            'user_id': user_id,
            'username': username,
            'data': 'This is the secured data'
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired!'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token!'}), 403


# Route để làm mới access token
@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.headers.get('Authorization')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing!'}), 403

    try:
        decoded_payload = jwt.decode(refresh_token, public_key, algorithms=['RS256'])
        user_id = decoded_payload['user_id']
        username = decoded_payload['username']
        new_access_token = create_jwt(user_id, username, private_key, 15)  # Access token mới hết hạn sau 15 phút
        return jsonify({
            'access_token': new_access_token
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired!'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 403

if __name__ == '__main__':
    app.run(debug=True)
