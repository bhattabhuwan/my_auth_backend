from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from  flask_jwt_extended import decode_token
from flask_cors import CORS
from datetime import timedelta
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)  # INFO level to avoid debug spam
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configs
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'change_this_to_a_strong_secret_key_in_production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=60)
app.config['JWT_ERROR_MESSAGE_KEY'] = 'msg'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# JWT Callbacks
@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.warning("Invalid token attempted")
    return jsonify({'msg': 'Invalid token'}), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    logger.warning("Unauthorized access attempt")
    return jsonify({'msg': 'Authorization required'}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    logger.warning("Expired token used")
    return jsonify({'msg': 'Token has expired', 'error': 'token_expired'}), 401

# Routes
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json() or {}
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not (username and email and password):
            return jsonify({'msg': 'Username, email and password required'}), 400

        if User.query.filter((User.email==email) | (User.username==username)).first():
            return jsonify({'msg': 'User already exists'}), 400

        hashed = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed)
        db.session.add(user)
        db.session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=str(user.id), additional_claims={'username': user.username})
        refresh_token = create_refresh_token(identity=str(user.id), additional_claims={'username': user.username})
        
        logger.info(f"New user registered")
        
        return jsonify({
            'msg': 'User created', 
            'access_token': access_token, 
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 201
    except Exception:
        logger.exception("Error during registration")
        return jsonify({'msg': 'Server error during registration'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        if not (email and password):
            return jsonify({'msg': 'Email and password required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'msg': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=str(user.id), additional_claims={'username': user.username})
        refresh_token = create_refresh_token(identity=str(user.id), additional_claims={'username': user.username})
        
        logger.info(f"User logged in")
        
        return jsonify({
            'access_token': access_token, 
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 200
    except Exception:
        logger.exception("Error during login")
        return jsonify({'msg': 'Server error during login'}), 500


# forget password
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'msg': 'email not found'}), 400

        # create a reset validation token
        reset_token = create_access_token(
    identity=str(user.id),
    expires_delta=timedelta(minutes=15),  # ✅ use timedelta directly
    additional_claims={'reset': True}
)

        return jsonify({'reset_token': reset_token}), 200

    except Exception as e:
        print(f"Error in forgot_password: {e}")
        return jsonify({'msg': 'something went wrong'}), 500

# reset password 
@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')

        if not token or not new_password:
            return jsonify({'msg': 'token and new password required'}), 400

        # decode token 
        decode = decode_token(token)
        if not decode.get('reset'):
            return jsonify({'msg': 'invalid reset token'}), 401

        user_id = decode['sub']
        user = User.query.get(user_id)
        if not user:
            return jsonify({'msg': 'user not found'}), 404

        # update password 
        user.password = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({'msg': 'password reset successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#refresh        
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        identity = get_jwt_identity()
        user = User.query.get(int(identity))
        if not user:
            return jsonify({'msg': 'User not found'}), 404

        new_token = create_access_token(identity=str(identity), additional_claims={'username': user.username})
        logger.info("Access token refreshed")
        return jsonify({'access_token': new_token}), 200
    except Exception:
        logger.exception("Error refreshing token")
        return jsonify({'msg': 'Server error during token refresh'}), 500

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'msg': 'User not found'}), 404

        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email
        }), 200
    except Exception:
        logger.exception("Error accessing protected data")
        return jsonify({'msg': 'Server error accessing protected data'}), 500

@app.route('/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'email': user.email
        } for user in users]), 200
    except Exception:
        logger.exception("Error fetching users")
        return jsonify({'msg': 'Server error fetching users'}), 500

@app.route('/delete-account', methods=['DELETE'])
@jwt_required()
def delete_account():
    try:
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'msg': 'User not found'}), 404

        db.session.delete(user)
        db.session.commit()

        logger.info(f"User account deleted")
        return jsonify({'msg': 'Account deleted successfully'}), 200
    except Exception:
        logger.exception("Error deleting account")
        return jsonify({'msg': 'Server error while deleting account'}), 500

@app.route('/delete-all-users', methods=['DELETE'])
def delete_all_users():
    # Admin-only, use header key for safety
    secret = request.headers.get('X-ADMIN-KEY')
    if secret != 'my_super_secret_key':  # Change to strong key
        return jsonify({'msg': 'Unauthorized'}), 401

    try:
        num_deleted = User.query.delete()
        db.session.commit()
        logger.info(f"All users deleted: {num_deleted} accounts removed")
        return jsonify({'msg': f'All users deleted ({num_deleted} accounts)'}), 200
    except Exception:
        logger.exception("Error deleting all users")
        return jsonify({'msg': 'Server error while deleting all users'}), 500

@app.route('/debug/token', methods=['POST'])
def debug_token():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'msg': 'No Bearer token found'}), 400
    token = auth_header[7:]
    return jsonify({
        'token_length': len(token),
        'token_prefix': token[:10] + '...' if len(token) > 10 else token
    }), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
