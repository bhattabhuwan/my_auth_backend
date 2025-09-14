from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, decode_token
)
from flask_cors import CORS
from datetime import timedelta
import logging

# Swagger
from flasgger import Swagger

# Set up logging
logging.basicConfig(level=logging.INFO)  # INFO level
logger = logging.getLogger(__name__)

app = Flask(__name__)
swagger = Swagger(app)
CORS(app)  # Enable CORS

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

# Root route for Render / health check
@app.route('/')
def home():
    """
    Home route to check if API is running
    ---
    responses:
      200:
        description: API is running
    """
    return "API is running!", 200

# Register route
@app.route('/register', methods=['POST'])
def register():
    """
    User Registration
    ---
    tags:
      - Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: Register
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              example: johndoe
            email:
              type: string
              example: johndoe@example.com
            password:
              type: string
              example: secret123
    responses:
      201:
        description: User created successfully
      400:
        description: Bad request (missing or duplicate data)
    """
    try:
        data = request.get_json() or {}
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not (username and email and password):
            return jsonify({'msg': 'Username, email and password required'}), 400

        if User.query.filter((User.email == email) | (User.username == username)).first():
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

# Login route
@app.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          id: Login
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: johndoe@example.com
            password:
              type: string
              example: secret123
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
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

# Forgot-password route
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json()
        email = data.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'msg': 'email not found'}), 400

        reset_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(minutes=15),
            additional_claims={'reset': True}
        )

        return jsonify({'reset_token': reset_token}), 200

    except Exception as e:
        logger.exception(f"Error in forgot_password: {e}")
        return jsonify({'msg': 'something went wrong'}), 500

# ... keep all your other routes (reset-password, refresh, protected, users, delete, etc.) unchanged ...

if __name__ == '__main__':
    with app.app_context():
        db.create_all()   # ensures tables are created
    app.run(host='0.0.0.0', port=5000)
