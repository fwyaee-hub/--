from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from app.extensions import db
from app.models import User
from app.utils import init_user_keys

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        return jsonify({'error': 'Missing required fields'}), 400

    if len(username) < 3 or len(password) < 6:
        return jsonify({'error': 'Username or password too short'}), 400

    hashed_password = generate_password_hash(password)
    try:
        db.session.execute(
            text('INSERT INTO users (username, password, email) VALUES (:name, :pwd, :email)'),
            {'name': username, 'pwd': hashed_password, 'email': email}
        )
        db.session.commit()
        new_user_id = db.session.execute(text('SELECT LAST_INSERT_ID()')).fetchone()[0]
        init_user_keys(new_user_id)
        return jsonify({'message': 'Registration successful'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Username or email already exists'}), 409

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    result = db.session.execute(
        text('SELECT * FROM users WHERE username = :name'),
        {'name': username}
    )
    user_data = result.fetchone()
    
    # Check password
    if user_data and check_password_hash(user_data[2], password):
        # Construct User object. Note: be careful with indices as discussed in models.py
        # app.py login function used: User(user_data[0], user_data[1], user_data[3], user_data[4])
        # This conflicts with load_user indices.
        # Let's try to infer is_admin. If user_data has 6 elements, index 5 is likely is_admin.
        # If it has 5 elements, index 4 might be is_admin.
        
        is_admin = False
        if len(user_data) > 5:
            is_admin = bool(user_data[5])
        elif len(user_data) > 4:
            is_admin = bool(user_data[4])
            
        user = User(user_data[0], user_data[1], user_data[3], is_admin)
        login_user(user)
        return jsonify({'message': 'Login successful', 'user': user.to_dict()}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

@auth_bp.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200
