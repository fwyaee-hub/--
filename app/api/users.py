import os
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text
from app.extensions import db
from app.decorators import admin_required
from app.config import Config

users_bp = Blueprint('users', __name__)

@users_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin
    })

@users_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json() or request.form
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'error': 'Missing password fields'}), 400

    result = db.session.execute(
        text('SELECT * FROM users WHERE id = :id'),
        {'id': current_user.id}
    )
    user_data = result.fetchone()
    # Check old password
    if not check_password_hash(user_data[2], old_password):
        return jsonify({'error': 'Incorrect old password'}), 400

    hashed_password = generate_password_hash(new_password)
    db.session.execute(
        text('UPDATE users SET password = :pwd WHERE id = :id'),
        {'pwd': hashed_password, 'id': current_user.id}
    )
    db.session.commit()
    return jsonify({'message': 'Password updated successfully'}), 200

@users_bp.route('/admin/users', methods=['GET'])
@admin_required
def get_all_users():
    result = db.session.execute(text('SELECT id, username, email, is_admin FROM users'))
    users = result.fetchall()
    users_list = []
    for u in users:
        users_list.append({
            'id': u[0],
            'username': u[1],
            'email': u[2],
            'is_admin': bool(u[3])
        })
    return jsonify({'users': users_list})

@users_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete yourself'}), 400

    # Delete shared files references
    db.session.execute(
        text('DELETE FROM shared_files WHERE sender_id = :id OR receiver_id = :id'),
        {'id': user_id}
    )

    # Get user files to delete physical files
    file_records = db.session.execute(
        text('SELECT filename FROM files WHERE user_id = :id'),
        {'id': user_id}
    ).fetchall()

    db.session.execute(
        text('DELETE FROM files WHERE user_id = :id'),
        {'id': user_id}
    )

    for record in file_records:
        file_path = os.path.join(Config.UPLOAD_FOLDER, record[0])
        if os.path.exists(file_path):
            os.remove(file_path)

    # Delete keys
    db.session.execute(
        text('DELETE FROM user_keys WHERE user_id = :id'),
        {'id': user_id}
    )

    # Delete user
    db.session.execute(text('DELETE FROM users WHERE id = :id'), {'id': user_id})
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200
