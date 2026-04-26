import os
import hashlib
from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from sqlalchemy import text
from app.extensions import db
from app.config import Config
from app.utils import allowed_file

files_bp = Blueprint('files', __name__)

@files_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Handle duplicate filenames? secure_filename might not be enough if file exists.
        # But for now, sticking to original logic.
        
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        
        file_content = file.read()
        padded_data = padder.update(file_content) + padder.finalize()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
        file_hash = hashlib.sha256(encrypted_data).hexdigest()
        
        if not os.path.exists(Config.UPLOAD_FOLDER):
            os.makedirs(Config.UPLOAD_FOLDER)
            
        encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)
            
        db.session.execute(
            text('INSERT INTO files (user_id, filename, hash, encryption_key) '
                 'VALUES (:uid, :fname, :hash, :key)'),
            {'uid': current_user.id, 'fname': filename, 'hash': file_hash, 'key': key}
        )
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 201
    
    return jsonify({'error': 'File type not allowed'}), 400

@files_bp.route('/', methods=['GET'])
@login_required
def list_files():
    result = db.session.execute(
        text('SELECT filename, upload_time, hash FROM files WHERE user_id = :id'),
        {'id': current_user.id}
    )
    files = result.fetchall()
    files_list = []
    for f in files:
        files_list.append({
            'filename': f[0],
            'upload_time': f[1],
            'hash': f[2]
        })
    return jsonify({'files': files_list})

@files_bp.route('/<filename>', methods=['DELETE'])
@login_required
def delete_file(filename):
    result = db.session.execute(
        text('SELECT id FROM files WHERE filename = :fname AND user_id = :uid'),
        {'fname': filename, 'uid': current_user.id}
    )
    file_record = result.fetchone()
    if not file_record:
        return jsonify({'error': 'File not found or permission denied'}), 404
    
    file_id = file_record[0]
    
    db.session.execute(
        text('DELETE FROM shared_files WHERE file_id = :fid'),
        {'fid': file_id}
    )
    db.session.execute(
        text('DELETE FROM files WHERE id = :id'),
        {'id': file_id}
    )
    db.session.commit()
    
    file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({'message': 'File deleted successfully'}), 200
    else:
        return jsonify({'message': 'File record deleted but file not found on disk'}), 200 # Or 404? 200 is safer.

@files_bp.route('/verify', methods=['POST'])
@login_required
def batch_verify():
    result = db.session.execute(
        text('SELECT filename, hash FROM files WHERE user_id = :uid'),
        {'uid': current_user.id}
    )
    files = result.fetchall()
    
    verified_count = 0
    failed_count = 0
    failed_files = []
    
    for filename, stored_hash in files:
        encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            current_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            if current_hash == stored_hash:
                verified_count += 1
            else:
                failed_count += 1
                failed_files.append(filename)
        else:
            failed_count += 1
            failed_files.append(f"{filename} (File not found)")
            
    return jsonify({
        'verified_count': verified_count,
        'failed_count': failed_count,
        'failed_files': failed_files
    })
