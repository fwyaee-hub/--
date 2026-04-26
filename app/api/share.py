import os
import hashlib
from urllib.parse import quote
from flask import Blueprint, request, jsonify, make_response
from flask_login import login_required, current_user
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from sqlalchemy import text
from app.extensions import db
from app.config import Config

share_bp = Blueprint('share', __name__)

@share_bp.route('/share/<filename>', methods=['POST'])
@login_required
def share_file(filename):
    data = request.get_json() or request.form
    receiver_username = data.get('username')
    
    if not receiver_username:
        return jsonify({'error': 'Receiver username required'}), 400
        
    result = db.session.execute(
        text('SELECT users.id, user_keys.public_key FROM users '
             'JOIN user_keys ON users.id = user_keys.user_id WHERE username = :name'),
        {'name': receiver_username}
    )
    receiver = result.fetchone()
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
        
    receiver_id, receiver_pub = receiver
    receiver_public_key = serialization.load_pem_public_key(receiver_pub)
    
    result = db.session.execute(
        text('SELECT private_key FROM user_keys WHERE user_id = :uid'),
        {'uid': current_user.id}
    )
    sender_priv_pem = result.fetchone()[0]
    sender_private_key = serialization.load_pem_private_key(sender_priv_pem, password=None)
    
    shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)
    
    result = db.session.execute(
        text('SELECT encryption_key FROM files WHERE filename = :fname AND user_id = :uid'),
        {'fname': filename, 'uid': current_user.id}
    )
    file_record = result.fetchone()
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
        
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # file_record[0] is the AES key used to encrypt the file. We encrypt this key with the derived shared key.
    # Note: AES Key is 32 bytes (256 bits). ECB mode requires block size alignment if not full blocks? 
    # AES block size is 16 bytes. 32 bytes is 2 blocks. So it fits perfectly. No padding needed for the key itself.
    encrypted_file_key = encryptor.update(file_record[0]) + encryptor.finalize()
    
    try:
        db.session.execute(
            text('INSERT INTO shared_files (file_id, sender_id, receiver_id, encrypted_key) '
                 'SELECT f.id, :sid, :rid, :key FROM files f WHERE f.filename = :fname'),
            {'sid': current_user.id, 'rid': receiver_id, 'key': encrypted_file_key, 'fname': filename}
        )
        db.session.commit()
        return jsonify({'message': 'File shared successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@share_bp.route('/', methods=['GET'])
@login_required
def list_shared_files():
    result = db.session.execute(text('''
        SELECT f.filename, u.username, sf.shared_at, f.hash, sf.id 
        FROM shared_files sf
        JOIN files f ON sf.file_id = f.id 
        JOIN users u ON sf.sender_id = u.id 
        WHERE sf.receiver_id = :rid
    '''), {'rid': current_user.id})
    shared_files = result.fetchall()
    
    files_list = []
    for f in shared_files:
        files_list.append({
            'filename': f[0],
            'sender': f[1],
            'shared_at': f[2],
            'hash': f[3],
            'id': f[4]
        })
    return jsonify({'shared_files': files_list})

@share_bp.route('/download/<filename>', methods=['GET'])
@login_required
def download_shared(filename):
    result = db.session.execute(text('''
        SELECT sf.encrypted_key, f.hash, f.user_id 
        FROM shared_files sf 
        JOIN files f ON sf.file_id = f.id 
        WHERE sf.receiver_id = :rid AND f.filename = :fname
    '''), {'rid': current_user.id, 'fname': filename})
    file_data = result.fetchone()
    if not file_data:
        return jsonify({'error': 'File not found or access denied'}), 404
    
    encrypted_key, original_file_hash, sender_id = file_data
    
    result = db.session.execute(
        text('SELECT private_key FROM user_keys WHERE user_id = :uid'),
        {'uid': current_user.id}
    )
    receiver_priv_pem = result.fetchone()[0]
    receiver_private_key = serialization.load_pem_private_key(receiver_priv_pem, password=None)
    
    result = db.session.execute(
        text('SELECT public_key FROM user_keys WHERE user_id = :uid'),
        {'uid': sender_id}
    )
    sender_pub_pem = result.fetchone()[0]
    sender_public_key = serialization.load_pem_public_key(sender_pub_pem)
    
    shared_key = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)
    
    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    file_encryption_key = decryptor.update(encrypted_key) + decryptor.finalize()
    
    encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    if not os.path.exists(encrypted_file_path):
        return jsonify({'error': 'Physical file not found'}), 404
    
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    current_encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
    if current_encrypted_hash != original_file_hash:
        return jsonify({'error': 'File integrity check failed'}), 400
    
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(file_encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    try:
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError:
        return jsonify({'error': 'Decryption failed'}), 500
        
    response = make_response(decrypted_data)
    response.headers['Content-Type'] = 'application/octet-stream'
    encoded_filename = quote(filename, safe='', encoding='utf-8')
    content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"
    response.headers['Content-Disposition'] = content_disposition.encode('latin-1').decode('utf-8')
    
    return response

@share_bp.route('/<int:shared_file_id>', methods=['DELETE'])
@login_required
def delete_shared(shared_file_id):
    result = db.session.execute(
        text('SELECT id FROM shared_files WHERE id = :id AND receiver_id = :rid'),
        {'id': shared_file_id, 'rid': current_user.id}
    )
    if not result.fetchone():
        return jsonify({'error': 'Record not found'}), 404
        
    db.session.execute(
        text('DELETE FROM shared_files WHERE id = :id'),
        {'id': shared_file_id}
    )
    db.session.commit()
    return jsonify({'message': 'Shared file record deleted'}), 200

@share_bp.route('/verify_batch', methods=['POST'])
@login_required
def batch_verify_shared():
    result = db.session.execute(text('''
        SELECT f.filename, f.hash, u.username
        FROM shared_files sf 
        JOIN files f ON sf.file_id = f.id 
        JOIN users u ON sf.sender_id = u.id
        WHERE sf.receiver_id = :rid
    '''), {'rid': current_user.id})
    
    shared_files = result.fetchall()
    
    verified_count = 0
    failed_count = 0
    failed_files = []
    
    for filename, original_hash, sender_name in shared_files:
        encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            current_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            if current_hash == original_hash:
                verified_count += 1
            else:
                failed_count += 1
                failed_files.append(f"{filename} (from {sender_name})")
        else:
            failed_count += 1
            failed_files.append(f"{filename} (File not found)")
            
    return jsonify({
        'verified_count': verified_count,
        'failed_count': failed_count,
        'failed_files': failed_files
    })
