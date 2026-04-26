from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from urllib.parse import quote
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import text
import unicodedata
import re
import logging
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 配置数据库连接（使用PyMySQL）
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:123456@localhost/fwyaee'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'upload'
db = SQLAlchemy(app)

# 设置登录管理
login_manager = LoginManager()
login_manager.init_app(app)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif','docx'}

# 用户模型
class User(UserMixin):
    def __init__(self, id, username, email, is_admin):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin =bool(is_admin)

@login_manager.user_loader
def load_user(user_id):
    result = db.session.execute(text('SELECT * FROM users WHERE id = :val'), {'val': user_id})
    user_data = result.fetchone()
    if user_data:
        return User(user_data[0], user_data[1], user_data[3], bool(user_data[5]))  # 添加is_admin字段
    return None
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash("请先登录")
            return redirect(url_for('login'))
        if not getattr(current_user, 'is_admin', False):
            flash("无权访问该页面")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html', username=current_user.username)
    return render_template('index.html')

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def init_user_keys(user_id):
    result = db.session.execute(text('SELECT * FROM user_keys WHERE user_id = :val'), {'val': user_id})
    if not result.fetchone():
        private_key, public_key = generate_ecdh_keys()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        db.session.execute(
            text('INSERT INTO user_keys (user_id, private_key, public_key) VALUES (:id, :priv, :pub)'),
            {'id': user_id, 'priv': priv_pem, 'pub': pub_pem}
        )
        db.session.commit()


@app.route('/admin')
@admin_required
def admin_dashboard():
    result = db.session.execute(text('SELECT id, username, email, is_admin FROM users'))
    users = result.fetchall()
    return render_template('admin.html', users=users)




@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash("不能删除自己！")
        return redirect(url_for('admin_dashboard'))
    db.session.execute(
        text('DELETE FROM shared_files WHERE sender_id = :id OR receiver_id = :id'),
        {'id': user_id}
    )

    file_records = db.session.execute(
        text('SELECT filename FROM files WHERE user_id = :id'),
        {'id': user_id}
    ).fetchall()

    db.session.execute(
        text('DELETE FROM files WHERE user_id = :id'),
        {'id': user_id}
    )


    for record in file_records:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], record[0])
        if os.path.exists(file_path):
            os.remove(file_path)


    # 删除共享记录（作为发送方或接收方）

    db.session.execute(
        text('DELETE FROM user_keys WHERE user_id = :id'),
        {'id': user_id}
    )

    db.session.execute(text('DELETE FROM users WHERE id = :id'), {'id': user_id})
    db.session.commit()
    flash("用户已删除")
    return redirect(url_for('admin_dashboard'))
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if len(username) < 3 or len(password) < 6:
            flash("用户名或密码太短")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        try:
            db.session.execute(
                text('INSERT INTO users (username, password, email) VALUES (:name, :pwd, :email)'),
                {'name': username, 'pwd': hashed_password, 'email': email}
            )
            db.session.commit()
            new_user_id = db.session.execute(text('SELECT LAST_INSERT_ID()')).fetchone()[0]
            init_user_keys(new_user_id)
            flash("注册成功！")
            return redirect(url_for('login'))
        except Exception as e:
            flash("用户名或邮箱已存在！")
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        result = db.session.execute(
            text('SELECT * FROM users WHERE username = :name'),
            {'name': username}
        )
        user_data = result.fetchone()
        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1], user_data[3],user_data[4])
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash("用户名或密码错误")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    result = db.session.execute(
        text('SELECT username, email FROM users WHERE id = :id'),
        {'id': current_user.id}
    )
    user_data = result.fetchone()
    if user_data:
        return render_template('profile.html', username=user_data[0], email=user_data[1])
    else:
        flash("无法找到您的信息")
        return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        result = db.session.execute(
            text('SELECT * FROM users WHERE id = :id'),
            {'id': current_user.id}
        )
        user_data = result.fetchone()
        if not check_password_hash(user_data[2], old_password):
            flash("旧密码错误")
            return redirect(url_for('change_password'))
        hashed_password = generate_password_hash(new_password)
        db.session.execute(
            text('UPDATE users SET password = :pwd WHERE id = :id'),
            {'pwd': hashed_password, 'id': current_user.id}
        )
        db.session.commit()
        flash("密码修改成功！")
        return redirect(url_for('profile'))
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('没有选择文件')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('未选择文件')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = file.filename
            filename = os.path.basename(filename)
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            file_content = file.read()
            padded_data = padder.update(file_content) + padder.finalize()
            encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()
            file_hash = hashlib.sha256(encrypted_data).hexdigest()
            encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)


            
            # 在 upload_file 函数中，移除这一行：
            # up(filename,file_hash)  # 删除这行区块链上传调用
            
            db.session.execute(
                text('INSERT INTO files (user_id, filename, hash, encryption_key) '
                     'VALUES (:uid, :fname, :hash,  :key)'),
                {'uid': current_user.id, 'fname': filename, 'hash': file_hash,
                 'key': key}
            )
            db.session.commit()
            # 移除 up(filename,file_hash) 这一行
            flash('文件上传成功')


            return redirect(url_for('uploaded_files'))
    return render_template('upload.html')

@app.route('/uploaded_files')
@login_required
def uploaded_files():
    result = db.session.execute(
        text('SELECT filename, upload_time FROM files WHERE user_id = :id'),
        {'id': current_user.id}
    )
    files = result.fetchall()
    return render_template('uploaded_files.html', files=files)

@app.route('/delete_file/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    result = db.session.execute(
        text('SELECT id FROM files WHERE filename = :fname AND user_id = :uid'),
        {'fname': filename, 'uid': current_user.id}
    )
    file_record = result.fetchone()
    if not file_record:
        flash('文件不存在或您无权限删除此文件')
        return redirect(url_for('uploaded_files'))
    db.session.execute(
        text('DELETE FROM shared_files WHERE file_id = :fid'),
        {'fid': file_record[0]}
    )
    db.session.execute(
        text('DELETE FROM files WHERE id = :id'),
        {'id': file_record[0]}
    )
    db.session.commit()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('文件已删除')
    else:
        flash('文件不存在')
    return redirect(url_for('uploaded_files'))

@app.route('/share_file/<filename>', methods=['GET', 'POST'])
@login_required
def share_file(filename):
    if request.method == 'POST':
        receiver_username = request.form['username']
        result = db.session.execute(
            text('SELECT users.id, user_keys.public_key FROM users '
                 'JOIN user_keys ON users.id = user_keys.user_id WHERE username = :name'),
            {'name': receiver_username}
        )
        receiver = result.fetchone()
        if not receiver:
            flash("用户不存在")
            return redirect(url_for('share_file', filename=filename))
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
            flash("文件不存在")
            return redirect(url_for('uploaded_files'))
        cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_file_key = encryptor.update(file_record[0]) + encryptor.finalize()
        db.session.execute(
            text('INSERT INTO shared_files (file_id, sender_id, receiver_id, encrypted_key) '
                 'SELECT f.id, :sid, :rid, :key FROM files f WHERE f.filename = :fname'),
            {'sid': current_user.id, 'rid': receiver_id, 'key': encrypted_file_key, 'fname': filename}
        )
        db.session.commit()
        flash("文件分享成功")
        return redirect(url_for('uploaded_files'))
    return render_template('share_file.html', filename=filename)

@app.route('/shared_files')
@login_required
def shared_files():
    result = db.session.execute(text('''
        SELECT f.filename, u.username, sf.shared_at, f.hash, sf.id 
        FROM shared_files sf
        JOIN files f ON sf.file_id = f.id 
        JOIN users u ON sf.sender_id = u.id 
        WHERE sf.receiver_id = :rid
    '''), {'rid': current_user.id})
    shared_files = result.fetchall()
    return render_template('shared_files.html', files=shared_files)

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    return value.strftime(format)

@app.route('/download_shared/<filename>')
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
        flash("文件不存在或没有访问权限")
        return redirect(url_for('shared_files'))
    
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
    
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(encrypted_file_path):
        flash("文件不存在")
        return redirect(url_for('shared_files'))
    
    # 读取加密文件并验证完整性
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # 验证加密文件的完整性
    current_encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
    if current_encrypted_hash != original_file_hash:
        flash("❌ 文件完整性验证失败！文件可能已被篡改，拒绝下载")
        # 记录安全日志
        logging.warning(f"文件完整性验证失败 - 用户: {current_user.id}, 文件: {filename}, 原始哈希: {original_file_hash[:16]}..., 当前哈希: {current_encrypted_hash[:16]}...")
        return redirect(url_for('shared_files'))
    
    # 解密文件
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(file_encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    
    try:
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError:
        flash("文件解密失败")
        return redirect(url_for('shared_files'))
    
    # 验证解密后文件的完整性（可选的额外验证）
    decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
    
    # 记录成功的完整性验证日志
    logging.info(f"文件完整性验证成功 - 用户: {current_user.id}, 文件: {filename}, 哈希: {original_file_hash[:16]}...")
    flash(f"✅ 文件完整性验证通过，开始下载")
    
    response = make_response(decrypted_data)
    response.headers['Content-Type'] = 'application/octet-stream'
    encoded_filename = quote(filename, safe='', encoding='utf-8')
    content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"
    response.headers['Content-Disposition'] = content_disposition.encode('latin-1').decode('utf-8')
    
    return response

@app.route('/delete_shared/<int:shared_file_id>', methods=['POST'])
@login_required
def delete_shared(shared_file_id):
    result = db.session.execute(
        text('SELECT id FROM shared_files WHERE id = :id AND receiver_id = :rid'),
        {'id': shared_file_id, 'rid': current_user.id}
    )
    if not result.fetchone():
        flash("无权限删除该共享记录")
        return redirect(url_for('shared_files'))
    db.session.execute(
        text('DELETE FROM shared_files WHERE id = :id'),
        {'id': shared_file_id}
    )
    db.session.commit()
    flash("已删除共享文件记录")
    return redirect(url_for('shared_files'))


@app.route('/verify_shared_file/<filename>')
@login_required
def verify_shared_file(filename):
    """验证接收到的共享文件完整性"""
    result = db.session.execute(text('''
        SELECT sf.encrypted_key, f.hash, f.user_id, u.username
        FROM shared_files sf 
        JOIN files f ON sf.file_id = f.id 
        JOIN users u ON sf.sender_id = u.id
        WHERE sf.receiver_id = :rid AND f.filename = :fname
    '''), {'rid': current_user.id, 'fname': filename})
    
    file_data = result.fetchone()
    if not file_data:
        flash("文件不存在或没有访问权限")
        return redirect(url_for('shared_files'))
    
    encrypted_key, original_file_hash, sender_id, sender_name = file_data
    
    # 检查文件是否存在
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(encrypted_file_path):
        flash("❌ 文件不存在于服务器")
        return redirect(url_for('shared_files'))
    
    # 读取并验证文件完整性
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    current_hash = hashlib.sha256(encrypted_data).hexdigest()
    
    if current_hash == original_file_hash:
        flash(f"✅ 共享文件完整性验证成功！")
        flash(f"文件来源：{sender_name}，文件未被篡改")
        # 记录验证成功日志
        logging.info(f"共享文件完整性验证成功 - 接收者: {current_user.id}, 发送者: {sender_name}, 文件: {filename}")
    else:
        flash(f"❌ 共享文件完整性验证失败！")
        flash(f"文件可能在传输或存储过程中被篡改")
        # 记录验证失败日志
        logging.warning(f"共享文件完整性验证失败 - 接收者: {current_user.id}, 发送者: {sender_name}, 文件: {filename}")
        logging.warning(f"原始哈希: {original_file_hash}, 当前哈希: {current_hash}")
    
    return redirect(url_for('shared_files'))
@app.route('/batch_verify')
@login_required
def batch_verify():
    """批量验证用户所有文件的完整性"""
    result = db.session.execute(
        text('SELECT filename, hash FROM files WHERE user_id = :uid'),
        {'uid': current_user.id}
    )
    files = result.fetchall()
    
    verified_count = 0
    failed_count = 0
    failed_files = []
    
    for filename, stored_hash in files:
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
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
            failed_files.append(f"{filename} (文件不存在)")
    
    if failed_count == 0:
        flash(f"✅ 批量验证完成！{verified_count} 个文件完整性良好")
    else:
        flash(f"⚠️ 验证完成：{verified_count} 个文件正常，{failed_count} 个文件异常")
        flash(f"异常文件：{', '.join(failed_files)}")
    
    return redirect(url_for('uploaded_files'))
@app.route('/batch_verify_shared')
@login_required
def batch_verify_shared():
    """批量验证所有接收到的共享文件"""
    result = db.session.execute(text('''
        SELECT f.filename, f.hash, u.username
        FROM shared_files sf 
        JOIN files f ON sf.file_id = f.id 
        JOIN users u ON sf.sender_id = u.id
        WHERE sf.receiver_id = :rid
    '''), {'rid': current_user.id})
    
    shared_files = result.fetchall()
    
    if not shared_files:
        flash("没有共享文件需要验证")
        return redirect(url_for('shared_files'))
    
    verified_count = 0
    failed_count = 0
    failed_files = []
    
    for filename, original_hash, sender_name in shared_files:
        encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            current_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            if current_hash == original_hash:
                verified_count += 1
            else:
                failed_count += 1
                failed_files.append(f"{filename} (来自 {sender_name})")
        else:
            failed_count += 1
            failed_files.append(f"{filename} (文件不存在)")
    
    if failed_count == 0:
        flash(f"✅ 批量验证完成！{verified_count} 个共享文件完整性良好")
    else:
        flash(f"⚠️ 验证完成：{verified_count} 个文件正常，{failed_count} 个文件异常")
        flash(f"异常文件：{', '.join(failed_files)}")
    
    return redirect(url_for('shared_files'))
if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        admin_username = 'admin'
        result = db.session.execute(
            text('SELECT * FROM users WHERE username = :name'),
            {'name': admin_username}
        )
        admin_user = result.fetchone()
        if not admin_user:
            hashed_password = generate_password_hash('admin')
            # 添加email字段（例如使用空字符串）
            db.session.execute(
                text('INSERT INTO users (username, password, email, is_admin) VALUES (:name, :pwd, :email, :is_admin)'),
                {
                    'name': admin_username,
                    'pwd': hashed_password,
                    'email': '',  # 提供默认值
                    'is_admin': True
                }
            )
            db.session.commit()
            print("管理员账户 'admin' 已创建")
    app.run(debug=True)


# 配置日志
logging.basicConfig(
    filename='bin/logs/integrity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_integrity_check(filename, user_id, result, stored_hash, current_hash):
    """记录完整性检查日志"""
    status = "SUCCESS" if result else "FAILED"
    logging.info(f"INTEGRITY_CHECK - User: {user_id}, File: {filename}, Status: {status}, Stored: {stored_hash[:16]}..., Current: {current_hash[:16]}...")