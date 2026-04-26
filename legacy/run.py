import os
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from app import create_app, db

app = create_app()

def init_admin():
    with app.app_context():
        # Create upload folder if not exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
            
        # Create admin user if not exists
        admin_username = 'admin'
        try:
            result = db.session.execute(
                text('SELECT * FROM users WHERE username = :name'),
                {'name': admin_username}
            )
            admin_user = result.fetchone()
            if not admin_user:
                hashed_password = generate_password_hash('admin')
                db.session.execute(
                    text('INSERT INTO users (username, password, email, is_admin) VALUES (:name, :pwd, :email, :is_admin)'),
                    {
                        'name': admin_username,
                        'pwd': hashed_password,
                        'email': '',
                        'is_admin': True
                    }
                )
                db.session.commit()
                print("Admin user 'admin' created.")
        except Exception as e:
            print(f"Error checking/creating admin: {e}")

if __name__ == '__main__':
    init_admin()
    app.run(debug=True)
