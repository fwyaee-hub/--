from app.config import Config


def create_app(config_class=Config):
    from flask import Flask
    from app.extensions import db, login_manager
    from app.api.auth import auth_bp
    from app.api.users import users_bp
    from app.api.files import files_bp
    from app.api.share import share_bp

    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(share_bp, url_prefix="/api/share")

    return app
