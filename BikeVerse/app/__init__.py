from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from config import Config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer

# Инициализируем расширения
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

# Черный список токенов
blacklist = set()

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Инициализация расширений
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Инициализация Limiter
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )
    limiter.init_app(app)

    # Инициализация reset_serializer
    app.reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # Security headers
    @app.after_request
    def add_security_headers(resp):
        resp.headers['Content-Security-Policy'] = "default-src 'self'"
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return resp

    # Регистрация блюпринтов
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    return app