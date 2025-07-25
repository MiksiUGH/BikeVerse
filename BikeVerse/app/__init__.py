from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from config import Config

# Инициализируем расширения
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()


def create_app(config_class=Config):
    """Фабрика приложений"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Инициализация расширений с приложением
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Регистрируем блюпринты
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    return app