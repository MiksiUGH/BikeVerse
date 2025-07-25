import os
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()


class Config:
    # Секретный ключ для защиты от CSRF
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'

    # URI для подключения к БД
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'

    # Отключаем отслеживание модификаций (для экономии памяти)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Ключ для JWT-токенов
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'super-secret-jwt-key'

    # Время жизни access-токена (30 минут)
    JWT_ACCESS_TOKEN_EXPIRES = 1800

    # Время жизни refresh-токена (30 дней)
    JWT_REFRESH_TOKEN_EXPIRES = 2592000