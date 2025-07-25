from flask import Blueprint, jsonify

# Создаем блюпринт с префиксом /api
main_bp = Blueprint('main', __name__, url_prefix='/api')

@main_bp.route('/test', methods=['GET'])
def test_endpoint():
    """Тестовый эндпоинт для проверки работы API"""
    return jsonify({
        'status': 'success',
        'message': 'BikeVerse API работает!',
        'version': '0.1'
    }), 200