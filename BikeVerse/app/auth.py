from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash
from app import db
from app.models import User
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from sqlalchemy import or_
from app import blacklist  # Импортируем blacklist

bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    limiter = current_app.extensions['limiter']
    reset_serializer = current_app.reset_serializer

    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()

    if user:
        token = reset_serializer.dumps(
            email,
            salt=current_app.config['RESET_SECRET_KEY']
        )
        return jsonify({"msg": "Reset instructions sent"}), 200

    return jsonify({"error": "Email not found"}), 404


@bp.route('/reset-password', methods=['POST'])
def reset_password():
    reset_serializer = current_app.reset_serializer

    token = request.json.get('token')
    new_password = request.json.get('password')

    try:
        email = reset_serializer.loads(
            token,
            salt=current_app.config['RESET_SECRET_KEY'],
            max_age=3600
        )
    except:
        return jsonify({"error": "Invalid or expired token"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({"msg": "Password updated"}), 200

    return jsonify({"error": "User not found"}), 404


@bp.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    return jsonify({"msg": "Successfully logged out"}), 200


@bp.route('/register', methods=['POST'])
def register():
    limiter = current_app.extensions['limiter']

    data = request.get_json()

    if not data.get('password') or not data.get('username') or not data.get('email'):
        return jsonify({"error": 0}), 400

    if len(data['password']) < 8:
        return jsonify({"error": 1}), 400

    existing_user = User.query.filter(
        or_(User.email == data['email'], User.username == data['username'])
    ).first()

    if existing_user:
        if existing_user.email == data['email']:
            return jsonify({"error": 2}), 400
        else:
            return jsonify({"error": 3}), 400

    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    reset_serializer = current_app.reset_serializer
    verification_token = reset_serializer.dumps(
        new_user.email,
        salt='email-verification'
    )

    return jsonify({
        'access': create_access_token(identity=new_user.id),
        'refresh': create_refresh_token(identity=new_user.id),
        'verification_token': verification_token
    }), 201


@bp.route('/verify-email', methods=['POST'])
@jwt_required()
def verify_email():
    reset_serializer = current_app.reset_serializer

    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    token = request.json.get('token')

    try:
        email = reset_serializer.loads(
            token,
            salt='email-verification',
            max_age=86400
        )
    except:
        return jsonify({"error": "Invalid or expired token"}), 400

    if email == user.email:
        user.is_verified = True
        db.session.commit()
        return jsonify({"msg": "Email verified"}), 200

    return jsonify({"error": "Token doesn't match"}), 400


@bp.route('/login', methods=['POST'])
def login():
    limiter = current_app.extensions['limiter']

    data = request.get_json()

    if not data.get('username') or not data.get('password'):
        return jsonify({"error": 0}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({"error": 1}), 401

    if not user.is_verified:
        return jsonify({"error": 4}), 403  # Код 4 для "Email not verified"

    return jsonify({
        'access': create_access_token(identity=user.id),
        'refresh': create_refresh_token(identity=user.id),
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "level": user.level,
        "exp": user.exp,
        "created_at": user.created_at.isoformat()
    }), 200


@bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": 0}), 404

    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "level": user.level,
        "exp": user.exp,
        "created_at": user.created_at.isoformat()
    }), 200


@bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": 0}), 404

    return jsonify({
        "new_access": create_access_token(identity=user.id),
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "level": user.level,
        "exp": user.exp,
        "created_at": user.created_at.isoformat()
    }), 200

