from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


#Базовая модель с id
class BaseModel(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)


#Связь многие-ко-многим между User и Achievement
user_achievements = db.Table('user_achievements',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('achievement_id', db.Integer, db.ForeignKey('achievements.id'), primary_key=True),
    db.Column('unlocked_at', db.DateTime, default=datetime.utcnow)
)


#Пользователей
class User(BaseModel):
    __tablename__ = 'users'
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(), nullable=False)
    level = db.Column(db.Integer, default=1)
    exp = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    routes = db.relationship('Route', back_populates='user')
    rides = db.relationship('Ride', back_populates='user')
    achievements = db.relationship('Achievement', secondary=user_achievements, back_populates='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


#Маршруты
class Route(BaseModel):
    __tablename__ = 'routes'
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String())
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_public = db.Column(db.Boolean, default=True)
    location = db.Column(db.String(120), nullable=False)

    points = db.relationship('RoutePoint', back_populates='route')
    user = db.relationship('User', back_populates='routes')
    rides = db.relationship('Ride', back_populates='route')


#Точки на маршрутах
class RoutePoint(BaseModel):
    __tablename__ = 'route_points'
    route_id =  db.Column(db.Integer, db.ForeignKey('routes.id'), nullable=False)
    order = db.Column(db.Integer)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    name = db.Column(db.String(80))
    description = db.Column(db.String())
    is_ar = db.Column(db.Boolean, default=False)
    ar_content_url = db.Column(db.String())

    route = db.relationship('Route', back_populates='points')
    visits = db.relationship('VisitedPoint', back_populates='point', cascade="all, delete-orphan")


#Посещенные точки маршрутов
class VisitedPoint(BaseModel):
    __tablename__ = 'visited_points'
    ride_id = db.Column(db.Integer, db.ForeignKey('rides.id'), index=True)
    point_id = db.Column(db.Integer, db.ForeignKey('route_points.id'), index=True)

    ride = db.relationship('Ride', back_populates='visited_points')
    point = db.relationship('RoutePoint', back_populates='visits')


#Поездки
class Ride(BaseModel):
    __tablename__ = 'rides'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    route_id = db.Column(db.Integer, db.ForeignKey('routes.id'))
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    distance = db.Column(db.Float)
    max_elevation = db.Column(db.Float)
    gps_track = db.Column(db.JSON)

    user = db.relationship('User', back_populates='rides')
    route = db.relationship('Route', back_populates='rides')
    visited_points = db.relationship('VisitedPoint', back_populates='ride', cascade="all, delete-orphan")

    __table_args__ = (
        db.CheckConstraint('end_time IS NULL OR end_time >= start_time', name='check_end_time'),
    )

    @property
    def duration(self):
        if self.end_time:
            return self.end_time - self.start_time
        return datetime.utcnow() - self.start_time


#Достижения
class Achievement(BaseModel):
    __tablename__ = 'achievements'
    name = db.Column(db.String(), unique=True, nullable=False)
    description = db.Column(db.String())
    criteria_type = db.Column(db.String())
    criteria_value = db.Column(db.Float)

    users = db.relationship('User', secondary=user_achievements, back_populates='achievements')