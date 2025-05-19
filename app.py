from flask import Flask, jsonify, request, send_from_directory
from flask_restx import Api, Resource, fields, reqparse
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_required, get_jwt
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import logging
import stripe
from dotenv import load_dotenv


load_dotenv()

basedir = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///' + os.path.join(basedir, 'social_media.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

stripe.api_key=os.environ.get('STRIPE_SECRET_KEY', 'sk_test_your_key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
cors = CORS(app)
limiter = Limiter(
    get_remote_address,
    app = app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

api = Api(app, doc="/", title="Social Media API", description='A comprehension REST Api for a social media service.')

authorizations = {
    'jwt':{
        'type': 'apikey',
        'in': 'Header',
        'name': "Authorization"

    }
}
api.authorizations = authorizations

#define namespaces
auth_ns = api.namespace('auth', description='User operations')
users_ns = api.namespace('users', description = 'profile operations and relationship management')
posts_ns = api.namespace('posts', description = 'creation, retrieval and interaction with content')
comments_ns = api.namespace('comments', description = 'comments interaction')
media_ns = api.namespace('media', description = 'for media handling')
notifications_ns = api.namespace('notifications', description = 'User activity and engagement tracking')
messages_ns = api.namespace('messages', description = 'Handling direct messaging')
search_ns = api.namespace('search', description = 'Api for searching users, posts, hashtags and searching across all content types')
moderation_ns = api.namespace('moderation', description = 'moderation to ensure reporting content and Blocking users is possible')
analytics_ns = api.namespace('analytics', description = 'provision of insights data')


revoked_tokens = set()


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"message": "token has expired", "error": "token_expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"message": "signature verification failed", "error": "invalid_token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"message": "Request does not contain an access token", "error":"Authorization_required"}), 401

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

followers = db.Table('followers',
                     db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                     db.Column('followed_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                     db.Column('created_at', db.DateTime(timezone=True), default=lambda: datetime.now()))

class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(50), unique=True, nullable=False)
        email = db.Column(db.String(100), unique=True, nullable = False)
        password_hash = db.Column(db.String(128), nullable=False)
        first_name = db.Column(db.String(50), nullable=False)
        last_name = db.Column(db.String(50), nullable = True)
        is_admin = db.Column(db.Boolean, default=False)
        is_verified = db.Column(db.Boolean, default = False)
        verification_token = db.Column(db.String(100), nullable = True)
        date_joined = db.Column(db.DateTime(timezone=True), default = lambda: datetime.now(timezone.utc))
        last_login = db.Column(db.DateTime(timezone=True), nullable = True)

        # profile
        profile_picture = db.column(db.String(255), nullable = True)
        bio = db.Column(db.text, nullable=True)
        location = db.column(db.String(100), nullable=True)
        website = db.Column(db.String(200), nullable = True)

        # Privacy settings
        is_private = db.Column(db.Boolean, default = False)
        allow_messages = db.Column(db.Boolean, default=True)

        last_active = db.Column(db.DateTime(timezone=True), nullable=True)

        notification_preferences = db.Column(db.JSON, default=lambda:{
            'likes': True,
            'comments': True,
            'follows': True,
            'messages': True
        })

        # relationships

        posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete_orphan')
        comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete_orphan')
        likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')

        following = db.relationship(
            'User', secondary='followers',
            primaryjoin = 'User.id==followers.c.follower_id',
            secondaryjoin='User.id==followers.c.followed_id',
            backref=db.backref('followers', lazy='dynamic'),
            lazy = 'dynamic'
        )

        def __repr__(self):
            return f'<User {self.username}>'

        def set_password(self, password):
            """Hash and set password"""
            self.password_hash = generate_password_hash(password)

        def check_password(self, password):
            """verify password"""
            return check_password_hash(self.password_hash, password)

        def follow(self, user):
            """follow another user"""
            if not self.is_following(user) and self != user:
                self.following.append(user)
                return True
            return False

        def unfollow(self, user):
            """Unfollow a user"""
            if self.is_following(user):

                self.following.remove(user)
                return True
            return False
        def is_following(self, user):
            """Checking if following a user is True"""
            return self.following.filter(followers.c.followed_id == user.id).count() > 0









