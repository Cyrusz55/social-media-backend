from flask import Flask, jsonify, request, send_from_directory, render_template_string, url_for, render_template
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
import re
import secrets
from flask_mail import Mail, Message
from threading import Thread



load_dotenv()

basedir = os.path.dirname(os.path.realpath(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__, template_folder='templates')
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
mail = Mail(app)
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

# define namespaces
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
class Post(db.model):
    id = db.Column(db.integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.column(db.DateTime(timezone=True),onupdate = lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    media_url = db.Column(db.String(255), nullable=True)
    media_type = db.Column(db.String(20), default='public')

    # Relationships
    likes = db.relationship('like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')

class Comment(db.model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable = False)
    created_at = db.Column(db.DateTime(timezone = True), default = lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Ineger,db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable = False)

class Relationship(db.model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id= db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    timestamp = db.Column(db.DateTime(timezone = True), default=lambda: datetime.now(timezone.utc))
    status = db.Column(db.String(20), default = 'pending', nullable = False)

    # relationships
    follower = db.relationship('User', foreign_keys= [follower_id], backref = db.backref('following', lazy = 'dynamic'))
    followed = db.relationship('User', foreign_keys= [followed_id], backref = db.backref('followers', lazy = 'dynamic'))

    def __repr__(self):
        return f"<Relationship follower_id = {self.follower_id} followed_id={self.followed_id} status = {self.status}>"

class Like(db.model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False) # the user who likes the post
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable = False) # the post that was liked
    created_at = db.Column(db.DateTime(timezone = True), default = lambda: datetime.now(timezone.utc)) # when the like was created

    # relationships
    user = db.relationship('User', backref=db.backref('likes', lazy='dynamic'))
    post = db.relationship('Post', backref=db.backref('likes', lazy='dynamic'))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),

    )

    def __repr__(self):
        return f"Like user_id={self.user_id} post_id={self.post_id} timestamp={self.timestamp}>"

class Notification(db.model):
    __tablename__ = 'Notifications'

    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # user who receive the notification
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False) # User who caused the notification
    notification_type = db.Column(db.String(50), nullable = False) # type of notification like, comment, follow
    target_id = db.Column(db.Integer, nullable=True)
    target_type = db.Column(db.String(50), nullable = True)
    message = db.Column(db.String(255), nullable = True)
    is_read = db.Column(db.Boolean, default = False, nullable = False)
    created_at = db.Column(db.DateTime(timezone = True), default =  lambda: datetime.now(timezone.utc))

    # Relationship for easy navigation
    user = db.relationship('User', foreign_keys=[user_id], backref = db.backref('notifications', lazy = 'dynamic'))
    actor = db.relationship('User', foreign_keys = [actor_id])

    def __repr__(self):
        return f"<Notification id={self.id} user_id{self.user_id} type = {self.notification_type} read = {self.is_read}>"


class Message(db.model):
    id = db.Column(db.Integer, primary_key = True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable = False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable = False)
    timestamp = db.Column(db.DateTime(timezone = True), default = lambda: datetime.now(timezone.utc))
    is_read = db.Column(db.Boolean, default = False, nullable = False)

    # relationships for easier access to sender and receipient user objects
    sender = db.relationship('User', foreign_keys=[sender_id], backref=db.backref('sent_messages', lazy='dynamic'))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_messages', lazy='dynamic'))


    def __repr__(self):
        return f"<Message id ={self.id} sender_id = {self.sender_id} recipient_id = {self.recipiemt_id} read = {self.is_read}>"

class MediaFile(db.model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable = True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable = True)
    filename = db.Column(db.String(255), nullable = False)
    media_type = db.Column(db.String(50), nullable = False)
    size = db.Column(db.Integer, nullable = True)
    upload_time = db.Column(db.DateTime(timezone = True), default = lambda: datetime.now(timezone.utc))
    description = db.Column(db.String(255), nullable = True)


    # Relationship for easy access and cascading deletes if needed
    user = db.relationship('User', backref=db.backref('media_files', lazy='dynamic'))
    post = db.relationship ('Post', backref = db.backref('media_files',lazy = 'dynamic'))
    message = db.relationship('message', backref=db.backref('media_files', lazy='dynamic'))


    def __repr__(self):
        return f"<MediaFile id={self.id} filename{self.filename} media_type = {self.media_type} user_id = {self.user_id}>"


# Blacklisted token model for JWT management
class BlacklistedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    token_type = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    expires = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<BlacklistedToken: {self.token_type}>'


# Helper functions for validation
def validate_email(email):
    """Validate email format"""
    email_pattern = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
    return bool(email_pattern.match(email))


def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit"

    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter"

    return True, "Password is valid"


def is_token_blacklisted(jti):
    """Check if token is blacklisted"""
    return BlacklistedToken.query.filter_by(jti=jti).first() is not None

# definition of email utility functions
def send_async_email(app, msg):
    with app.app_conext():
        mail.send(msg)

def send_email(subject, recipients, html_body, text_body = None):
    msg = Message(subject, recipient= recipients)
    msg.html = html_body
    if text_body:
        msg.body = text_body

    Thread(target=send_async_email, args=(app, msg)).start()

def send_verification_email(user):
    verification_url = f"http://yourdomain.com/verify-email?token={user.verification_token}"

    # Generate email content
    subject = "Verify Your Email Address"
    html_template = """
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Verify Your Email</h1>
            <p>Hello {{ name }},</p>
            <p>Please click the link below to verify your email:</p>
            <p><a href="{{ url }}">Verify Email</a></p>
        </body>
        </html>
        """
    html_body = render_template_string(
        html_template,
        name=user.first_name,
        url=verification_url
    )

    text_body = f"""
        Hello {user.first_name},

        Please verify your email by clicking this link:
        {verification_url}
        """
    send_email(
        subject=subject,
        recipients=[user.email],
        html_body=html_body,
        text_body=text_body
    )
def send_password_reset_email(user):
    """Send password reset email to user."""
    reset_url = url_for(
        'auth_ns.password_reset',
        token=user.reset_token,
        _external=True
    )
    # Generate email content
    subject = "Reset Your Password"
    html_body = render_template(
        'emails/reset_password.html',
        user=user,
        reset_url=reset_url
    )
    text_body = render_template(
        'emails/reset_password.txt',
        user=user,
        reset_url=reset_url
    )

    send_email(
        subject=subject,
        recipients=[user.email],
        html_body=html_body,
        text_body=text_body
    )

token_model = auth_ns.model('Token',{
    'access_token': fields.String(description = 'JWT access token'),
    'refresh_token': fields.String(description = 'JWT refresh token'),
    'token_type': fields.String(default = 'Bearer', description = 'Token type'),
    'expires_in': fields.Integer(description = 'Token expiration time in seconds')


})

login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description = 'Username or email'),
    'password': fields.String(required = True, description = 'Password'),

})

register_model = auth_ns.model('Register',{
    'username': fields.String(required = True, description = 'Username'),
    'email': fields.String(required = True, description = 'Email address'),
    'password': fields.String(required = True, description =  'password'),
    'first_name': fields.String(required = False, description = 'First name'),
    'last_name': fields.String(required = False, description = 'Last name'),
})
password_reset_request_model = auth_ns.model('PasswordResetRequest',{
    'email': fields.String(required=True, description = 'Email address')
})

password_reset_model = auth_ns.model('PasswordReset',{
    'token': fields.String(required = True, description = 'Email address'),
    'new_password': fields.String(required=True, description = 'New password')
})

email_verification_model = auth_ns.model('EmailVerification', {
    'token': fields.String(required = True, description = 'Email Verification token')

})

@auth_ns.route('/register')
class RegisterUser(Resource):
    @auth_ns.expect(register_model, validate = True)
    def post(self):
        """register a new user"""
        data = request.json

        if not validate_email(data['email']):
            return{'message': 'Invalid email format'}, 400

        valid_password, msg = validate_password(data['password'])
        if not valid_password:
            return {'message': msg}, 400

        # check if user already exists
        if User.query.filter_by(username=data['username']).first():
            return {'message': 'Email already regisrered'}, 409

        # Create a nrw user
        new_user = User(
            username = data['username'],
            email = data['email'],
            first_name = data['first_name'],
            last_name = data.get('last_name', ''),
            verification_token = secrets.token_urlsafe(32)
        )
        new_user.set_password(data['password'])

        try:
            db.session.add(new_user)
            db.session.commit()

            send_verification_email(new_user)

            return{
                'message': 'User registered successfully. Please check your email to verify account.',
                'user_id': new_user.id
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500