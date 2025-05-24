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
from sqlalchemy import func
from sqlalchemy import Table, Column, Integer, ForeignKey, desc, or_, and_
from sqlalchemy.orm import relationship, joinedload
from PIL import Image
from werkzeug.exceptions import NotFound, Forbidden, BadRequest


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
        profile_picture = db.Column(db.String(255), nullable = True)
        bio = db.Column(db.Text, nullable=True)
        location = db.Column(db.String(100), nullable=True)
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

        posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
        comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
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
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True),onupdate = lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    media_url = db.Column(db.String(255), nullable=True)
    media_type = db.Column(db.String(20), default='public')

    # Relationships
    likes = db.relationship('like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable = False)
    created_at = db.Column(db.DateTime(timezone = True), default = lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable = False)

class Relationship(db.Model):
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

class Like(db.Model):
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

class Notification(db.Model):
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


class Message(db.Model):
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

class MediaFile(db.Model):
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

# profile model for the API
profile_model = users_ns.model('UserProfile', {
    'Username': fields.String(description='Username'),
    'first_name': fields.String(description = 'First name'),
    'last_name': fields.String(description = 'Last name', required=False),
    'bio': fields.String(description = 'User biography', required=False),
    'location': fields.String(description = 'User location', required=False),
    'website': fields.String(description = 'User website', required=False),
    'profile_picture': fields.String(description = 'URL to profile picture', required=False),
    'followers_count': fields.Integer(description = 'Number of followers'),
    'following_count': fields.Integer(description = 'Number of users being followed'),
    'posts_count': fields.Integer(description = 'Number of posts created'),
    'date_joined': fields.DateTime(description = 'Date user joined'),
    'is_private': fields.Boolean(description = 'whether the user profile is private')
})

# profile update model
profile_update_model = users_ns.model('ProfileUpdate',{
    'first_name': fields.String(description = 'First name', required=False),
    'last_name': fields.String(description = 'Last name', required = False),
    'bio': fields.String(description = 'User biography', required=False),
    'location': fields.String(description='User location', required=False),
    'website': fields.String(description = 'User website', required=False)
})

# privacy settings model

privacy_settings_model = users_ns.model('PrivacySettings',{
    'is_private': fields.Boolean(description = 'Where the profile is private'),
    'allow_messages': fields.Boolean(description = 'Whether to allow direct messages')
})

# Follow request model
follow_model = users_ns.model('FollowRequest', {
    'user_id': fields.Integer(description='ID of the user to follow/unfollow')
})

user_search_model = users_ns.model('UserSearch',{
    'query': fields.String(description = 'search term'),
    'page': fields.Integer(description = 'Page number', required=False, default = 1),
    'per_page': fields.Integer(description = 'Results per page', required = False, default=20)
})

# basic user info model

user_info_model = users_ns.model('UserInfo', {
    'id': fields.Integer(description='User ID'),
    'Username': fields.String(description='Username'),
    'first_name': fields.String(description='First name'),
    'last_name': fields.String(description='Last name', required = False),
    'Profile_picture': fields.String(description = 'URL to profile picture', required=False),
    'is_private': fields.Boolean(description='Whether the user profile is private'),
    'is_following': fields.Boolean(description = 'Whether the current user is following this user'),
    'is_followed_by': fields.Boolean(description = 'whether this user is following the current user')
})

users_list_model = users_ns.model('UsersList', {
    'users': fields.List(fields.Nested(user_info_model)),
    'total': fields.Integer(description='Total number of results'),
    'page': fields.Integer(description='Current page number'),
    'pages': fields.Integer(description='Total number of pages'),
    'per_page': fields.Integer(description='Results per page')
})


@users_ns.route('/profile')
class UserProfile(Resource):
    @jwt_required()
    @users_ns.marshal_with(profile_model)
    def get(self):
        """Get current user's profile"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)

        # calculate counts
        followers_count = user.followers.count()
        following_count = user.following.count()
        posts_count = user.posts.count()

        # prepare response
        response = {
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'bio': user.bio,
            'location': user.location,
            'website': user.website,
            'profile_picture': user.profile_picture,
            'followers_count': followers_count,
            'following_count': following_count,
            'posts_count': posts_count,
            'date_joined': user.date_joined,
            'is_private': user.is_private

        }

        return response

    @jwt_required()
    @users_ns.expect(profile_update_model)
    @users_ns.marshal_with(profile_model)
    def put(self):
        """Update current user's profile"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        data = request.json

        # Update fields if provided
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'bio' in data:
            user.bio = data['bio']
        if 'location' in data:
            user.location = data['location']
        if 'website' in data:
            user.website = data['website']

        try:
            db.session.commit()

            # Calculate counts for response
            followers_count = user.followers.count()
            following_count = user.following.count()
            posts_count = user.posts.count()

            # Prepare response
            response = {
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'bio': user.bio,
                'location': user.location,
                'website': user.website,
                'profile_picture': user.profile_picture,
                'followers_count': followers_count,
                'following_count': following_count,
                'posts_count': posts_count,
                'date_joined': user.date_joined,
                'is_private': user.is_private
            }

            return response
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

@users_ns.route('.profile/<int:user_id>')
class UserProfileById(Resource):
    @jwt_required(optional = True)
    @users_ns.marshal_with(profile_model)
    def get(self, user_id):
        """Get a user's profile by ID"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)

        # check if profile is private and not followed by current user
        if user.is_private and current_user_id:
            current_user = User.query.get(current_user_id)
            if current_user and not current_user.is_following(user) and current_user_id != user_id:
                return {'message': 'This profile is private'}, 401
        elif user.is_private and not current_user_id:
            return {'message': 'This profile is private'}, 403

        # Calculate counts
        followers_count = user.followers.count()
        following_count = user.following.count()
        posts_count = user.posts.count()

        # Prepare response
        response = {
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'bio': user.bio,
            'location': user.location,
            'website': user.website,
            'profile_picture': user.profile_picture,
            'followers_count': followers_count,
            'following_count': following_count,
            'posts_count': posts_count,
            'date_joined': user.date_joined,
            'is_private': user.is_private
        }

        return response

@users_ns.route('privacy')
class PrivacySettings(Resource):
    @jwt_required()
    @users_ns.marshal_with(privacy_settings_model)
    def get(self):
        """Get current user;s privacy settings"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)

        return{
            'is_private': user.is_private,
            'allow_messages': user.allow_messages
        }
    @jwt_required()
    @users_ns.expect(privacy_settings_model)
    @users_ns.marshal_with(privacy_settings_model)
    def put(self):
        """Update current user's privacy settings"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        data = request.json

        if 'is_private' in data:
            user.is_private = data['is_private']
        if 'allow_messages' in data:
            user.allow_messages = data['allow_messages']

        try:
            db.session.commit()
            return {
                'is_private': user.is_private,
                'allow_messages': user.allow_messages
            }
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occured: {str(e)}'}, 500


@users_ns.route('/follow')
class FollowUser(Resource):
    @jwt_required()
    @users_ns.expect(follow_model)
    def post(self):
        """Follow a user"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get_or_404(current_user_id)

        target_user_id = request.json.get('user_id')
        if not target_user_id:
            return {'message': 'User ID is required'}, 400

        target_user = User.query.get_or_404(target_user_id)

        # Check if trying to follow self
        if current_user_id == target_user_id:
            return {'message': 'Cannot follow yourself'}, 400

        # Check if already following
        if current_user.is_following(target_user):
            return {'message': 'Already following this user'}, 409

        # Check if target user is private - create a pending request
        if target_user.is_private:
            existing_request = Relationship.query.filter_by(
                follower_id=current_user_id,
                followed_id=target_user_id,
                status='pending'
            ).first()

            if existing_request:
                return {'message': 'Follow request already sent'}, 409

            new_request = Relationship(
                follower_id=current_user_id,
                followed_id=target_user_id,
                status='pending'
            )

            try:
                db.session.add(new_request)
                db.session.commit()

                # Create notification for follow request
                notification = Notification(
                    user_id=target_user_id,
                    actor_id=current_user_id,
                    notification_type='follow_request',
                    message=f"{current_user.username} wants to follow you"
                )
                db.session.add(notification)
                db.session.commit()

                return {'message': 'Follow request sent'}, 200
            except Exception as e:
                db.session.rollback()
                return {'message': f'An error occurred: {str(e)}'}, 500
        else:
            # If user is public, follow directly
            if current_user.follow(target_user):
                try:
                    db.session.commit()

                    # Create notification for new follower
                    notification = Notification(
                        user_id=target_user_id,
                        actor_id=current_user_id,
                        notification_type='follow',
                        message=f"{current_user.username} started following you"
                    )
                    db.session.add(notification)
                    db.session.commit()

                    return {'message': 'Successfully followed user'}, 200
                except Exception as e:
                    db.session.rollback()
                    return {'message': f'An error occurred: {str(e)}'}, 500
            else:
                return {'message': 'Unable to follow user'}, 400


@users_ns.route('/unfollow')
class UnfollowUser(Resource):
    @jwt_required()
    @users_ns.expect(follow_model)
    def post(self):
        """Unfollow a user"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get_or_404(current_user_id)

        target_user_id = request.json.get('user_id')
        if not target_user_id:
            return {'message': 'User ID is required'}, 400

        target_user = User.query.get_or_404(target_user_id)

        # Check if already not following
        if not current_user.is_following(target_user):
            # Check if there's a pending request to cancel
            pending_request = Relationship.query.filter_by(
                follower_id=current_user_id,
                followed_id=target_user_id,
                status='pending'
            ).first()

            if pending_request:
                try:
                    db.session.delete(pending_request)
                    db.session.commit()
                    return {'message': 'Follow request canceled'}, 200
                except Exception as e:
                    db.session.rollback()
                    return {'message': f'An error occurred: {str(e)}'}, 500
            else:
                return {'message': 'Not following this user'}, 400

        # Unfollow the user
        if current_user.unfollow(target_user):
            try:
                db.session.commit()
                return {'message': 'Successfully unfollowed user'}, 200
            except Exception as e:
                db.session.rollback()
                return {'message': f'An error occurred: {str(e)}'}, 500
        else:
            return {'message': 'Unable to unfollow user'}, 400


@users_ns.route('/follow-requests')
class FollowRequests(Resource):
    @jwt_required()
    @users_ns.marshal_with(users_list_model)
    def get(self):
        """Get list of pending follow requests"""
        current_user_id = get_jwt_identity()

        # Get pending follow requests
        pending_requests = Relationship.query.filter_by(
            followed_id=current_user_id,
            status='pending'
        ).all()

        results = []
        for request in pending_requests:
            requester = User.query.get(request.follower_id)
            if requester:
                results.append({
                    'id': requester.id,
                    'username': requester.username,
                    'first_name': requester.first_name,
                    'last_name': requester.last_name,
                    'profile_picture': requester.profile_picture,
                    'is_private': requester.is_private,
                    'is_following': False,  # They requested to follow you
                    'is_followed_by': False  # You haven't accepted yet
                })

        return {
            'users': results,
            'total': len(results),
            'page': 1,
            'pages': 1,
            'per_page': len(results)
        }


@users_ns.route('/accept-follow')
class AcceptFollow(Resource):
    @jwt_required()
    @users_ns.expect(follow_model)
    def post(self):
        """Accept a follow request"""
        current_user_id = get_jwt_identity()

        follower_id = request.json.get('user_id')
        if not follower_id:
            return {'message': 'User ID is required'}, 400

        # Find the pending request
        pending_request = Relationship.query.filter_by(
            follower_id=follower_id,
            followed_id=current_user_id,
            status='pending'
        ).first()

        if not pending_request:
            return {'message': 'No pending follow request found'}, 404

        try:
            # Update the request status
            pending_request.status = 'accepted'

            # Create the follow relationship
            follower = User.query.get(follower_id)
            current_user = User.query.get(current_user_id)

            if not follower or not current_user:
                return {'message': 'User not found'}, 404

            if not follower.is_following(current_user):
                follower.follow(current_user)

            db.session.commit()

            # Create notification for request acceptance
            notification = Notification(
                user_id=follower_id,
                actor_id=current_user_id,
                notification_type='follow_accepted',
                message=f"{current_user.username} accepted your follow request"
            )
            db.session.add(notification)
            db.session.commit()

            return {'message': 'Follow request accepted'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@users_ns.route('/reject-follow')
class RejectFollow(Resource):
    @jwt_required()
    @users_ns.expect(follow_model)
    def post(self):
        """Reject a follow request"""
        current_user_id = get_jwt_identity()

        follower_id = request.json.get('user_id')
        if not follower_id:
            return {'message': 'User ID is required'}, 400

        # Find the pending request
        pending_request = Relationship.query.filter_by(
            follower_id=follower_id,
            followed_id=current_user_id,
            status='pending'
        ).first()

        if not pending_request:
            return {'message': 'No pending follow request found'}, 404

        try:
            # Delete the request
            db.session.delete(pending_request)
            db.session.commit()

            return {'message': 'Follow request rejected'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@users_ns.route('/followers')
class Followers(Resource):
    @jwt_required(optional=True)
    @users_ns.doc(params={'user_id': 'User ID (optional, defaults to current user)', 'page': 'Page number',
                          'per_page': 'Results per page'})
    @users_ns.marshal_with(users_list_model)
    def get(self):
        """Get list of user's followers"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        user_id = request.args.get('user_id', current_user_id, type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        user = User.query.get_or_404(user_id)

        # Check privacy if not the current user
        if user.is_private and current_user_id != user_id:
            if not current_user_id:
                return {'message': 'This profile is private'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user.is_following(user):
                return {'message': 'This profile is private'}, 403

        # Paginate followers
        pagination = user.followers.paginate(page=page, per_page=per_page)

        results = []
        for follower in pagination.items:
            # Check if current user is following this follower
            is_following = False
            is_followed_by = False

            if current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(follower)
                    is_followed_by = follower.is_following(current_user)

            results.append({
                'id': follower.id,
                'username': follower.username,
                'first_name': follower.first_name,
                'last_name': follower.last_name,
                'profile_picture': follower.profile_picture,
                'is_private': follower.is_private,
                'is_following': is_following,
                'is_followed_by': is_followed_by
            })

        return {
            'users': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@users_ns.route('/following')
class Following(Resource):
    @jwt_required(optional=True)
    @users_ns.doc(params={'user_id': 'User ID (optional, defaults to current user)', 'page': 'Page number',
                          'per_page': 'Results per page'})
    @users_ns.marshal_with(users_list_model)
    def get(self):
        """Get list of users followed by a user"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        user_id = request.args.get('user_id', current_user_id, type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        user = User.query.get_or_404(user_id)

        # Check privacy if not the current user
        if user.is_private and current_user_id != user_id:
            if not current_user_id:
                return {'message': 'This profile is private'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user.is_following(user):
                return {'message': 'This profile is private'}, 403

        # Paginate following
        pagination = user.following.paginate(page=page, per_page=per_page)

        results = []
        for followed in pagination.items:
            # Check if current user is following this user
            is_following = False
            is_followed_by = False

            if current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(followed)
                    is_followed_by = followed.is_following(current_user)

            results.append({
                'id': followed.id,
                'username': followed.username,
                'first_name': followed.first_name,
                'last_name': followed.last_name,
                'profile_picture': followed.profile_picture,
                'is_private': followed.is_private,
                'is_following': is_following,
                'is_followed_by': is_followed_by
            })

        return {
            'users': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@search_ns.route('/users')
class SearchUsers(Resource):
    @jwt_required(optional=True)
    @search_ns.doc(params={'q': 'Search query', 'page': 'Page number', 'per_page': 'Results per page'})
    @search_ns.marshal_with(users_list_model)
    def get(self):
        """Search for users by username or name"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        query = request.args.get('q', '')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        if not query:
            return {'message': 'Search query is required'}, 400

        # Search users with LIKE operator
        search_query = f"%{query}%"
        users_query = User.query.filter(
            db.or_(
                User.username.ilike(search_query),
                User.first_name.ilike(search_query),
                User.last_name.ilike(search_query)
            )
        )

        # Paginate results
        pagination = users_query.paginate(page=page, per_page=per_page)

        results = []
        for user in pagination.items:
            # Skip private users that aren't followed by current user
            if user.is_private and current_user_id and current_user_id != user.id:
                current_user = User.query.get(current_user_id)
                if not current_user or not current_user.is_following(user):
                    continue
            elif user.is_private and not current_user_id:
                continue

            # Check relationship with current user
            is_following = False
            is_followed_by = False

            if current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(user)
                    is_followed_by = user.is_following(current_user)

            results.append({
                'id': user.id,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'profile_picture': user.profile_picture,
                'is_private': user.is_private,
                'is_following': is_following,
                'is_followed_by': is_followed_by
            })

        return {
            'users': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@users_ns.route('/profile-picture')
class ProfilePicture(Resource):
    @jwt_required()
    def post(self):
        """Upload profile picture"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)

        # Check if file is present
        if 'file' not in request.files:
            return {'message': 'No file provided'}, 400

        file = request.files['file']

        # Check if file is valid
        if file.filename == '':
            return {'message': 'No file selected'}, 400

        if not allowed_file(file.filename):
            return {'message': 'File type not allowed. Please upload an image (png, jpg, jpeg, gif)'}, 400

        # Generate unique filename to prevent collisions
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            # Save the file
            file.save(file_path)

            # Update user's profile picture
            user.profile_picture = f"/media/profile/{unique_filename}"
            db.session.commit()

            return {'message': 'Profile picture updated successfully', 'url': user.profile_picture}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

@media_ns.route('/profile/<path:filename>')
class GetProfilePicture(Resource):
    def get(self, filename):
        """Get profile picture"""
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Post creation model
post_create_model = posts_ns.model('PostCreate', {
    'content': fields.String(required=True, description='Post content/caption'),
    'visibility': fields.String(required=False, default='public', enum=['public', 'followers', 'private'], description='Post visibility'),
    'media_id': fields.Integer(required=False, description='ID of previously uploaded media')
})

# Post update model
post_update_model = posts_ns.model('PostUpdate', {
    'content': fields.String(required=False, description='Updated post content/caption'),
    'visibility': fields.String(required=False, enum=['public', 'followers', 'private'], description='Updated post visibility')
})

# Post response model
post_model = posts_ns.model('Post', {
    'id': fields.Integer(description='Post ID'),
    'content': fields.String(description='Post content/caption'),
    'created_at': fields.DateTime(description='Post creation time'),
    'updated_at': fields.DateTime(description='Post last update time'),
    'visibility': fields.String(description='Post visibility'),
    'likes_count': fields.Integer(description='Number of likes on the post'),
    'comments_count': fields.Integer(description='Number of comments on the post'),
    'media_url': fields.String(description='URL to media, if any'),
    'media_type': fields.String(description='Type of media'),
    'author': fields.Nested(users_ns.models['UserInfo'], description='Post author information'),
    'current_user_liked': fields.Boolean(description='Whether current user liked this post')
})


# Posts list model
posts_list_model = posts_ns.model('PostsList', {
    'posts': fields.List(fields.Nested(post_model)),
    'total': fields.Integer(description='Total number of results'),
    'page': fields.Integer(description='Current page number'),
    'pages': fields.Integer(description='Total number of pages'),
    'per_page': fields.Integer(description='Results per page')
})

# Media upload response model
media_upload_model = media_ns.model('MediaUpload', {
    'id': fields.Integer(description='Media ID'),
    'media_url': fields.String(description='URL to the uploaded media'),
    'media_type': fields.String(description='Type of media'),
    'size': fields.Integer(description='Size of media in bytes'),
    'upload_time': fields.DateTime(description='Upload timestamp')
})

# Hashtag model
hashtag_model = posts_ns.model('Hashtag', {
    'id': fields.Integer(description='Hashtag ID'),
    'name': fields.String(description='Hashtag name'),
    'posts_count': fields.Integer(description='Number of posts with this hashtag')
})

# Hashtags list model
hashtags_list_model = posts_ns.model('HashtagsList', {
    'hashtags': fields.List(fields.Nested(hashtag_model)),
    'total': fields.Integer(description='Total number of results'),
    'page': fields.Integer(description='Current page number'),
    'pages': fields.Integer(description='Total number of pages'),
    'per_page': fields.Integer(description='Results per page')
})


# Now let's implement the Hashtags model
class Hashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Hashtag id={self.id} name={self.name}>"


# Post-Hashtag association table
post_hashtags = db.Table('post_hashtags',
                         db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
                         db.Column('hashtag_id', db.Integer, db.ForeignKey('hashtag.id'), primary_key=True),
                         db.Column('created_at', db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
                         )

Post.hashtags = db.relationship('Hashtag', secondary=post_hashtags, backref=db.backref('posts', lazy='dynamic'))

# Helper function to extract hashtags from post content
def extract_hashtags(content):
    """Extract hashtags from post content and return a list of hashtag names"""
    hashtag_pattern = re.compile(r'#(\w+)')
    return hashtag_pattern.findall(content)

# Function to create or get existing hashtags
def get_or_create_hashtags(hashtag_names):
    """Get existing hashtags or create new ones for the given names"""
    hashtags = []
    for name in hashtag_names:
        hashtag = Hashtag.query.filter_by(name=name.lower()).first()
        if not hashtag:
            hashtag = Hashtag(name=name.lower())
            db.session.add(hashtag)
        hashtags.append(hashtag)
    return hashtags

# api endpoints
@media_ns.route('/upload')
class MediaUpload(Resource):
    @jwt_required()
    @media_ns.doc(params={'file': 'Media file to upload'})
    @media_ns.marshal_with(media_upload_model)
    def post(self):
        """Upload media (image or video)"""
        current_user_id = get_jwt_identity()

        # Check if file is present
        if 'file' not in request.files:
            return {'message': 'No file provided'}, 400

        file = request.files['file']

        # Check if file is valid
        if file.filename == '':
            return {'message': 'No file selected'}, 400

        if not allowed_file(file.filename):
            return {'message': 'File type not allowed. Please upload an image (png, jpg, jpeg, gif)'}, 400

        # Generate unique filename to prevent collisions
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        try:
            # Save the file
            file.save(file_path)

            # Determine media type
            media_type = filename.rsplit('.', 1)[1].lower()

            # Create media record
            media = MediaFile(
                user_id=current_user_id,
                filename=unique_filename,
                media_type=media_type,
                size=os.path.getsize(file_path)
            )

            db.session.add(media)
            db.session.commit()

            return {
                'id': media.id,
                'media_url': f"/media/content/{unique_filename}",
                'media_type': media.media_type,
                'size': media.size,
                'upload_time': media.upload_time
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

@media_ns.route('/content/<path:filename>')
class GetMedia(Resource):
    def get(self, filename):
        """Get uploaded media"""
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@posts_ns.route('/')
class PostsResource(Resource):
    @jwt_required()
    @posts_ns.expect(post_create_model)
    @posts_ns.marshal_with(post_model)
    def post(self):
        """Create a new post"""
        current_user_id = get_jwt_identity()
        user = User.query.get_or_404(current_user_id)
        data = request.json

        content = data.get('content', '').strip()
        visibility = data.get('visibility', 'public')
        media_id = data.get('media_id')

        if not content and not media_id:
            return {'message': 'Post must contain either text content or media'}, 400

        # Create post
        new_post = Post(
            content=content,
            user_id=current_user_id,
            visibility=visibility
        )

        # Associate media if provided
        if media_id:
            media = MediaFile.query.filter_by(id=media_id, user_id=current_user_id).first()
            if not media:
                return {'message': 'Media not found or does not belong to you'}, 404

            new_post.media_url = f"/media/content/{media.filename}"
            new_post.media_type = media.media_type
            media.post_id = new_post.id

        try:
            db.session.add(new_post)
            db.session.flush()  # To get the post ID before commit

            # Process hashtags if present
            if content:
                hashtag_names = extract_hashtags(content)
                if hashtag_names:
                    hashtags = get_or_create_hashtags(hashtag_names)
                    new_post.hashtags = hashtags

            db.session.commit()

            # Format response
            return {
                'id': new_post.id,
                'content': new_post.content,
                'created_at': new_post.created_at,
                'updated_at': new_post.updated_at,
                'visibility': new_post.visibility,
                'likes_count': 0,
                'comments_count': 0,
                'media_url': new_post.media_url,
                'media_type': new_post.media_type,
                'author': {
                    'id': user.id,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'profile_picture': user.profile_picture,
                    'is_private': user.is_private,
                    'is_following': False,
                    'is_followed_by': False
                },
                'current_user_liked': False
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

    @jwt_required(optional=True)
    @posts_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @posts_ns.marshal_with(posts_list_model)
    def get(self):
        """Get posts feed (personalized if authenticated)"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Base query for public posts
        base_query = Post.query.filter_by(visibility='public')

        # If user is authenticated, enhance the feed
        if current_user_id:
            current_user = User.query.get(current_user_id)

            if current_user:
                # Include posts from followed users (regardless of visibility)
                followed_users_ids = [user.id for user in current_user.following]

                if followed_users_ids:
                    # Show public posts + posts from followed users (with appropriate visibility)
                    base_query = Post.query.filter(
                        db.or_(
                            Post.visibility == 'public',
                            db.and_(
                                Post.user_id.in_(followed_users_ids),
                                db.or_(
                                    Post.visibility == 'public',
                                    Post.visibility == 'followers'
                                )
                            ),
                            # Include user's own posts
                            Post.user_id == current_user_id
                        )
                    )

        # Order by creation date (newest first)
        posts_query = base_query.order_by(Post.created_at.desc())

        # Paginate results
        pagination = posts_query.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Get author info
            author = User.query.get(post.user_id)

            # Check if current user liked the post
            current_user_liked = False
            if current_user_id:
                like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
                current_user_liked = like is not None

            # Check following status if authenticated
            is_following = False
            is_followed_by = False
            if current_user_id and author.id != current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(author)
                    is_followed_by = author.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked
            })

        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@posts_ns.route('/<int:post_id>')
class PostResource(Resource):
    @jwt_required(optional=True)
    @posts_ns.marshal_with(post_model)
    def get(self, post_id):
        """Get a specific post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)
        author = User.query.get(post.user_id)

        # Check visibility permissions
        if post.visibility == 'private' and (not current_user_id or current_user_id != author.id):
            return {'message': 'This post is private'}, 403

        elif post.visibility == 'followers' and current_user_id != author.id:
            if not current_user_id:
                return {'message': 'This post is only visible to followers'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            if not current_user_id:
                return {'message': 'This post belongs to a private account'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        # Check if current user liked the post
        current_user_liked = False
        if current_user_id:
            like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
            current_user_liked = like is not None

        # Check following status if authenticated
        is_following = False
        is_followed_by = False
        if current_user_id and author.id != current_user_id:
            current_user = User.query.get(current_user_id)
            if current_user:
                is_following = current_user.is_following(author)
                is_followed_by = author.is_following(current_user)

        return {
            'id': post.id,
            'content': post.content,
            'created_at': post.created_at,
            'updated_at': post.updated_at,
            'visibility': post.visibility,
            'likes_count': post.likes.count(),
            'comments_count': post.comments.count(),
            'media_url': post.media_url,
            'media_type': post.media_type,
            'author': {
                'id': author.id,
                'username': author.username,
                'first_name': author.first_name,
                'last_name': author.last_name,
                'profile_picture': author.profile_picture,
                'is_private': author.is_private,
                'is_following': is_following,
                'is_followed_by': is_followed_by
            },
            'current_user_liked': current_user_liked
        }

    @jwt_required()
    @posts_ns.expect(post_update_model)
    @posts_ns.marshal_with(post_model)
    def put(self, post_id):
        """Update a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check if user is the author
        if post.user_id != current_user_id:
            return {'message': 'You can only edit your own posts'}, 403

        data = request.json

        # Update fields if provided
        if 'content' in data:
            post.content = data['content'].strip()

            # Re-process hashtags if content changed
            if post.hashtags:
                # Remove old hashtag associations
                post.hashtags = []

            hashtag_names = extract_hashtags(post.content)
            if hashtag_names:
                hashtags = get_or_create_hashtags(hashtag_names)
                post.hashtags = hashtags

        if 'visibility' in data:
            post.visibility = data['visibility']

        try:
            # Update timestamp
            post.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            # Get author info
            author = User.query.get(post.user_id)

            return {
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': False,
                    'is_followed_by': False
                },
                'current_user_liked': False  # The user is the author, so they can't like their own post
            }
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

    @jwt_required()
    def delete(self, post_id):
        """Delete a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check if user is the author or an admin
        user = User.query.get(current_user_id)
        if post.user_id != current_user_id and not user.is_admin:
            return {'message': 'You can only delete your own posts'}, 403

        try:
            # Remove hashtag associations
            if post.hashtags:
                post.hashtags = []

            # Delete the post
            db.session.delete(post)
            db.session.commit()

            return {'message': 'Post deleted successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@posts_ns.route('/user/<int:user_id>')
class UserPosts(Resource):
    @jwt_required(optional=True)
    @posts_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @posts_ns.marshal_with(posts_list_model)
    def get(self, user_id):
        """Get posts by a specific user"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        user = User.query.get_or_404(user_id)

        # Check if profile is private
        if user.is_private and current_user_id != user_id:
            if not current_user_id:
                return {'message': 'This profile is private'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(user):
                return {'message': 'This profile is private'}, 403

        # Build post query based on visibility permissions
        if current_user_id == user_id:
            # User can see all their own posts
            posts_query = Post.query.filter_by(user_id=user_id)
        else:
            # Others can see public posts plus followers-only if they're following
            visibility_filters = ['public']
            if current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user and current_user.is_following(user):
                    visibility_filters.append('followers')

            posts_query = Post.query.filter(
                Post.user_id == user_id,
                Post.visibility.in_(visibility_filters)
            )

        # Order by creation date (newest first)
        posts_query = posts_query.order_by(Post.created_at.desc())

        # Paginate results
        pagination = posts_query.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Check if current user liked the post
            current_user_liked = False
            if current_user_id:
                like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
                current_user_liked = like is not None

            # Check following status if authenticated
            is_following = False
            is_followed_by = False
            if current_user_id and user.id != current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(user)
                    is_followed_by = user.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': user.id,
                    'username': user.username,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'profile_picture': user.profile_picture,
                    'is_private': user.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked
            })

        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@posts_ns.route('/like/<int:post_id>')
class LikePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Like a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)
        author = User.query.get(post.user_id)

        # Check visibility permissions
        if post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private'}, 403

        elif post.visibility == 'followers' and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        # Check if already liked
        existing_like = Like.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if existing_like:
            return {'message': 'Post already liked'}, 409

        try:
            # Create like
            new_like = Like(user_id=current_user_id, post_id=post_id)
            db.session.add(new_like)

            # Create notification for post author if not self
            if current_user_id != author.id:
                current_user = User.query.get(current_user_id)
                notification = Notification(
                    user_id=author.id,
                    actor_id=current_user_id,
                    notification_type='like',
                    target_id=post_id,
                    target_type='post',
                    message=f"{current_user.username} liked your post"
                )
                db.session.add(notification)

            db.session.commit()

            return {'message': 'Post liked successfully', 'likes_count': post.likes.count()}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@posts_ns.route('/unlike/<int:post_id>')
class UnlikePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Unlike a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check if liked
        existing_like = Like.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if not existing_like:
            return {'message': 'Post not liked'}, 400

        try:
            # Remove like
            db.session.delete(existing_like)
            db.session.commit()

            return {'message': 'Post unliked successfully', 'likes_count': post.likes.count()}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@posts_ns.route('/discover')
class DiscoverPosts(Resource):
    @jwt_required(optional=True)
    @posts_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @posts_ns.marshal_with(posts_list_model)
    def get(self):
        """Discover posts (trending or recommended)"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Start with public posts only
        base_query = Post.query.filter_by(visibility='public')

        if current_user_id:
            # For logged-in users, exclude posts from blocked users
            # (This would require implementing a blocked users system)
            pass

        # For a simple discover feed, get posts with most interactions recently
        # More sophisticated recommendation systems would need separate services
        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        popular_posts = base_query.filter(Post.created_at >= one_week_ago).join(Like).group_by(Post.id).order_by(
            db.func.count(Like.id).desc(),
            db.func.count(Comment.id).desc(),
            Post.created_at.desc()
        )

        # Paginate results
        pagination = popular_posts.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Get author info
            author = User.query.get(post.user_id)

            # Check if current user liked the post
            current_user_liked = False
            if current_user_id:
                like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
                current_user_liked = like is not None

            # Check following status if authenticated
            is_following = False
            is_followed_by = False
            if current_user_id and author.id != current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(author)
                    is_followed_by = author.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'author':{
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked

            })
        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }

@posts_ns.route('/hashtag/<string:hashtag_name>')
class HashtagPosts(Resource):
    @jwt_required(optional=True)
    @posts_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @posts_ns.marshal_with(posts_list_model)
    def get(self, hashtag_name):
        """Get posts with a specific hashtag"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Find hashtag (case insensitive)
        hashtag = Hashtag.query.filter(func.lower(Hashtag.name) == func.lower(hashtag_name)).first()
        if not hashtag:
            return {'message': 'Hashtag not found'}, 404

        # Get posts with this hashtag that the user has permission to view
        base_query = Post.query.join(post_hashtags).join(Hashtag).filter(
            Hashtag.id == hashtag.id
        )

        # Filter based on visibility and user authentication
        if current_user_id:
            current_user = User.query.get(current_user_id)
            if current_user:
                # Get IDs of users the current user follows
                followed_users_ids = [user.id for user in current_user.following]

                base_query = base_query.filter(
                    db.or_(
                        # Public posts
                        Post.visibility == 'public',

                        # Followers-only posts from followed users
                        db.and_(
                            Post.user_id.in_(followed_users_ids),
                            Post.visibility == 'followers'
                        ),

                        # User's own posts
                        Post.user_id == current_user_id
                    )
                )
        else:
            # Only public posts for unauthenticated users
            base_query = base_query.filter(Post.visibility == 'public')

        # Additionally filter out posts from private accounts unless following
        if current_user_id:
            # No filter needed for user's own posts
            private_users_query = User.query.filter(
                User.is_private == True,
                User.id != current_user_id
            )

            # Exclude posts from private users that the current user doesn't follow
            private_users_not_followed = [
                u.id for u in private_users_query.all()
                if u.id not in [user.id for user in current_user.following]
            ]

            if private_users_not_followed:
                base_query = base_query.filter(~Post.user_id.in_(private_users_not_followed))
        else:
            # For anonymous users, exclude all posts from private accounts
            private_users = [u.id for u in User.query.filter_by(is_private=True).all()]
            if private_users:
                base_query = base_query.filter(~Post.user_id.in_(private_users))

        # Order by creation date (newest first)
        posts_query = base_query.order_by(Post.created_at.desc())

        # Paginate results
        pagination = posts_query.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Get author info
            author = User.query.get(post.user_id)

            # Check if current user liked the post
            current_user_liked = False
            if current_user_id:
                like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
                current_user_liked = like is not None

            # Check following status if authenticated
            is_following = False
            is_followed_by = False
            if current_user_id and author.id != current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(author)
                    is_followed_by = author.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked
            })

        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@posts_ns.route('/trending-hashtags')
class TrendingHashtags(Resource):
    @jwt_required(optional=True)
    @posts_ns.doc(params={'limit': 'Maximum number of hashtags to return'})
    @posts_ns.marshal_with(hashtags_list_model)
    def get(self):
        """Get trending hashtags based on recent activity"""
        # Get query parameters
        limit = request.args.get('limit', 10, type=int)

        # Calculate trending over the past week
        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)

        # Get hashtags with most posts in the past week
        trending_hashtags = db.session.query(
            Hashtag,
            db.func.count(post_hashtags.c.post_id).label('post_count')
        ).join(
            post_hashtags
        ).join(
            Post
        ).filter(
            post_hashtags.c.created_at >= one_week_ago,
            # Only count public posts
            Post.visibility == 'public'
        ).group_by(
            Hashtag.id
        ).order_by(
            db.desc('post_count'),
            Hashtag.name
        ).limit(limit).all()

        results = []
        for hashtag, post_count in trending_hashtags:
            results.append({
                'id': hashtag.id,
                'name': hashtag.name,
                'posts_count': post_count
            })

        return {
            'hashtags': results,
            'total': len(results),
            'page': 1,
            'pages': 1,
            'per_page': limit
        }


@posts_ns.route('/search')
class PostSearch(Resource):
    @jwt_required(optional=True)
    @posts_ns.doc(params={
        'q': 'Search query',
        'page': 'Page number',
        'per_page': 'Results per page'
    })
    @posts_ns.marshal_with(posts_list_model)
    def get(self):
        """Search for posts by content"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        query = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        if not query:
            return {'message': 'Search query is required'}, 400

        # Search posts by content
        # Using ILIKE for case-insensitive search
        base_query = Post.query.filter(Post.content.ilike(f'%{query}%'))

        # Filter based on visibility and user authentication
        if current_user_id:
            current_user = User.query.get(current_user_id)
            if current_user:
                # Get IDs of users the current user follows
                followed_users_ids = [user.id for user in current_user.following]

                base_query = base_query.filter(
                    db.or_(
                        # Public posts
                        Post.visibility == 'public',

                        # Followers-only posts from followed users
                        db.and_(
                            Post.user_id.in_(followed_users_ids),
                            Post.visibility == 'followers'
                        ),

                        # User's own posts
                        Post.user_id == current_user_id
                    )
                )
        else:
            # Only public posts for unauthenticated users
            base_query = base_query.filter(Post.visibility == 'public')

        # Additionally filter out posts from private accounts unless following
        if current_user_id:
            # No filter needed for user's own posts
            private_users_query = User.query.filter(
                User.is_private == True,
                User.id != current_user_id
            )

            # Exclude posts from private users that the current user doesn't follow
            private_users_not_followed = [
                u.id for u in private_users_query.all()
                if u.id not in [user.id for user in current_user.following]
            ]

            if private_users_not_followed:
                base_query = base_query.filter(~Post.user_id.in_(private_users_not_followed))
        else:
            # For anonymous users, exclude all posts from private accounts
            private_users = [u.id for u in User.query.filter_by(is_private=True).all()]
            if private_users:
                base_query = base_query.filter(~Post.user_id.in_(private_users))

        # Order by relevance and then by date
        # For more sophisticated relevance ranking, consider using a search engine like Elasticsearch
        posts_query = base_query.order_by(
            # Exact matches first
            db.case([(Post.content.ilike(f'{query}'), 0)], else_=1),
            # Posts with query in the beginning next
            db.case([(Post.content.ilike(f'{query}%'), 0)], else_=1),
            # Then by creation date
            Post.created_at.desc()
        )

        # Paginate results
        pagination = posts_query.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Get author info
            author = User.query.get(post.user_id)

            # Check if current user liked the post
            current_user_liked = False
            if current_user_id:
                like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
                current_user_liked = like is not None

            # Check following status if authenticated
            is_following = False
            is_followed_by = False
            if current_user_id and author.id != current_user_id:
                current_user = User.query.get(current_user_id)
                if current_user:
                    is_following = current_user.is_following(author)
                    is_followed_by = author.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked
            })

        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@posts_ns.route('/saved')
class SavedPosts(Resource):
    @jwt_required()
    @posts_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @posts_ns.marshal_with(posts_list_model)
    def get(self):
        """Get current user's saved posts"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Get saved posts for the current user
        saved_posts_query = Post.query.join(SavedPost).filter(
            SavedPost.user_id == current_user_id
        ).order_by(SavedPost.saved_at.desc())

        # Paginate results
        pagination = saved_posts_query.paginate(page=page, per_page=per_page)

        results = []
        for post in pagination.items:
            # Get author info
            author = User.query.get(post.user_id)

            # Check if current user liked the post
            like = Like.query.filter_by(user_id=current_user_id, post_id=post.id).first()
            current_user_liked = like is not None

            # Check following status
            is_following = False
            is_followed_by = False
            if author.id != current_user_id:
                current_user = User.query.get(current_user_id)
                is_following = current_user.is_following(author)
                is_followed_by = author.is_following(current_user)

            results.append({
                'id': post.id,
                'content': post.content,
                'created_at': post.created_at,
                'updated_at': post.updated_at,
                'visibility': post.visibility,
                'likes_count': post.likes.count(),
                'comments_count': post.comments.count(),
                'media_url': post.media_url,
                'media_type': post.media_type,
                'author': {
                    'id': author.id,
                    'username': author.username,
                    'first_name': author.first_name,
                    'last_name': author.last_name,
                    'profile_picture': author.profile_picture,
                    'is_private': author.is_private,
                    'is_following': is_following,
                    'is_followed_by': is_followed_by
                },
                'current_user_liked': current_user_liked
            })

        return {
            'posts': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }


@posts_ns.route('/save/<int:post_id>')
class SavePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Save a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check visibility permissions first
        author = User.query.get(post.user_id)

        # Check visibility permissions
        if post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private'}, 403

        elif post.visibility == 'followers' and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        # Check if already saved
        existing_save = SavedPost.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if existing_save:
            return {'message': 'Post already saved'}, 409

        try:
            # Create saved post record
            saved_post = SavedPost(user_id=current_user_id, post_id=post_id)
            db.session.add(saved_post)
            db.session.commit()

            return {'message': 'Post saved successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@posts_ns.route('/unsave/<int:post_id>')
class UnsavePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Unsave a post"""
        current_user_id = get_jwt_identity()

        # Check if saved
        saved_post = SavedPost.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if not saved_post:
            return {'message': 'Post not saved'}, 400

        try:
            # Remove saved post record
            db.session.delete(saved_post)
            db.session.commit()

            return {'message': 'Post unsaved successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


# Add SavedPost model if it doesn't already exist
class SavedPost(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), primary_key=True)
    saved_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('saved_posts', lazy='dynamic'))
    post = db.relationship('Post', backref=db.backref('saved_by', lazy='dynamic'))

    def __repr__(self):
        return f"<SavedPost user_id={self.user_id} post_id={self.post_id}>"

# Models for API documentation and response marshalling
comment_model = comments_ns.model('Comment', {
    'id': fields.Integer(readonly=True),
    'content': fields.String(required=True),
    'created_at': fields.DateTime(readonly=True),
    'updated_at': fields.DateTime(readonly=True),
    'user_id': fields.Integer(readonly=True),
    'post_id': fields.Integer(readonly=True),
    'author': fields.Nested(comments_ns.model('CommentAuthor', {
        'id': fields.Integer(readonly=True),
        'username': fields.String(readonly=True),
        'profile_picture': fields.String(readonly=True)
    }))
})

comments_list_model = comments_ns.model('CommentsList', {
    'comments': fields.List(fields.Nested(comment_model)),
    'total': fields.Integer,
    'page': fields.Integer,
    'pages': fields.Integer,
    'per_page': fields.Integer
})

notification_model = notifications_ns.model('Notification', {
    'id': fields.Integer(readonly=True),
    'type': fields.String(readonly=True, description='Type of notification (like, comment, follow, etc.)'),
    'is_read': fields.Boolean(readonly=True),
    'created_at': fields.DateTime(readonly=True),
    'source_id': fields.Integer(readonly=True, description='ID of the user who triggered the notification'),
    'source_user': fields.Nested(notifications_ns.model('NotificationSourceUser', {
        'id': fields.Integer(readonly=True),
        'username': fields.String(readonly=True),
        'profile_picture': fields.String(readonly=True)
    })),
    'post_id': fields.Integer(readonly=True, description='ID of the related post, if applicable'),
    'comment_id': fields.Integer(readonly=True, description='ID of the related comment, if applicable')
})

notifications_list_model = notifications_ns.model('NotificationsList', {
    'notifications': fields.List(fields.Nested(notification_model)),
    'total': fields.Integer,
    'page': fields.Integer,
    'pages': fields.Integer,
    'per_page': fields.Integer,
    'unread_count': fields.Integer
})


@comments_ns.route('/posts/<int:post_id>/like')
class LikePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Like a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check visibility permissions
        author = User.query.get(post.user_id)

        # Check if post is private
        if post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private'}, 403

        # Check if post is followers-only
        elif post.visibility == 'followers' and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        # Check if already liked
        existing_like = Like.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if existing_like:
            return {'message': 'Post already liked'}, 409

        try:
            # Create like record
            like = Like(user_id=current_user_id, post_id=post_id)
            db.session.add(like)

            # Create notification for post author (if not self-like)
            if current_user_id != author.id:
                notification = Notification(
                    user_id=post.user_id,
                    source_id=current_user_id,
                    type='like',
                    post_id=post_id
                )
                db.session.add(notification)

            db.session.commit()
            return {'message': 'Post liked successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


@comments_ns.route('/posts/<int:post_id>/unlike')
class UnlikePost(Resource):
    @jwt_required()
    def post(self, post_id):
        """Unlike a post"""
        current_user_id = get_jwt_identity()

        # Check if liked
        like = Like.query.filter_by(user_id=current_user_id, post_id=post_id).first()
        if not like:
            return {'message': 'Post not liked'}, 400

        try:
            # Remove like record
            db.session.delete(like)

            # Remove the associated notification (optional)
            # Only if you want to remove notifications when unliking
            post = Post.query.get(post_id)
            if post and current_user_id != post.user_id:
                notification = Notification.query.filter_by(
                    user_id=post.user_id,
                    source_id=current_user_id,
                    type='like',
                    post_id=post_id
                ).first()

                if notification:
                    db.session.delete(notification)

            db.session.commit()
            return {'message': 'Post unliked successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500




comments_ns.route('/posts/<int:post_id>/comments')
class PostComments(Resource):
    @jwt_required(optional=True)
    @comments_ns.doc(params={'page': 'Page number', 'per_page': 'Results per page'})
    @comments_ns.marshal_with(comments_list_model)
    def get(self, post_id):
        """Get comments for a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check visibility permissions
        author = User.query.get(post.user_id)

        # Check if post is private
        if post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private'}, 403

        # Check if post is followers-only
        elif post.visibility == 'followers' and current_user_id != author.id:
            if not current_user_id:
                return {'message': 'This post is only visible to followers'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            if not current_user_id:
                return {'message': 'This post belongs to a private account'}, 403

            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Get comments for the post
        comments_query = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.asc())

        # Paginate results
        pagination = comments_query.paginate(page=page, per_page=per_page)

        results = []
        for comment in pagination.items:
            # Get author info
            comment_author = User.query.get(comment.user_id)

            results.append({
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at,
                'updated_at': comment.updated_at,
                'user_id': comment.user_id,
                'post_id': comment.post_id,
                'author': {
                    'id': comment_author.id,
                    'username': comment_author.username,
                    'profile_picture': comment_author.profile_picture
                }
            })

        return {
            'comments': results,
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
            'per_page': pagination.per_page
        }

    @jwt_required()
    @comments_ns.expect(comments_ns.model('NewComment', {
        'content': fields.String(required=True, description='Comment content')
    }))
    @comments_ns.marshal_with(comment_model)
    def post(self, post_id):
        """Create a new comment on a post"""
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # Check visibility permissions
        author = User.query.get(post.user_id)

        # Check if post is private
        if post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private'}, 403

        # Check if post is followers-only
        elif post.visibility == 'followers' and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post belongs to a private account'}, 403

        data = request.json
        content = data.get('content')

        if not content or not content.strip():
            return {'message': 'Comment content is required'}, 400

        try:
            # Create comment
            comment = Comment(
                content=content.strip(),
                user_id=current_user_id,
                post_id=post_id
            )
            db.session.add(comment)

            # Create notification for post author (if not self-comment)
            if current_user_id != author.id:
                notification = Notification(
                    user_id=post.user_id,
                    source_id=current_user_id,
                    type='comment',
                    post_id=post_id,
                    comment_id=comment.id  # This will be set after commit
                )
                db.session.add(notification)

            db.session.commit()

            # If notification was created, update the comment_id
            if current_user_id != author.id:
                notification.comment_id = comment.id
                db.session.commit()

            comment_author = User.query.get(current_user_id)

            return {
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at,
                'updated_at': comment.updated_at,
                'user_id': comment.user_id,
                'post_id': comment.post_id,
                'author': {
                    'id': comment_author.id,
                    'username': comment_author.username,
                    'profile_picture': comment_author.profile_picture
                }
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500
@comments_ns.route('/comments/<int:comment_id>')
class CommentResource(Resource):
    @jwt_required()
    @comments_ns.expect(comments_ns.model('UpdateComment',{
        'content': fields.String(required=True, description='Updated comment content')
    }))
    @comments_ns.marshal_with(comment_model)
    def put(self, comment_id):
        """update a comment"""
        current_user_id = get_jwt_identity()
        comment = Comment.query.get_or_404(comment_id)

        if comment.user_id != current_user_id:
            return {'message': 'Not authoriszed to update this comment'}, 403

        data = request.json
        content = data.get('content')

        if not content or not content.strip():
            return {'message': 'Comment content is required'}, 400

        try:
            comment.content = content.strip()
            comment.updated_at = datetime.now(timezone.utc)
            db.session.commit()

            comment_author = User.query.get(current_user_id)

            return{
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at,
                'updated_at': comment.updated_at,
                'user_id': comment.user_id,
                'post_id': comment.post_id,
                'author': {
                    'id': comment_author.id,
                    'username': comment_author.username,
                    'profile_picture': comment_author.profile_picture
                }
            },200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occured: {str(e)}'}, 500

    @jwt_required()
    def delete(self, comment_id):
        """Delete a comment"""
        current_user_id = get_jwt_identity()
        comment = Comment.querry.get_or_404(comment_id)

        # Check if the user is the comment author or the post owner
        post = Post.query.get(comment.post_id)
        if comment.user_id != current_user_id and post.user_id != current_user_id:
            return {'message' : 'Not authorized to delete this comment'}, 403

        try:
            # Delete related notifications
            notifications = Notification.query.filter_by(comment_id=comment_id).all()
            for notification in notifications:
                db.session.delete(notification)

                # delete the comment
                db.session.delete(comment)
                db.session.commit()

                return {'message': 'Comment deleted successfully'}, 200
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500


# Content sharing

@comments_ns.route('/posts/<int:post_id>/share')
class SharePost(Resource):
    @jwt_required()
    @comments_ns.expect(comments_ns.model('SharePost',{
        'content': fields.String(description = 'Additional content for the shared post'),
        'visibility': fields.String(description = 'Visibility of the shared post', enum=['public', 'followers', 'private'])
    }))
    def post(self, post_id):
        """Share a post (create a new post that references the original)"""
        current_user_id = get_jwt_identity()
        original_post = Post.query.get_or_404(post_id)

        #check visibility permission
        author = User.query.get(original_post.user_id)

        if original_post.visibility == 'private' and current_user_id != author.id:
            return {'message': 'This post is private and cannot be shared'}, 403

        # Check if post is followers only
        elif original_post.visibility == 'followers' and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return {'message': 'This post is only visible to followers and cannot be shared'}, 403

        # Check if author profile is private
        if author.is_private and current_user_id != author.id:
            current_user = User.query.get(current_user_id)
            if not current_user or not current_user.is_following(author):
                return{'message': 'This post belongs to a private account and cannot be shared'}, 403

        data = request.json or {}
        content = data.get('content', '')
        visibility = data.get('visibility', 'public')

        if visibility not in ['public', 'followers', 'private']:
            return {'message': 'invalid visibility option'}, 400

        try:
            shared_post = Post(
                content = content,
                user_id=current_user_id,
                visibility=visibility,
                shared_from=post_id
            )
            db.session.add(shared_post)

            # Create notification for original post author (if not self-share)
            if current_user_id != author.id:
                notification = Notification(
                    user_id=original_post.user_id,
                    source_id=current_user_id,
                    type='share',
                    post_id = post_id
                )
                db.session.add(notification)

            db.session.commit()

            return{
                'message': 'Post shared successfully',
                'post_id': shared_post.id
            }, 201
        except Exception as e:
            db.session.rollback()
            return{'message': f'An error occured: {str(e)}'}, 500


@comments_ns.route('/posts/<int:post_id>/is_saved')
class IsPostSaved(Resource):
    @jwt_required()
    def get(self, post_id):
        """Check if a post is saved by the current user"""
        current_user_id = get_jwt_identity()

        saved_post = SavedPost.query.filter_by(user_id = current_user_id, post_id=post_id).first()

        return{
            'is_saved': saved_post is not None
        }, 200


@comments_ns.route('/')
class NotificationList(Resource):
    @jwt_required()
    @notifications_ns.doc(params={
        'page': 'Page number',
        'per_page': 'Results per page',
        'unread_only': 'Filter to show only unreard notifications'
    })
    @notifications_ns.marshal_with(notifications_list_model)
    def get(self):
        """Get current user's notifications"""
        current_user_id = get_jwt_identity()

        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        unread_only = request.args.get('unread_only', False, type=lambda v: v.lower() == 'true')

        # Build the query
        query = Notification.query.filter_by(user_id=current_user_id)

        # Filter unread if requested
        if unread_only:
            query = query.filter_by(is_read=False)

        query = query.order_by(Notification.created_at.desc())

        pagination = query.paginate(page=page, per_page=per_page)

        unread_count = Notification.query.filter_by(user_id = current_user_id, is_read=False).count()

        results = []
        for notification in pagination.items:

            source_user = User.query.get(notification.source_id) if notification.source_id else None

            results.append({
                'id': notification.id,
                'type': notification.type,
                'is_read': notification.is_read,
                'created_at': notification.created_at,
                'source_id': notification.source_id,
                'source_user': {
                    'id': source_user.id,
                    'username': source_user.username,
                    'profile_picture': source_user.profile_picture
                } if source_user else None,
                'post_id': notification.post_id,
                'comment_id': notification.comment_id

            })
        return {
            'notifications': results,
            'total': pagination.total,
            'page': pagination.page,
            'per_page': pagination.per_page,
            'unread_count': unread_count
        }
notifications_ns.route('/mark_read')
class MarkNotificationsRead(Resource):
    @jwt_required()
    @notifications_ns.expect(notifications_ns.model('MarkRead',{
        'notification_ids': fields.List(fields.Integer, description='List of notification IDs to mark as read'),
        'mark_all': fields.Boolean(description='Mark all notification as read', default = False)
    }))
    def post(self):
        """Mark notifications as read"""
        current_user_id = get_jwt_identity()
        data = request.json or {}

        notification_ids = data.get('notification_ids', [])
        mark_all = data.get('mark_all', False)

        try:
            if mark_all:

                Notification.query.filter_by(
                    user_id = current_user_id,
                    is_read = False
                ).update({'is_read': True})

                db.session.commit()
                return {'message': 'All notifications marked as read'}, 200
            elif notification_ids:

                Notification.query.filter(
                    Notification.id.in_(notification_ids),
                    Notification.user_id == current_user_id
                ).update({'is_read': True}, synchronize_session=False)

                db.session.commit()
                return {'message': f'{len(notification_ids)} notifications marked as read'}, 200
            else:
                return{'message': 'No notifications specified'}, 400
        except Exception as e:
            db.session.rollback()
            return {'message': f'An error occurred: {str(e)}'}, 500

@notifications_ns.route('/unread_count')
class UnreadNotificationCount(Resource):
    @jwt_required()
    def get(self):
        """Get count of unread notifications"""
        current_user_id = get_jwt_identity()

        unread_count = Notification.query.filter_by(
            user_id=current_user_id,
            is_read=False
        ).count()

        return {'unread_count': unread_count}, 200

conversation_participants = Table(
    'conversation_participants',
    db.Model.metadata,
    Column('conversation_id', Integer, ForeignKey('converation.id'), primary_key=True),
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True)
)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.now)
    last_message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)

    # Relationship
    participants = relationship('User', secondary = conversation_participants, backref = 'conversations')
    messages = relationship('Message', back_populates='conversion', cascade='all, delete-orphan')
    last_message = relationship('Message', foreign_keys=[last_message_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable = True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    media_url = db.Column(db.String(255), nullable=True)
    media_type = db.Column(db.String(50), nullable = True)

    sender = relationship('USer', backref='sent_messages')
    conversation = relationship('Conversation', back_populates='messages')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reported_post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    reported_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    reason = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    admin_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)

    # relationships
    reporter = relationship('User', foreign_keys = [reporter_id])
    reported_user = relationship('User', foreign_keys=[reported_user_id])
    reported_post = relationship('Post', foreign_keys=[reported_comment_id])
    reviewer = relationship('User', foreign_keys=[reviewed_by])


class BlockedUser(db.Model):
    __tablename__ = 'blocked_users'
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    blocked_id = db.Column(db.Integer, db.ForeignKey('USer.id'), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    blocker = relationship('User', foreign_keys=[blocker_id])
    blocked = relationship('User', foreign_keys=[blocked_id])

class Media(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable = False)
    file_size = db.Column(db.Integer, nullable = False)
    media_type = db.Column(db.String(50), nullable = False)
    mime_type = db.Column(db.String(100), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    thumbnail_path = db.Column(db.String(500), nullable = True)

    uploader = relationship('User', backref='uploaded_media')


if __name__ =='__main__':
    app.run(debug = True)