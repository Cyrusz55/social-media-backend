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