import os
import uuid
from xml.dom import NoModificationAllowedErr
from app import BadRequest, Media, db, NotFound, User, Forbidden

from PIL import Image
from werkzeug.utils import secure_filename
from flask import request, send_file, current_app
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy import desc

media_ns = Namespace('media', description = 'For media handling')

ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp'},
    'video': {'mp4', 'avi', 'mov', 'wmv', 'flv'},
    'document': {'pdf', 'doc', 'docx', 'txt'}
}

MAX_FILE_SIZE = 10 * 1024 * 1024
THUMBNAIL_SIZE = (300, 300)

media_model = media_ns.model('Media', {
    'id': fields.Integer(required = True),
    'filename': fields.String(required=True),
    'original_name': fields.String(required=True),
    'file_size': fields.Integer,
    'media_type': fields.String,
    'mime_type': fields.String,
    'created_at': fields.DateTime,
    'Thumbnail_url': fields.String,
    'file_url':fields.String

})
def allowed_file(filename, file_type=None):
    if '.' not in filename:
        return False

    extension = filename.rsplit('.', 1)[1].lower()

    if file_type:
        return extension in ALLOWED_EXTENSIONS.get(file_type, set())

    for extensions in ALLOWED_EXTENSIONS.values():
        if extension in extensions:
            return True
    return False

def get_media_type(filename):
    if '.' not in filename:
        return 'unknown'

    extension = filename.rsplit('.', 1)[1].lower()

    for media_type, extensions in ALLOWED_EXTENSIONS.items():
        if extension in extensions:
            return media_type

    return 'unknown'

def create_thumbnail(image_path, thumbnail_path):
    """Create a thumbnail for an image"""
    try:
        with Image.open(image_path) as img:
            img.thumbnail(THUMBNAIL_SIZE, Image.Resampling.LANCZOS)

            if img.mode in ('RGBA', 'LA', 'P'):
                background = Image.new('RGB', img.size, (255, 255, 255))
                if img.mode == 'p':
                    img = img.convert('RGBA')
                background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                img = background

            img.save(thumbnail_path, 'JPEG', quality=85)
            return True
    except Exception as e:
        print(f'Error creating thumbnail: {e}')
        return False

@media_ns.route('/upload')
class MediaUploadAPI(Resource):
    @jwt_required()
    @media_ns.marshal_with(media_model)
    def post(self):
        """Upload a media file"""
        current_user_id = get_jwt_identity()

        if 'file' not in request.files:
            raise BadRequest('No file provided')

        file = request.files['file']
        if file.filename == '':
            raise BadRequest("no file selected")

        if not allowed_file(file.filename):
            raise BadRequest("File type not allowed")

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_FILE_SIZE:
            raise BadRequest(f'File too large. Maximum size is {MAX_FILE_SIZE  // (1024*1024)}MB')

        original_name = secure_filename(file.filename)
        file_extension = original_name.rsplit('.', 1)[1].lower()
        unique_filename = f'{uuid.uuid4().hex}.{file_extension}'

        upload_dir = os.path.join(current_app.config.get('UPLOAD_FOLDER', 'uploads'), 'media')
        os.makedirs(upload_dir, exist_ok=True)

        file_path = os.path.join(upload_dir, unique_filename)
        thumbnail_path = None

        try:
            file.save(file_path)

            media_type = get_media_type(original_name)
            mime_type = file.content_type or 'application/octet-stream'

            if media_type == 'image':
                thumbnail_filename = f"thumb_{unique_filename}"
                thumbnail_path = os.path.join(upload_dir, thumbnail_filename)
                if create_thumbnail(file_path, thumbnail_path):
                    thumbnail_path = os.path.join('media', thumbnail_filename)
                else:
                    thumbnail_path = None

                media = Media(
                    filename= unique_filename,
                    original_name=original_name,
                    file_path = os.path.join('media', unique_filename),
                    file_size=file_size,
                    media_type=media_type,
                    uploaded_by = current_user_id,
                    thumbnail_path = thumbnail_path,
                )

                db.session.add(media)
                db.session.commit()

                media_dict = {
                    'id': media.id,
                    'filename': media.filename,
                    'original_name': media.original_name,
                    'file_size': media.file_size,
                    'media_type': media.media_type,
                    'mime_type': media.mime_type,
                    'created_at': media.created_at,
                    'file_url': f"/api/media/files/{media.id}",
                    'thumbnail_url': f"/api/media/thumbnails/{media.id}" if media.thumbnail_path else None
                }

                return media_dict

        except Exception as e:

            if os.path.exists(file_path):
                os.remove(file_path)

            if thumbnail_path and os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)

            db.session.rollback()
            raise BadRequest(f"Failed to upload file: {str(e)}")

@media_ns.route('/files/<int:media_id>')
class MediaFileAPI(Resource):
    def get(self, media_id):
        """Serve a media file"""
        media = Media.query.get(media_id)
        if not media:
            raise NotFound("Media not found")

        file_path = os.path.join(current_app.config.get('UPLOAD_FOLDER', 'uploads'), media.file_path)

        if not os.path.exists(file_path):
            raise NotFound('File not found on disk')

        return send_file(file_path, as_attachment=False, mimetype=media.mime_type)

@media_ns.route('/thumbnails/<int:media_id>')
class MediaThumbnailAPI(Resource):
    def get(self, media_id):
        """Serve a media thumbnail"""
        media = Media.query.get(media_id)
        if not media or not media.thumbnail_path:
            raise NotFound("Thumbnail fnot found")
        thumbnail_path = os.path.join(current_app.config.get('UPLOAD_FOLDER', 'uploads'), media.thumbnail_path)

        if not os.path.exists(thumbnail_path):
            raise NotFound("Thumbnail file not found on disk")

        return send_file(thumbnail_path, as_attachment=False, mmimetype='image/jpeg')

@media_ns.route('/<int:media_id>')
class MediaAPI(Resource):
    @jwt_required()
    @media_ns.marshal_with(media_model)
    def get(selfself, media_id):
        """Get media metadata"""
        current_user_id = get_jwt_identity()

        media = Media.query.get(media_id)
        if not media:
            raise NotFound("Media not found")

        media_dict = {
            'id': media.id,
            'filename': media.filename,
            'original_name': media.original_name,
            'file_size': media.file_size,
            'media_type': media.media_type,
            'mime_type': media.mime_type,
            'created_at': media.created_at,
            'file_url': f"/api/media/files/{media.id}" if media.thumbnail_path else None,
            'thumbnail_url': f"/api/media/thumbnails/{media.id}" if media.thumbnail_path else None
        }

        return media_dict

    @jwt_required()
    def delete(self, media_id):
        """Delete a media file"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        media = Media.query.get(media_id)
        if not media:
            raise Forbidden("Access denied")

        try:
            file_path = os.path.join(current_app.config.get('UPLOAD_FOLDER', 'uploads'), media.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)

            db.session.delete(media)
            db.session.commit()

            return {'message': 'media deleted successfully'}
        except Exception as e:

            db.session.rolllback()
            raise BadRequest(f"Failed to delete media: {str(e)}")

@media_ns.route('/my-media')
class UserMediaListAPI(Resource):
    @jwt_required()
    def get(self):
        """Get current user's uploaded media"""
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        media_type = request.args.get('type')
        query = Media.query.filter_by(uploaded_by = current_user_id)

        if media_type:
            query = query.filter_by(media_type = media_type)

        media_list = query.order_by(desc(Media.created_at)).paginate(
            page = page, per_page = per_page, error_out=False
        )

        result = []
        for media in media_list.items:
            media_dict = {
                'id': media.id,
                'filename': media.filename,
                'original_name': media.original_name,
                'file_size': media.file_size,
                'media_type': media.media_type,
                'mime_type': media.mime_type,
                'created_at': media.created_at,
                'file_url': f"/api/media/files/{media.id}",
                'thumbnail_url': f"/api/media/thumbnails/{media.id}" if media.thumbnail_path else None
            }
            result.append(media_dict)

            return{
                'items': result,
                'total': media_list.total,
                'page': page,
                'per_page': per_page,
                'pages': media_list.pages
            }




