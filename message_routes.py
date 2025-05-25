from flask import request, current_app
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.orm import joinedload
from sqlalchemy import or_, and_, desc
from werkzeug.exceptions import NotFound, Forbidden, BadRequest
from app import app
messages_ns = Namespace('messages', description='Handling direct messaging')

# API models for documentation
conversation_model = messages_ns.model('Conversation',{
    'id': fields.Integer(required=True),
    'participants': fields.List(fields.Raw),
    'created_at': fields.DateTime,
    'updated_at': fields.DateTime,
    'last_message': fields.Raw,
    'unread_count': fields.Integer

})
message_model = messages_ns.model('Message', {
    'id': fields.Integer(required=True),
    'content': fields.String,
    'sender_id': fields.Integer(required=True),
    'conversation_id': fields.Integer(required=True),
    'created_at': fields.DateTime,
    'is_read': fields.Boolean,
    'media_url': fields.String,
    'media_type': fields.String,
    'sender': fields.Raw
})

create_conversation_model = messages_ns.model('CreateConversation',{
    'participant_ids': fields.List(fields.Integer, required=True, description='List of user IDs to be included in conversation')

})

send_message_model = messages_ns.model('SendMessage',{
    'content': fields.String(description = 'Message content'),
    'media_id': fields.Integer(description='Optional media attachment ID')
})

@messages_ns.route('/conversations')
class ConversationListAPI(Resource):
    @jwt_required()
    @messages_ns.marshal_list_with(conversation_model)
    def get(self):
        """Get all conversations for the current user"""
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)

        conversations = Conversation.query.join(
            conversation_participants

        ).filter(
            conversation_participants.c.user_id == current_user_id
        ).options(
            joinedload(Conversation.participants),
            joinedload(Conversation.last_message).joinedload(Message.sender)
        ).order_by(desc(Conversation.updated_at)).paginate(
            page = page, per_page = per_page, error_out=False
        )