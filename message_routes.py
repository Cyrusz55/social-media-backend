from flask import request, current_app
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from sqlalchemy.orm import joinedload
from sqlalchemy import or_, and_, desc
from werkzeug.exceptions import NotFound, Forbidden, BadRequest
from app import Conversation, Message
from app import conversation_participants, db, User, Media, datetime, Notification
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

        result = []
        for conv in conversations.items:
            unread_count = Message.query.filter(
                Message.conversation_id == conv.id,
                Message.sender_id != current_user_id,
                Message.is_read == False
            ).count()

            conv_data = {
                'id': conv.id,
                'participants': [{'id': p.id, 'username': p.username, 'avatar_url': getattr(p, 'avatar_url', None)}
                             for p in conv.participants if p.id != current_user_id],
                'created_at': conv.created_at,
                'updated_at': conv.updated_at,
                'last_message': {
                    'content': conv.last_message.content if conv.last_message else None,
                    'sender': {'username': conv.last_message.sender.username} if conv.last_message else None,
                    'created_at': conv.last_message.created_at if conv.last_message else None
                } if conv.last_message else None,
                'unread_count': unread_count
            }
            result.append(conv_data)


@jwt_required()
@messages_ns.expect(create_conversation_model)
@messages_ns.marshal_with(conversation_model)
def post(self):
    """Create a new conversation"""
    current_user_id = get_jwt_identity()
    data = request.get_json()

    participant_ids = data.get('participant_ids', [])
    if not participant_ids:
        raise BadRequest("At least one participant is required")

    # Add current user to participants
    all_participant_ids = list(set([current_user_id] + participant_ids))

    # Check if conversation already exists with same participants
    existing_conv = None
    if len(all_participant_ids) == 2:  # Direct message
        existing_conv = Conversation.query.join(
            conversation_participants
        ).filter(
            conversation_participants.c.user_id.in_(all_participant_ids)
        ).group_by(Conversation.id).having(
            db.func.count(conversation_participants.c.user_id) == len(all_participant_ids)
        ).first()

    if existing_conv:
        return existing_conv

    # Verify all participants exist
    participants = User.query.filter(User.id.in_(all_participant_ids)).all()
    if len(participants) != len(all_participant_ids):
        raise BadRequest("One or more participants not found")

    try:
        conversation = Conversation()
        conversation.participants = participants
        db.session.add(conversation)
        db.session.commit()

        return conversation
    except Exception as e:
        db.session.rollback()
        raise BadRequest(f"Failed to create conversation: {str(e)}")


@messages_ns.route('/conversations/<int:conversation_id>')
class ConversationAPI(Resource):
    @jwt_required()
    def delete(self, conversation_id):
        """Delete a conversation"""
        current_user_id = get_jwt_identity()

        conversation = Conversation.query.filter(
            Conversation.id == conversation_id
        ).join(conversation_participants).filter(
            conversation_participants.c.user_id == current_user_id
        ).first()

        if not conversation:
            raise NotFound("Conversation not found")

        try:
            db.session.delete(conversation)
            db.session.commit()
            return {'message': 'Conversation deleted successfully'}
        except Exception as e:
            db.session.rollback()
            raise BadRequest(f"Failed to delete conversation: {str(e)}")


@messages_ns.route('/conversations/<int:conversation_id>/messages')
class MessageListAPI(Resource):
    @jwt_required()
    @messages_ns.marshal_list_with(message_model)
    def get(self, conversation_id):
        """Get messages in a conversation"""
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)

        # Verify user is participant in conversation
        conversation = Conversation.query.filter(
            Conversation.id == conversation_id
        ).join(conversation_participants).filter(
            conversation_participants.c.user_id == current_user_id
        ).first()

        if not conversation:
            raise NotFound("Conversation not found")

        messages = Message.query.filter(
            Message.conversation_id == conversation_id
        ).options(
            joinedload(Message.sender)
        ).order_by(desc(Message.created_at)).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return messages.items


@jwt_required()
@messages_ns.expect(send_message_model)
@messages_ns.marshal_with(message_model)
def post(self, conversation_id):
    """Send a message in a conversation"""
    current_user_id = get_jwt_identity()
    data = request.get_json()

    # Verify user is participant in conversation
    conversation = Conversation.query.filter(
        Conversation.id == conversation_id
    ).join(conversation_participants).filter(
        conversation_participants.c.user_id == current_user_id
    ).first()

    if not conversation:
        raise NotFound("Conversation not found")

    content = data.get('content', '').strip()
    media_id = data.get('media_id')

    if not content and not media_id:
        raise BadRequest("Message must have content or media attachment")

    media_url = None
    media_type = None

    if media_id:
        media = Media.query.filter_by(id=media_id, uploaded_by=current_user_id).first()
        if media:
            media_url = media.file_path
            media_type = media.media_type

    try:
        message = Message(
            content=content,
            sender_id=current_user_id,
            conversation_id=conversation_id,
            media_url=media_url,
            media_type=media_type
        )
        db.session.add(message)

        # Update conversation's last message
        conversation.last_message_id = message.id
        conversation.updated_at = datetime.utcnow()

        db.session.commit()

        # Create notifications for other participants
        for participant in conversation.participants:
            if participant.id != current_user_id:
                notification = Notification(
                    user_id=participant.id,
                    type='message',
                    message=f"New message from {message.sender.username}",
                    related_user_id=current_user_id
                )
                db.session.add(notification)

        db.session.commit()
        return message
    except Exception as e:
        db.session.rollback()
        raise BadRequest(f"Failed to send message: {str(e)}")

@messages_ns.route('/conversations/<int:conversation_id>/messages/<int:message_id>/read')
class MessageReadAPI(Resource):
    @jwt_required()
    def put(self, conversation_id, message_id):
        """Mark a message as read"""
        current_user_id = get_jwt_identity()

        message = Message.query.filter(
            Message.id == message_id,
            Message.conversation_id == conversation_id
        ).join(Conversation).join(conversation_participants).filter(
            conversation_participants.c.user_id == current_user_id
        ).first()
        if not message:
            raise NotFound('Message not found')

        if message.sender_id != current_user_id:
            message.is_read = True
            db.session.commit()
        return {'message': 'Message marked as read'}

@messages_ns.route('/conversations/<int:conversation_id>/messages/mark-read')
class ConversationMarkReadAPI(Resource):
    @jwt_required()
    def put(self, conversation_id):
        """Mark all messages in conversation as read"""

        current_user_id = get_jwt_identity()

        conversation = Conversation.query.filter(
            Conversation.id == conversation_id
        ).join(conversation_participants).filter(
            conversation_participants.c.user_id == current_user_id
        ).first()

        if not conversation:
            raise NotFound('Conversation not found')

        Message.query.filter(
            Message.converstion_id == conversation_id,
            Message.sender_id != current_user_id,
            Message.is_read == False
        ).update({'is_read': True})

        db.session.commit()
        return{'message': 'All messages marked as read'}



