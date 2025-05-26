from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from app import User, db,BadRequest, Comment
from app import Report, joinedload, desc, Forbidden, NotFound, BlockedUser

moderation_ns = Namespace('moderation', dscription='Moderation to ensure reporting content and blocking users is possible')

report_model = moderation_ns.model('Report',{
    'id': fields.Integer(required=True),
    'reporter': fields.Raw,
    'Reported_user': fields.Raw,
    'reported_post': fields.Raw,
    'reported_comment': fields.Raw,
    'reason': fields.String(required=True),
    'description': fields.String,
    'status': fields.String,
    'created_at': fields.DateTime,
    'admin_notes': fields.String,
    'reviewer': fields.Raw,
    'reviewed_at': fields.DateTime
})

create_report_model = moderation_ns.model('CreateReport',{
    'reported_user_id': fields.Integer(description = 'ID of reported user'),
    'reported_post_id': fields.Integer(description= 'ID of reported post'),
    'reported_comment_id': fields.Integer(description = 'Reason for report'),
    'reason': fields.String(required=True, description='Reason for report'),
    'description': fields.String(description='Additional details')
})

update_report_model = moderation_ns.model('UpdateReport',{
    'status': fields.String(required=True, description='New status: reviewed, resolved, dismissed'),
    'admin_notes': fields.String(description='Admin notes')
})

block_user_model = moderation_ns.model('BlockUser',{
    'user_id': fields.Integer(required=True, description='ID of user to block')
})

@moderation_ns.route('/reports')
class ReportListAPI(Resource):
    @jwt_required()
    @moderation_ns.marshal_list_with(report_model)
    def get(self):
        """Get reports list (admin only for all, users see their own)"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        status = request.args.get('status')

        query = Report.query

        if not getattr(current_user, 'is_admin', False):
            query = query.filter(Report.reporter_id == current_user_id)

            if status:
                query = query.filter(Report.status == status)

            reports = query.options(
                joinedload(Report.reporter),
                joinedload(Report.reported_user),
                joinedload(Report.reported_post),
                joinedload(Report.reported_comment),
                joinedload(Report.reviewer)
            ).order_by(desc(Report.created_at)).paginate(
                page = page, per_page=per_page, error_out=False
            )

            return reports.items

    @jwt_required()
    @moderation_ns.expect(create_report_model)
    @moderation_ns.marshal_with(report_model)
    def post(self):
        """Create a new report"""
        current_user_id = get_jwt_identity()
        data = request.get_json()

        reported_user_id = data.get('reported_user_id')
        reported_post_id = data.get('reported_post_id')
        reported_comment_id = data.get('reported_comment_id')
        reason = data.get('reason', '').strip()
        description = data.get('description', '').strip()

        if not reason:
            raise BadRequest("Reason is required")

        if not any([reported_user_id, reported_post_id, reported_comment_id]):
            raise BadRequest("Must specify what to report")

        if reported_user_id:
            user = User.query.get(reported_user_id)
            if not user:
                raise BadRequest('cannot report yourself')
            if user.id == current_user_id:
                raise BadRequest("Reported post not found")

            if reported_comment_id:
                comment = Comment.query.get(reported_comment_id)
                if not comment:
                    raise BadRequest("reported comment not found")

            existing_report = Report.query.filter(
                Report.reporter+id == current_user_id,
                Report.reported_user_id == reported_user_id,
                Report.reported_post_id == reported_post_id,
                Report.reported_comment_id == reported_comment_id,
                Report.status.in_(['pending', 'reviewed'])
            ).first()

            if existing_report:
                raise BadRequest("You have already reported this")

            try:
                report = Report(
                    reporter_id = current_user_id,
                    reported_user_id = reported_user_id,
                    reported_post_id = reported_post_id,
                    reported_comment_id = reported_comment_id,
                    reason = reason,
                    description = description
                )
                db.session.add(report)
                db.session.commit()

                return report
            except Exception as e:
                db.session.rollback()
                raise BadRequest(f'failed to create report: {str(e)}')


@moderation_ns.route('/reports/<int:report_id>')
class ReportAPI(Resource):
    @jwt_required()
    @moderation_ns.marshal_with(report_model)
    def get(self, report_id):
        """Get a specific report"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        report = Report.query.options(
            joinedload(Report.reporter),
            joinedload(Report.reported_user),
            joinedload(Report.reported_post),
            joinedload(Report.reported_comment),
            joinedload(Report.reviewer)
        ).get(report_id)

        if not report:
            raise NotFound("Report not found")

        # Non-admin users can only see their own reports
        if not getattr(current_user, 'is_admin', False) and report.reporter_id != current_user_id:
            raise Forbidden("Access denied")

        return report

    @jwt_required()
    @moderation_ns.expect(update_report_model)
    @moderation_ns.marshal_with(report_model)
    def put(self, report_id):
        """Update report status (admin only)"""
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not getattr(current_user, 'is_admin', False):
            raise Forbidden("Admin access required")

        report = Report.query.get(report_id)
        if not report:
            raise NotFound("Report not found")

        data = request.get_json()
        status = data.get('status', '').strip()
        admin_notes = data.get('admin_notes', '').strip()

        if status not in ['pending', 'reviewed', 'resolved', 'dismissed']:
            raise BadRequest("Invalid status")

        try:
            report.status = status
            report.admin_notes = admin_notes
            report.reviewed_by = current_user_id
            report.reviewed_at = datetime.utcnow()

            db.session.commit()
            return report
        except Exception as e:
            db.session.rollback()
            raise BadRequest(f"Failed to update report: {str(e)}")


@moderation_ns.route('/block')
class BlockUserAPI(Resource):
    @jwt_required()
    @moderation_ns.expect(block_user_model)
    def post(self):
        """Block a user"""
        current_user_id = get_jwt_identity()
        data = request.get_json()

        user_id = data.get('user_id')
        if not user_id:
            raise BadRequest("User ID is required")

        if user_id == current_user_id:
            raise BadRequest("Cannot block yourself")

        user = User.query.get(user_id)
        if not user:
            raise BadRequest("User not found")

        # Check if already blocked
        existing_block = BlockedUser.query.filter_by(
            blocker_id=current_user_id,
            blocked_id=user_id
        ).first()

        if existing_block:
            raise BadRequest("User is already blocked")

        try:
            block = BlockedUser(blocker_id=current_user_id, blocked_id=user_id)
            db.session.add(block)
            db.session.commit()

            return {'message': f'User {user.username} has been blocked'}
        except Exception as e:
            db.session.rollback()
            raise BadRequest(f"Failed to block user: {str(e)}")


@moderation_ns.route('/block/<int:user_id>')
class UnblockUserAPI(Resource):
    @jwt_required()
    def delete(self, user_id):
        """Unblock a user"""
        current_user_id = get_jwt_identity()

        block = BlockedUser.query.filter_by(
            blocker_id=current_user_id,
            blocked_id=user_id
        ).first()

        if not block:
            raise NotFound("User is not blocked")

        try:
            db.session.delete(block)
            db.session.commit()

            user = User.query.get(user_id)
            return {'message': f'User {user.username if user else user_id} has been unblocked'}
        except Exception as e:
            db.session.rollback()
            raise BadRequest(f"Failed to unblock user: {str(e)}")


@moderation_ns.route('/blocked-users')
class BlockedUsersListAPI(Resource):
    @jwt_required()
    def get(self):
        """Get list of blocked users"""
        current_user_id = get_jwt_identity()

        blocked_users = db.session.query(BlockedUser, User).join(
            User, BlockedUser.blocked_id == User.id
        ).filter(BlockedUser.blocker_id == current_user_id).all()

        result = []
        for block, user in blocked_users:
            result.append({
                'user_id': user.id,
                'username': user.username,
                'blocked_at': block.created_at
            })

        return result
@moderation_ns.route('/blocked-users')
class BlockedUsersListAPI(Resource):
    @jwt_required()
    def get(self):
        """Get list of blocked users"""
        current_user_id = get_jwt_identity()

        blocked_users = db.session.query(BlockedUser, User).join(
            User, BlockedUser.blocked_id == User.id
        ).filter(BlockedUser.blocker_id == current_user_id).all()

        result = []
        for block, user in blocked_users:
            result.append({
                'user_id': user.id,
                'username': user.username,
                'blocked_at': block.created_at
            })

        return result
