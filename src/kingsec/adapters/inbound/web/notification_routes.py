from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from kingsec.application.errors import NotificationNotFoundError
from kingsec.application.ports.notification_service import NotificationServicePort
from kingsec.bootstrap.application import Application
from kingsec.domain.notification import NotificationChannel, NotificationId, NotificationPriority

from .auth import CurrentUser, get_current_user, require_admin, require_viewer
from .dependencies import get_application

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


def _get_service(request: Request) -> NotificationServicePort:
    app: Application = get_application(request)
    return app.resolve(NotificationServicePort)


@router.get("")
async def list_notifications(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    if user.role.value == "admin":
        notifications, total = service.list_all(limit=limit, offset=offset)
    else:
        notifications, total = service.list_by_user(user.user_id, limit=limit, offset=offset)
    return {
        "notifications": [_to_json(n) for n in notifications],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{notification_id}")
async def get_notification(
    notification_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    try:
        notification = service.get(NotificationId(notification_id))
    except NotificationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found") from None
    if user.role.value != "admin" and notification.user_id != user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return _to_json(notification)


@router.post("/send")
async def send_notification(
    body: dict,
    request: Request,
    user: CurrentUser = Depends(require_viewer),
) -> dict:
    service = _get_service(request)
    from kingsec.domain.notification import Notification, NotificationStatus
    from datetime import UTC, datetime
    from uuid import uuid4
    now = datetime.now(UTC).isoformat()
    notification = Notification(
        id=NotificationId(str(uuid4())),
        user_id=body.get("user_id", user.user_id),
        title=body.get("title", ""),
        message=body.get("message", ""),
        channel=NotificationChannel(body.get("channel", "in_app")),
        status=NotificationStatus.PENDING,
        priority=NotificationPriority(body.get("priority", "medium")),
        event_type=body.get("event_type", "manual"),
        template_vars=body.get("variables", {}),
        retry_count=0,
        max_retries=body.get("max_retries", 3),
        created_at=now,
        updated_at=now,
    )
    result = service.send(notification)
    return _to_json(result)


@router.post("/bulk")
async def send_bulk(
    body: dict,
    request: Request,
    user: CurrentUser = Depends(require_admin),
) -> dict:
    service = _get_service(request)
    from kingsec.domain.notification import Notification, NotificationStatus
    from datetime import UTC, datetime
    from uuid import uuid4
    now = datetime.now(UTC).isoformat()
    items = body.get("notifications", [])
    notifications = []
    for item in items:
        notifications.append(
            Notification(
                id=NotificationId(str(uuid4())),
                user_id=item.get("user_id", user.user_id),
                title=item.get("title", ""),
                message=item.get("message", ""),
                channel=NotificationChannel(item.get("channel", "in_app")),
                status=NotificationStatus.PENDING,
                priority=NotificationPriority(item.get("priority", "medium")),
                event_type=item.get("event_type", "manual"),
                template_vars=item.get("variables", {}),
                retry_count=0,
                max_retries=item.get("max_retries", 3),
                created_at=now,
                updated_at=now,
            )
        )
    results = service.send_bulk(notifications)
    return {"sent": len(results), "notifications": [_to_json(n) for n in results]}


@router.post("/{notification_id}/read")
async def mark_read(
    notification_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> dict:
    service = _get_service(request)
    nid = NotificationId(notification_id)
    try:
        notification = service.get(nid)
    except NotificationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found") from None
    if user.role.value != "admin" and notification.user_id != user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    result = service.mark_read(nid)
    return _to_json(result)


@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification(
    notification_id: str,
    request: Request,
    user: CurrentUser = Depends(get_current_user),
) -> None:
    service = _get_service(request)
    nid = NotificationId(notification_id)
    try:
        notification = service.get(nid)
    except NotificationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found") from None
    if user.role.value != "admin" and notification.user_id != user.user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    service.delete(nid)


@router.post("/retry")
async def retry_failed(
    body: dict,
    request: Request,
    user: CurrentUser = Depends(require_admin),
) -> dict:
    service = _get_service(request)
    notification_id = body.get("notification_id")
    if not notification_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="notification_id is required")
    try:
        result = service.retry_failed(NotificationId(notification_id))
    except NotificationNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found") from None
    return _to_json(result)


def _to_json(notification: object) -> dict:
    from kingsec.domain.notification import Notification as N
    if not isinstance(notification, N):
        return {}
    return {
        "id": str(notification.id),
        "user_id": notification.user_id,
        "title": notification.title,
        "message": notification.message,
        "channel": notification.channel.value,
        "status": notification.status.value,
        "priority": notification.priority.value,
        "event_type": notification.event_type,
        "retry_count": notification.retry_count,
        "max_retries": notification.max_retries,
        "created_at": notification.created_at,
        "updated_at": notification.updated_at,
        "read_at": notification.read_at,
        "error_message": notification.error_message,
    }
