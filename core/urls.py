from django.urls import path
from .views import EventIngestAPIView, alert_feed, resolve_alert, unlock_user, user_unlock_view

urlpatterns = [
    path('api/events/', EventIngestAPIView.as_view(), name='event-ingest'),
    path('alerts/', alert_feed, name='alert-feed'),
    path('alerts/resolve/<int:alert_id>/', resolve_alert, name='resolve-alert'),
    path('alerts/unlock_user/<int:user_id>/', unlock_user, name='unlock-user'),
    path('user/unlock/<int:user_id>/', user_unlock_view, name='user-unlock'),

]
