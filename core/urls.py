from django.urls import path
from .views import EventIngestAPIView, alert_feed, resolve_alert, unlock_user, user_unlock_view, home, register, login_view, logout_view, member_dashboard, alert_not_me, trigger_event

urlpatterns = [
    path('', home, name='home'),
    path('register/', register, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('member/', member_dashboard, name='member-dashboard'),
    path('member/trigger_event/', trigger_event, name='trigger-event'),
    path('alert/not_me/<int:alert_id>/', alert_not_me, name='alert-not-me'),
    path('admin_dashboard/', alert_feed, name='admin-dashboard'),
    path('api/events/', EventIngestAPIView.as_view(), name='event-ingest'),
    path('alerts/', alert_feed, name='alert-feed'),
    path('alerts/resolve/<int:alert_id>/', resolve_alert, name='resolve-alert'),
    path('alerts/unlock_user/<int:user_id>/', unlock_user, name='unlock-user'),
    path('user/unlock/<int:user_id>/', user_unlock_view, name='user-unlock'),

]
