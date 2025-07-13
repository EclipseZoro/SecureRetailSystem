from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Event, Device, Alert
from .serializers import EventSerializer
from django.contrib.auth.models import User
from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.core.mail import mail_admins
import random
from django.contrib import messages

def alert_feed(request):
    alerts = Alert.objects.select_related('event').order_by('-created_at')[:50]
    return render(request, 'core/alert_feed.html', {'alerts': alerts})
def resolve_alert(request, alert_id):
    alert = get_object_or_404(Alert, pk=alert_id)
    alert.resolved = not alert.resolved  # Toggle status
    alert.save()
    return redirect('alert-feed')
class EventIngestAPIView(APIView):
    def post(self, request):
        serializer = EventSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user'].id
            user = User.objects.get(id = user_id)
            event_type = serializer.validated_data['event_type']
            sensitive_types = ['transaction', 'checkout']
            if user.userprofile.is_security_locked and event_type in sensitive_types:
                return Response(
                    {"detail": "USer is security-locked. Please verify identity to perform this action"},
                    status=status.HTTP_403_FORBIDDEN
                )
            event = serializer.save()
            self.detect_and_alert(event)
            
            return Response({"message": "Event recorded."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def detect_and_alert(self, event):
        # Example Rule 1: 5 failed logins from same user in 2 minutes
        if event.event_type == "failed_login":
            now = timezone.now()
            count = Event.objects.filter(
                user=event.user,
                event_type="failed_login",
                timestamp__gte=now - timezone.timedelta(minutes=2)
            ).count()
            if count >= 5:
                alert = Alert.objects.create(
                    event=event,
                    detected_by="rule",
                    rule_name="Multiple failed logins",
                    severity="medium",
                    description=f"5+ failed logins within 2 minutes from user {event.user.username}",
                    action_taken="Alerted admin"
                )
                notify_admin_via_email(alert)
        # Example Rule 2: Transaction > 50000 from new device
        if event.event_type == "transaction":
            amount = event.metadata.get("amount", 0)
            if amount and float(amount) > 50000:
                # Check if device is new for this user
                device_events = Event.objects.filter(user=event.user, device=event.device)
                if device_events.count() == 1:  # This is first transaction from this device
                    alert = Alert.objects.create(
                        event=event,
                        detected_by="rule",
                        rule_name="Large transaction from new device",
                        severity="high",
                        description=f"Large transaction (₹{amount}) from new device by user {event.user.username}",
                        action_taken="Blocked transaction and alerted admin"
                    )
                    profile = event.user.userprofile
                    profile.is_security_locked = True
                    profile.last_locked_alert = alert
                    # Generate 6-digit otp
                    otp = f"{random.randint(100000, 999999)}"
                    profile.otp_code = otp
                    profile.otp_created_at = timezone.now()
                    profile.save()
                    notify_admin_via_email(alert)
                    print(f"SECURITY NOTICE: User {event.user.username} locked for verification. Awaiting user verification or admin action. OTP to unlock: {otp}")
        #if the event is a login from a new location
        if event.event_type == "login":
            location = event.location
            past_logins = Event.objects.filter(
            user=event.user,
            event_type="login",
            location=location
            ).exclude(id=event.id)
            if not past_logins.exists():
                alert = Alert.objects.create(
                event=event,
                detected_by="rule",
                rule_name="Login from new location",
                severity="medium",
                description=f"User {event.user.username} logged in from a new location: {location}",
                action_taken="Alerted admin"
                )
                notify_admin_via_email(alert)

        # Next alert when the password is changed multiple times within 24 hrs
        if event.event_type == "password_change":
            now = timezone.now()
            count = Event.objects.filter(
                user=event.user,
                event_type="password_change",
                timestamp__gte=now - timezone.timedelta(hours=24)
            ).count()
            if count > 3:
                alert = Alert.objects.create(
                    event=event,
                    detected_by="rule",
                    rule_name="Frequent password changes",
                    severity="medium",
                    description=f"User {event.user.username} changed password {count} times within 24 hours.",
                    action_taken="Alerted admin"
                )
                notify_admin_via_email(alert)
        if event.event_type == "browsing":
            now = timezone.now()
            count = Event.objects.filter(
                user=event.user,
                event_type="browsing",
                timestamp__gte=now-timezone.timedelta(minutes=5)
            ).count()
            if count > 5:
                alert = Alert.objects.create(
                    event=event,
                    detected_by="rule",
                    rule_name="Possible Scraping",
                    severity="medium",
                    description=f"User {event.user.username} has high browsing activity: {count} events in last 5 minutes.",
                    action_taken="Alerted admin"
                )
                notify_admin_via_email(alert)



def notify_admin_via_email(alert):
    subject = f"Security Alert: {alert.severity.upper()} - {alert.rule_name}"
    message = f"""
    Alert ID: {alert.id}
    User: {alert.event.user.username}
    Event: {alert.event.event_type}
    Severity: {alert.severity}
    Rule: {alert.rule_name}
    Description: {alert.description}
    Action Taken: {alert.action_taken}
    Time: {alert.created_at}

    Please review this alert in the admin dashboard.
    """
    mail_admins(subject, message)
    
def unlock_user(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    profile = user.userprofile
    profile.is_security_locked = False
    profile.save()
    if profile.last_locked_alert:
        profile.last_locked_alert.resolved = True
        profile.last_locked_alert.save()
    return redirect('alert-feed')


def user_unlock_view(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    profile = user.userprofile
    error = None
    unlocked = False

    if request.method == "POST":
        entered_otp = request.POST.get('otp', "")
        now = timezone.now()
        if profile.otp_code == entered_otp and (now- profile.otp_created_at).total_seconds() < 600:
            profile.is_security_locked = False
            profile.otp_code = None
            profile.otp_created_at = None
            profile.save()
            unlocked = True
        else:
            error = "Invalid or expired OTP. Please try again."
    return render(request, 'core/user_unlock.html',
                  {"user_obj": user,
                   "error": error,
                   "unlocked": unlocked,
                   "locked": profile.is_security_locked
                   })

