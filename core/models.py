from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=128)
    device_type = models.CharField(max_length=50, blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=128, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.device_id}"

class Event(models.Model):
    EVENT_TYPES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('password_change', 'Password Change'),
        ('transaction', 'Transaction'),
        ('failed_login', 'Failed Login'),
        ('browsing', 'Browsing Activity'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL)
    event_type = models.CharField(max_length=32, choices=EVENT_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField()
    location = models.CharField(max_length=128, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.event_type} at {self.timestamp}"

class Alert(models.Model):
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    detected_by = models.CharField(max_length=32)
    rule_name = models.CharField(max_length=64, blank=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_LEVELS)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    action_taken = models.CharField(max_length=128, blank=True)

    def __str__(self):
        return f"{self.event.user.username} - {self.severity} - {self.description[:30]}"

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_security_locked = models.BooleanField(default=False)
    last_locked_alert = models.ForeignKey('Alert', null=True, blank=True, on_delete=models.SET_NULL)
    otp_code = models.CharField(max_length=8, blank=True, null=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    

    def __str__(self):
        return f"{self.user.username} profile"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)