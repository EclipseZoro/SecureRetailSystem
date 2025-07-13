from django.contrib import admin
from .models import Device, Event, Alert, UserProfile

admin.site.register(Device)
admin.site.register(Event)
admin.site.register(Alert)
admin.site.register(UserProfile)