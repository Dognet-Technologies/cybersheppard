"""
============================================================================
CYBERSHEPPARD (MicroSIEM) - URL Configuration
============================================================================
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/hardening/', include('hardening_engine.urls')),
    path('api/integrations/', include('integrations.urls')),
    path('api/notifications/', include('notifications.urls')),
]
