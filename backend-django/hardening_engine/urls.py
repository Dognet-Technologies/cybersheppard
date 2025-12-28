"""
URL Configuration for Hardening Engine API
"""

from django.urls import path
from . import views

app_name = 'hardening_engine'

urlpatterns = [
    # Health check
    path('health', views.health_check, name='health_check'),

    # Hardening operations
    path('apply', views.apply_hardening, name='apply_hardening'),
    path('rollback', views.rollback_hardening, name='rollback_hardening'),

    # Models
    path('models', views.list_models, name='list_models'),
    path('models/<path:model_path>', views.get_model, name='get_model'),
    path('validate', views.validate_model, name='validate_model'),

    # Backups
    path('backups', views.list_backups, name='list_backups'),
    path('backups/<str:backup_id>', views.get_backup_info, name='get_backup_info'),

    # Utilities
    path('test-connection', views.test_connection, name='test_connection'),
]
