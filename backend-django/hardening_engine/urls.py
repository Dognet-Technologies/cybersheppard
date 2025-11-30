"""
============================================================================
CYBERSHEPPARD - Hardening Engine URLs
============================================================================
"""

from django.urls import path
from . import views

app_name = 'hardening_engine'

urlpatterns = [
    # Hardening Models
    path('models/', views.list_hardening_models, name='list-models'),
    path('models/<str:model_name>/', views.get_hardening_model, name='get-model'),

    # Apply Hardening
    path('apply/<int:target_id>/', views.apply_hardening, name='apply-hardening'),
    path('apply/<int:target_id>/status/', views.get_apply_status, name='apply-status'),

    # Validation
    path('validate/<int:target_id>/', views.validate_hardening, name='validate-hardening'),

    # SSH Operations
    path('ssh/test/<int:target_id>/', views.test_ssh_connection, name='test-ssh'),
    path('ssh/keys/', views.list_ssh_keys, name='list-ssh-keys'),
    path('ssh/keys/generate/', views.generate_ssh_key, name='generate-ssh-key'),
]
