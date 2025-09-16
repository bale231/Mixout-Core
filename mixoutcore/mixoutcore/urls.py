# mixoutcore/urls.py
from django.contrib import admin
from django.urls import path, include
from core.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Core app (include sia le nuove auth API che quelle esistenti)
    path('api/', include('core.urls')),

    path('auth/', auth_ui, name='auth'),
    path('api/register/', proxy_registration, name='proxy_register'),
    
    # Accounts app se necessario
    # path('accounts/', include('accounts.urls')),
]