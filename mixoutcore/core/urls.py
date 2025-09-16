# core/urls.py
from django.urls import path
from .views import *

urlpatterns = [
    # === Auth UI ===
    path('auth/', AuthUIView.as_view(), name='auth-ui'),
    
    # === Proxy API (Per UI personalizzata) ===
    path('api/register/', ProxyRegistrationView.as_view(), name='proxy-register'),
    path('api/login/', ProxyLoginView.as_view(), name='proxy-login'),
    
    # === Auth API Complete (Per frontend avanzati) ===
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/register/", RegistrationView.as_view(), name="auth-register"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/session/", SessionView.as_view(), name="auth-session"),
    path("auth/callback/", CallbackView.as_view(), name="auth-callback"),
    
    # === Webhook ===
    path("kratos/hooks/registration/", KratosRegistrationHookView.as_view(), name="kratos-registration-hook"),
    
    # === User API (Esistenti) ===
    path("api/whoami/", WhoAmIView.as_view(), name="whoami"),
    path("api/whoami", WhoAmIView.as_view()),  # alias senza /
    path("api/profile/", RegisterDetailsView.as_view(), name="profile"),
    path("api/profile", RegisterDetailsView.as_view()),  # alias senza /
    
    # === Route legacy (compatibilità) ===
    path("api/registration/details/", RegisterDetailsView.as_view(), name="registration-details"),
]