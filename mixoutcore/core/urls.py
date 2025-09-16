# core/urls.py
from django.urls import path
from .views import *

urlpatterns = [
    # === Auth API (Nuove) ===
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/register/", RegistrationView.as_view(), name="auth-register"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/session/", SessionView.as_view(), name="auth-session"),
    path("auth/callback/", CallbackView.as_view(), name="auth-callback"),
    path('auth/', auth_ui, name='auth'),
    
    # === Webhook ===
    path("kratos/hooks/registration/", KratosRegistrationHookView.as_view(), name="kratos-registration-hook"),
    
    # === User API (Esistenti - mantenute per compatibilità) ===
    path("api/whoami/", WhoAmIView.as_view(), name="whoami"),
    path("api/whoami", WhoAmIView.as_view()),  # alias senza /
    path("api/profile/", RegisterDetailsView.as_view(), name="profile"),
    path("api/profile", RegisterDetailsView.as_view()),  # alias senza /
    
    # Route "vecchia" per compatibilità
    path("api/registration/details/", RegisterDetailsView.as_view(), name="registration-details"),
]