# core/urls.py
from django.urls import path
from .views import *

urlpatterns = [
    # alias comodi
    path("api/whoami",                          WhoAmIView.as_view()),
    path("api/whoami/",                         WhoAmIView.as_view()),
    path("api/profile",                         RegisterDetailsView.as_view()),
    path("kratos/hooks/registration",           KratosRegistrationHookView.as_view(),                 name="kratos-registration-hook"),

    # Route “vecchia”
    path("api/registration/details/",           RegisterDetailsView.as_view(),                        name="registration-details"),
]
