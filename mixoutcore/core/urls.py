# app/urls.py
from django.urls import path
from .views import *

urlpatterns = [
    path("api/registration/details/", RegisterDetailsView.as_view(), name="registration-details"),
]
