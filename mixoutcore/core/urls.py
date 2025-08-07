from django.urls import path
from .views import *

urlpatterns = [
    path('books/', books_list),
    path('mongo-test/', mongo_test),
    path('secret-data/', secret_data),
]