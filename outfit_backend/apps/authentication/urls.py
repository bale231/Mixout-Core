# apps/authentication/urls.py

from django.urls import path
from .views import *

# URL patterns for authentication-related views
urlpatterns = [
    # Registration endpoints
    path('register/flow/',                          RegistrationFlowView.as_view(),                     name='get_registration_flow'),
    path('register/submit/',                        RegistrationSubmitView.as_view(),                   name='submit_registration_flow'),

    # Login endpoints
    path('login/flow/',                             LoginFlowView.as_view(),                            name='get_login_flow'),
    path('login/submit/',                           LoginSubmitView.as_view(),                          name='submit_login_flow'),
    path('logout/',                                 LogoutView.as_view(),                               name='logout'),

    # Account endpoints
    path('whoami/',                                 WhoAmIView.as_view(),                               name='whoami'),
    path('profile/',                                UserProfileView.as_view(),                          name='user_profile'),
]