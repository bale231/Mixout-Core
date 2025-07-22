# apps/authentication/views.py

# Django imports
from django.shortcuts import render
from django.conf import settings

from apps.users.serializers import UserSerializer


# DRF imports
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions



# Third-party imports
import requests


# apps/authentication/views.py

import requests
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from apps.users.models import User

# --- REGISTRAZIONE ---
class RegistrationFlowView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            response = requests.get(
                f"{settings.KRATOS_PUBLIC_URL}/self-service/registration/api",
                timeout=10
            )
            return Response(response.json(), status=response.status_code)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

class RegistrationSubmitView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        flow_id = request.data.get('flow')
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name', '')
        last_name = request.data.get('last_name', '')

        if not all([flow_id, email, password]):
            return Response({'error': 'Missing required fields'}, status=400)

        payload = {
            'method': 'password',
            'password': password,
            'traits.email': email,
            'traits.name.first': first_name,
            'traits.name.last': last_name
        }

        try:
            response = requests.post(
                f"{settings.KRATOS_PUBLIC_URL}/self-service/registration",
                params={'flow': flow_id},
                json=payload,
                timeout=10
            )
            # Se la registrazione va a buon fine, puoi creare/sincronizzare il profilo utente locale
            if response.status_code == 200:
                data = response.json()
                kratos_id = data.get('identity', {}).get('id')
                if kratos_id:
                    User.objects.get_or_create(
                        kratos_id=kratos_id,
                        defaults={
                            'email': email,
                            'first_name': first_name,
                            'last_name': last_name
                        }
                    )
            return Response(response.json(), status=response.status_code)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

# --- LOGIN ---
class LoginFlowView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        try:
            response = requests.get(
                f"{settings.KRATOS_PUBLIC_URL}/self-service/login/api",
                timeout=10
            )
            return Response(response.json(), status=response.status_code)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

class LoginSubmitView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        flow_id = request.data.get('flow')
        email = request.data.get('email')
        password = request.data.get('password')

        if not all([flow_id, email, password]):
            return Response({'error': 'Missing required fields'}, status=400)

        payload = {
            'method': 'password',
            'password_identifier': email,
            'password': password
        }

        try:
            response = requests.post(
                f"{settings.KRATOS_PUBLIC_URL}/self-service/login",
                params={'flow': flow_id},
                json=payload,
                timeout=10
            )
            # Se il login va a buon fine, puoi sincronizzare il profilo utente locale
            if response.status_code == 200:
                data = response.json()
                kratos_id = data.get('session', {}).get('identity', {}).get('id')
                traits = data.get('session', {}).get('identity', {}).get('traits', {})
                if kratos_id:
                    User.objects.get_or_create(
                        kratos_id=kratos_id,
                        defaults={
                            'email': traits.get('email', ''),
                            'first_name': traits.get('name', {}).get('first', ''),
                            'last_name': traits.get('name', {}).get('last', '')
                        }
                    )
            return Response(response.json(), status=response.status_code)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

# --- LOGOUT ---
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        session_cookie = request.COOKIES.get('ory_kratos_session')
        if not session_cookie:
            return Response({'error': 'No session cookie found'}, status=400)
        try:
            response = requests.delete(
                f"{settings.KRATOS_PUBLIC_URL}/sessions",
                cookies={'ory_kratos_session': session_cookie},
                timeout=10
            )
            return Response({'message': 'Logout successful'}, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

# --- WHOAMI / PROFILO UTENTE ---
class WhoAmIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            'id': getattr(user, 'id', None),
            'email': getattr(user, 'email', None),
            'first_name': getattr(user, 'first_name', ''),
            'last_name': getattr(user, 'last_name', ''),
        })

# --- PROFILO UTENTE (dettagli e update) ---
class UserProfileView(RetrieveUpdateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        # Cerca il profilo locale tramite kratos_id
        kratos_id = self.request.user.id
        user, _ = User.objects.get_or_create(
            kratos_id=kratos_id,
            defaults={
                'email': getattr(self.request.user, 'email', ''),
                'first_name': getattr(self.request.user, 'first_name', ''),
                'last_name': getattr(self.request.user, 'last_name', '')
            }
        )
        return user