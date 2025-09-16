# core/views.py
import json
import logging
import requests
from django.views import View
from django.conf import settings
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ValidationError
from django.shortcuts import render

from .models import *
from accounts.models import Identity
from .kratos_auth import kratos_required_class_based

logger = logging.getLogger(__name__)

ALLOWED_FIELDS = {
    "goals", "knowingStyles", "feelingConfident", "wardrobeWeared",
    "wastedResources", "feelingSecure", "feelingAnxious", "ages", "genders",
    "heightUnit", "weightUnit", "bodyShapes", "eyeColors", "hairColors",
    "skinTones", "aestheticStyles",
}

WEBHOOK_TOKEN = getattr(settings, "KRATOS_WEBHOOK_TOKEN", "dev-secret-123")

# === Utility Functions ===
@csrf_exempt
def debug_register(request):
    try:
        if request.method == 'POST':
            data = json.loads(request.body)
            return JsonResponse({
                'status': 'success',
                'received_data': data,
                'message': 'Debug endpoint working'
            })
        else:
            return JsonResponse({'error': 'Method not allowed'}, status=405)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
@csrf_exempt
@require_http_methods(["POST"])
def proxy_to_kratos(path, method='GET', data=None, headers=None):
    """Fa proxy di una richiesta verso Kratos"""
    kratos_url = f"{settings.KRATOS_ADMIN_URL.rstrip('/')}/{path.lstrip('/')}"
    
    request_headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    if headers:
        request_headers.update(headers)
    
    try:
        if method == 'GET':
            response = requests.get(kratos_url, headers=request_headers, timeout=10)
        elif method == 'POST':
            response = requests.post(kratos_url, json=data, headers=request_headers, timeout=10)
        elif method == 'PUT':
            response = requests.put(kratos_url, json=data, headers=request_headers, timeout=10)
        
        return response # type: ignore
    except requests.RequestException as e:
        logger.error(f"Errore connessione a Kratos: {e}")
        return None

# === Auth UI View ===
@csrf_exempt
def auth_ui(request):
    return render(request, 'core/auth.html')

# === Proxy Views for Kratos (Per frontend semplice) ===
@csrf_exempt
def proxy_registration(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
        
    try:
        # Parse i dati dal frontend
        data = json.loads(request.body)
        
        # Log per debug
        logger.info(f"Received registration data: {data}")
        
        # Usa requests.Session per mantenere i cookie
        session = requests.Session()
        
        # 1. Inizializza il flow di registrazione
        flow_response = session.get(
            'http://kratos:4433/self-service/registration/browser',
            headers={'Accept': 'application/json'}
        )
        
        if flow_response.status_code != 200:
            logger.error(f"Failed to initialize flow: {flow_response.status_code} - {flow_response.text}")
            return JsonResponse({'error': 'Failed to initialize flow'}, status=400)
            
        flow_data = flow_response.json()
        logger.info(f"Flow initialized: {flow_data['id']}")
        
        # 2. Estrai il CSRF token dal flow
        csrf_token = None
        for node in flow_data.get('ui', {}).get('nodes', []):
            if node.get('attributes', {}).get('name') == 'csrf_token':
                csrf_token = node.get('attributes', {}).get('value')
                break
        
        if not csrf_token:
            logger.error("CSRF token not found in flow")
            return JsonResponse({'error': 'CSRF token not found'}, status=400)
        
        logger.info(f"Found CSRF token: {csrf_token}")
        
        # 3. Prepara i dati per Kratos con CSRF token
        registration_data = {
            'flow': flow_data['id'],
            'method': 'password',
            'traits': data.get('traits', {}),
            'password': data.get('password', ''),
            'csrf_token': csrf_token  # ← Aggiungi questo
        }
        
        logger.info(f"Sending to Kratos with CSRF: {registration_data}")
        
        # 4. Invia la registrazione usando la stessa sessione
        register_response = session.post(
            f'http://kratos:4433/self-service/registration?flow={flow_data["id"]}',
            json=registration_data,
            headers={
                'Content-Type': 'application/json', 
                'Accept': 'application/json'
            }
        )
        
        logger.info(f"Kratos response: {register_response.status_code}")
        
        if register_response.status_code == 200:
            return JsonResponse({'success': True, 'message': 'Registrazione completata!'})
        else:
            try:
                error_data = register_response.json()
                logger.error(f"Kratos error: {error_data}")
                return JsonResponse({'error': error_data}, status=register_response.status_code)
            except:
                logger.error(f"Kratos error (raw): {register_response.text}")
                return JsonResponse({'error': 'Registration failed'}, status=register_response.status_code)
            
    except Exception as e:
        logger.error(f"Exception in proxy_registration: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

# === Webhook Views ===
@method_decorator(csrf_exempt, name="dispatch")
class KratosRegistrationHookView(View):
    def post(self, request: HttpRequest):
        token = request.headers.get("X-Kratos-Webhook-Token")
        if token != WEBHOOK_TOKEN:
            return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            return JsonResponse({"ok": False, "error": "bad json"}, status=400)

        identity_id = payload.get("identity_id") or (payload.get("identity") or {}).get("id")
        traits = payload.get("traits") or (payload.get("identity") or {}).get("traits") or {}
        email = payload.get("email") or traits.get("email") or ""

        if not identity_id:
            return JsonResponse({"ok": False, "error": "missing identity_id"}, status=400)

        obj, _ = Identity.objects.update_or_create(
            kratos_id=identity_id,
            defaults={"email": email, "traits": traits},
        )
        
        logger.info(f"Webhook registrazione: {identity_id} - {email}")
        return JsonResponse({"ok": True, "kratos_id": obj.kratos_id}, status=200)

# === Auth API Views (Nuove) ===
@method_decorator(csrf_exempt, name="dispatch")
class LoginView(View):
    """Handle login flow via Kratos API"""
    
    def get(self, request):
        """Inizia il flow di login"""
        response = proxy_to_kratos('self-service/login/browser')
        
        if not response or response.status_code != 200:
            return JsonResponse({'error': 'Errore inizializzazione login'}, status=500)
        
        flow_data = response.json()
        
        return JsonResponse({
            'flow_id': flow_data['id'],
            'action': flow_data['ui']['action'],
            'method': flow_data['ui']['method'],
            'nodes': flow_data['ui']['nodes'],
            'messages': flow_data.get('ui', {}).get('messages', [])
        })
    
    def post(self, request):
        """Sottometti le credenziali di login"""
        try:
            data = json.loads(request.body)
            flow_id = data.get('flow_id')
            
            if not flow_id:
                return JsonResponse({'error': 'Flow ID richiesto'}, status=400)
            
            submit_data = {
                'method': 'password',
                'identifier': data.get('email'),
                'password': data.get('password'),
                'csrf_token': data.get('csrf_token')
            }
            
            response = proxy_to_kratos(
                f'self-service/login?flow={flow_id}',
                method='POST',
                data=submit_data
            )
            
            if not response:
                return JsonResponse({'error': 'Errore login'}, status=500)
            
            if response.status_code == 200:
                result = response.json()
                session_token = result.get('session_token')
                
                json_response = JsonResponse({
                    'success': True,
                    'session': result.get('session'),
                    'identity': result.get('identity')
                })
                
                if session_token:
                    json_response.set_cookie(
                        'ory_kratos_session',
                        session_token,
                        max_age=86400,
                        httponly=True,
                        secure=not settings.DEBUG
                    )
                
                return json_response
            else:
                error_data = response.json()
                return JsonResponse({
                    'success': False,
                    'errors': error_data.get('ui', {}).get('messages', [])
                }, status=400)
                
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON non valido'}, status=400)

@method_decorator(csrf_exempt, name="dispatch")
class RegistrationView(View):
    """Handle registration flow via Kratos API"""
    
    def get(self, request):
        """Inizia il flow di registrazione"""
        response = proxy_to_kratos('self-service/registration/browser')
        
        if not response or response.status_code != 200:
            return JsonResponse({'error': 'Errore inizializzazione registrazione'}, status=500)
        
        flow_data = response.json()
        
        return JsonResponse({
            'flow_id': flow_data['id'],
            'action': flow_data['ui']['action'],
            'method': flow_data['ui']['method'],
            'nodes': flow_data['ui']['nodes'],
            'messages': flow_data.get('ui', {}).get('messages', [])
        })
    
    def post(self, request):
        """Sottometti i dati di registrazione"""
        try:
            data = json.loads(request.body)
            flow_id = data.get('flow_id')
            
            if not flow_id:
                return JsonResponse({'error': 'Flow ID richiesto'}, status=400)
            
            # Prepara i dati traits per Kratos
            traits_data = {
                'email': data.get('email'),
                'goals': data.get('goals', []),
                'knowingStyles': data.get('knowingStyles'),
                'feelingConfident': data.get('feelingConfident'),
                'wardrobeWeared': data.get('wardrobeWeared'),
                'wastedResources': data.get('wastedResources'),
                'feelingSecure': data.get('feelingSecure'),
                'feelingAnxious': data.get('feelingAnxious'),
                'ages': data.get('ages'),
                'genders': data.get('genders'),
                'heightUnit': data.get('heightUnit'),
                'weightUnit': data.get('weightUnit'),
                'bodyShapes': data.get('bodyShapes'),
                'eyeColors': data.get('eyeColors'),
                'hairColors': data.get('hairColors'),
                'skinTones': data.get('skinTones'),
                'aestheticStyles': data.get('aestheticStyles')
            }
            
            submit_data = {
                'method': 'password',
                'password': data.get('password'),
                'traits': traits_data,
                'csrf_token': data.get('csrf_token')
            }
            
            response = proxy_to_kratos(
                f'self-service/registration?flow={flow_id}',
                method='POST',
                data=submit_data
            )
            
            if not response:
                return JsonResponse({'error': 'Errore registrazione'}, status=500)
            
            if response.status_code == 200:
                result = response.json()
                session_token = result.get('session_token')
                
                json_response = JsonResponse({
                    'success': True,
                    'session': result.get('session'),
                    'identity': result.get('identity')
                })
                
                if session_token:
                    json_response.set_cookie(
                        'ory_kratos_session',
                        session_token,
                        max_age=86400,
                        httponly=True,
                        secure=not settings.DEBUG
                    )
                
                return json_response
            else:
                error_data = response.json()
                return JsonResponse({
                    'success': False,
                    'errors': error_data.get('ui', {}).get('messages', [])
                }, status=400)
                
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON non valido'}, status=400)

@method_decorator(csrf_exempt, name="dispatch")
class SessionView(View):
    """Gestione sessione utente"""
    
    def get(self, request):
        """Ottieni informazioni sulla sessione corrente"""
        session_token = request.COOKIES.get('ory_kratos_session') or \
                       request.headers.get('X-Session-Token')
        
        if not session_token:
            return JsonResponse({'authenticated': False}, status=401)
        
        response = proxy_to_kratos(
            'sessions/whoami',
            headers={'Cookie': f'ory_kratos_session={session_token}'}
        )
        
        if not response or response.status_code != 200:
            return JsonResponse({'authenticated': False}, status=401)
        
        session_data = response.json()
        
        return JsonResponse({
            'authenticated': True,
            'identity': session_data.get('identity'),
            'session': session_data
        })

@method_decorator(csrf_exempt, name="dispatch")
class LogoutView(View):
    """Handle logout"""
    
    def post(self, request):
        """Effettua logout"""
        session_token = request.COOKIES.get('ory_kratos_session') or \
                       request.headers.get('X-Session-Token')
        
        if session_token:
            proxy_to_kratos(
                'self-service/logout/browser',
                headers={'Cookie': f'ory_kratos_session={session_token}'}
            )
        
        response = JsonResponse({'success': True})
        response.delete_cookie('ory_kratos_session')
        return response

@method_decorator(csrf_exempt, name="dispatch")
class CallbackView(View):
    """Callback dopo operazioni Kratos"""
    
    def get(self, request):
        """Gestisce i callback da Kratos"""
        return JsonResponse({'status': 'callback_received'})

# === Existing Views (Mantenute) ===
@method_decorator(csrf_exempt, name="dispatch")
@kratos_required_class_based
class WhoAmIView(View):
    def get(self, request: HttpRequest):
        session = getattr(request, "kratos_session", None) or {}
        identity = session.get("identity") or {}
        return JsonResponse({
            "ok": True,
            "identity_id": getattr(request, "kratos_identity_id", None),
            "traits": identity.get("traits"),
        }, status=200)

@method_decorator(csrf_exempt, name="dispatch")
@kratos_required_class_based
class RegisterDetailsView(View):
    def get(self, request: HttpRequest):
        identity_id = request.kratos_identity_id # pyright: ignore[reportAttributeAccessIssue]
        obj = UserStyleProfile.objects.filter(kratos_identity_id=identity_id).first()
        if not obj:
            return JsonResponse({"ok": True, "profile": None}, status=200)
        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)

    def post(self, request: HttpRequest):
        identity_id = request.kratos_identity_id # pyright: ignore[reportAttributeAccessIssue]
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": {"detail": "Invalid JSON"}}, status=400)

        data = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS}

        obj, _created = UserStyleProfile.objects.get_or_create(
            kratos_identity_id=identity_id,
            defaults=data
        )
        if not _created:
            for k, v in data.items():
                setattr(obj, k, v)

        try:
            obj.full_clean()  # valida choices/required
            obj.save()
        except ValidationError as e:
            return JsonResponse({"ok": False, "error": e.message_dict or e.messages}, status=400)

        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)