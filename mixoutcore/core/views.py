# core/views.py
import json
import logging
import requests
from django.views import View
from django.conf import settings
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
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
@method_decorator(csrf_exempt, name="dispatch")
class AuthUIView(View):
    def get(self, request):
        return render(request, 'core/auth.html')

# === Proxy Views (Per UI personalizzata) ===
@method_decorator(csrf_exempt, name="dispatch")
class ProxyRegistrationView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            logger.info(f"Received registration data: {data}")
            
            # Usa i cookie del browser dell'utente
            cookies = request.COOKIES
            headers = {
                'Accept': 'application/json',
                'User-Agent': request.headers.get('User-Agent', ''),
            }
            
            # Se ci sono cookie di Kratos, passali
            cookie_header = '; '.join([f"{k}={v}" for k, v in cookies.items() if k.startswith('ory_kratos')])
            if cookie_header:
                headers['Cookie'] = cookie_header
            
            # 1. Inizializza flow registrazione CON i cookie dell'utente
            flow_response = requests.get(
                'http://kratos:4433/self-service/registration/browser',
                headers=headers
            )
            
            if flow_response.status_code != 200:
                logger.error(f"Failed to initialize flow: {flow_response.status_code}")
                return JsonResponse({'success': False, 'error': 'Errore inizializzazione flow'}, status=400)
            
            flow_data = flow_response.json()
            logger.info(f"Flow initialized: {flow_data['id']}")
            
            # 2. Estrai CSRF token
            csrf_token = None
            for node in flow_data.get('ui', {}).get('nodes', []):
                if node.get('attributes', {}).get('name') == 'csrf_token':
                    csrf_token = node.get('attributes', {}).get('value')
                    break
            
            if not csrf_token:
                logger.error("CSRF token not found in flow")
                return JsonResponse({'success': False, 'error': 'CSRF token mancante'}, status=400)
            
            logger.info(f"Found CSRF token: {csrf_token[:20]}...")
            
            # 3. Prepara dati con formato corretto per Kratos
            form_data = {
                'flow': flow_data['id'],
                'method': 'password',
                'csrf_token': csrf_token,
                'password': data.get('password', ''),
                'traits.email': data.get('traits', {}).get('email', ''),
            }
            
            # Aggiungi tutti i traits come campi separati
            for key, value in data.get('traits', {}).items():
                if key != 'email':  # email già aggiunta
                    if isinstance(value, list):
                        # Per array come goals, aggiungi come campi multipli
                        for i, item in enumerate(value):
                            form_data[f'traits.{key}.{i}'] = item
                    else:
                        form_data[f'traits.{key}'] = value
            
            logger.info(f"Form data keys: {list(form_data.keys())}")
            
            # 4. Prepara i cookie dalla risposta del flow
            request_cookies = {}
            for cookie in flow_response.cookies:
                request_cookies[cookie.name] = cookie.value
            
            # Combina con i cookie esistenti
            all_cookies = {**dict(cookies), **request_cookies}
            
            # 5. Invia come form data, non JSON
            action_url = flow_data.get('ui', {}).get('action', '').replace('localhost:4433', 'kratos:4433')
            
            register_response = requests.post(
                action_url,
                data=form_data,  # form data, non json
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': '; '.join([f"{k}={v}" for k, v in all_cookies.items()])
                },
                cookies=all_cookies,
                allow_redirects=False
            )
            
            logger.info(f"Registration response: {register_response.status_code}")
            logger.info(f"Response headers: {dict(register_response.headers)}")
            
            if register_response.status_code == 200:
                response_data = JsonResponse({'success': True, 'message': 'Registrazione completata!'})
                
                # Propaga eventuali cookie di sessione dal response di Kratos
                for cookie in register_response.cookies:
                    response_data.set_cookie(
                        cookie.name, 
                        cookie.value, # type: ignore
                        max_age=cookie.expires,
                        domain=cookie.domain,
                        path=cookie.path,
                        secure=cookie.secure,
                        httponly=cookie.get('HttpOnly', False) # type: ignore
                    )
                
                return response_data
                
            elif register_response.status_code in [302, 303]:
                # Redirect - registrazione probabilmente riuscita
                return JsonResponse({'success': True, 'message': 'Registrazione completata!'})
                
            else:
                try:
                    error_data = register_response.json()
                    logger.error(f"Kratos error: {error_data}")
                    
                    # Gestisci errori specifici
                    user_messages = []
                    
                    error_id = error_data.get('error', {}).get('id')
                    if error_id == 'security_csrf_violation':
                        user_messages.append('Errore di sicurezza. Ricarica la pagina e riprova.')
                    elif error_id == 'session_already_available':
                        user_messages.append('Sei già loggato. Ricarica la pagina.')
                    else:
                        ui_messages = error_data.get('ui', {}).get('messages', [])
                        for message in ui_messages:
                            message_id = message.get('id', 0)
                            message_text = message.get('text', '')
                            
                            if message_id == 4000007 or 'exists already' in message_text.lower():
                                user_messages.append('Un account con questa email esiste già.')
                            elif 'password' in message_text.lower() and ('policy' in message_text.lower() or 'weak' in message_text.lower()):
                                user_messages.append('La password non rispetta i criteri di sicurezza.')
                            elif 'email' in message_text.lower() and 'invalid' in message_text.lower():
                                user_messages.append('L\'indirizzo email non è valido.')
                            elif 'required' in message_text.lower():
                                user_messages.append('Tutti i campi obbligatori devono essere compilati.')
                            else:
                                user_messages.append(message_text)
                    
                    if not user_messages:
                        user_messages.append('Errore durante la registrazione. Controlla i dati inseriti.')
                    
                    return JsonResponse({
                        'success': False,
                        'error': user_messages[0],
                        'errors': user_messages,
                    }, status=400)
                    
                except Exception as json_error:
                    logger.error(f"Failed to parse Kratos error: {json_error}")
                    logger.error(f"Raw response: {register_response.text}")
                    return JsonResponse({
                        'success': False, 
                        'error': 'Errore durante la registrazione. Riprova.'
                    }, status=400)
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in request: {e}")
            return JsonResponse({'success': False, 'error': 'Dati non validi'}, status=400)
        except Exception as e:
            logger.error(f"Exception in proxy_registration: {str(e)}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return JsonResponse({'success': False, 'error': 'Errore del server. Riprova.'}, status=500)
        
@method_decorator(csrf_exempt, name="dispatch")
class ProxyLoginView(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
            logger.info(f"Received login data: {data.get('identifier', 'no email')}")
            
            # Usa i cookie del browser dell'utente
            cookies = request.COOKIES
            headers = {
                'Accept': 'application/json',
                'User-Agent': request.headers.get('User-Agent', ''),
            }
            
            # Se ci sono cookie di Kratos, passali
            cookie_header = '; '.join([f"{k}={v}" for k, v in cookies.items() if k.startswith('ory_kratos')])
            if cookie_header:
                headers['Cookie'] = cookie_header
            
            # 1. Inizializza flow login CON i cookie dell'utente
            flow_response = requests.get(
                'http://kratos:4433/self-service/login/browser',
                headers=headers
            )
            
            if flow_response.status_code != 200:
                logger.error(f"Failed to initialize login flow: {flow_response.status_code}")
                return JsonResponse({'success': False, 'error': 'Errore inizializzazione login'}, status=400)
            
            flow_data = flow_response.json()
            logger.info(f"Login flow initialized: {flow_data['id']}")
            
            # 2. Estrai CSRF token
            csrf_token = None
            for node in flow_data.get('ui', {}).get('nodes', []):
                if node.get('attributes', {}).get('name') == 'csrf_token':
                    csrf_token = node.get('attributes', {}).get('value')
                    break
            
            if not csrf_token:
                logger.error("CSRF token not found in login flow")
                return JsonResponse({'success': False, 'error': 'CSRF token mancante'}, status=400)
            
            logger.info(f"Found login CSRF token: {csrf_token[:20]}...")
            
            # 3. Prepara dati login come form data
            form_data = {
                'flow': flow_data['id'],
                'method': 'password',
                'csrf_token': csrf_token,
                'identifier': data.get('identifier', ''),
                'password': data.get('password', '')
            }
            
            logger.info(f"Login form data keys: {list(form_data.keys())}")
            
            # 4. Prepara i cookie dalla risposta del flow
            request_cookies = {}
            for cookie in flow_response.cookies:
                request_cookies[cookie.name] = cookie.value
            
            # Combina con i cookie esistenti
            all_cookies = {**dict(cookies), **request_cookies}
            
            # 5. Invia login come form data
            action_url = flow_data.get('ui', {}).get('action', '').replace('localhost:4433', 'kratos:4433')
            
            login_response = requests.post(
                action_url,
                data=form_data,  # form data, non json
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Cookie': '; '.join([f"{k}={v}" for k, v in all_cookies.items()])
                },
                cookies=all_cookies,
                allow_redirects=False
            )
            
            logger.info(f"Kratos login response: {login_response.status_code}")
            logger.info(f"Login response headers: {dict(login_response.headers)}")
            
            if login_response.status_code == 200:
                response_data = JsonResponse({'success': True, 'message': 'Login effettuato con successo!'})
                
                # Propaga eventuali cookie di sessione dal response di Kratos
                for cookie in login_response.cookies:
                    response_data.set_cookie(
                        cookie.name, 
                        cookie.value, # type: ignore
                        max_age=getattr(cookie, 'max_age', None),
                        domain=getattr(cookie, 'domain', None),
                        path=getattr(cookie, 'path', '/'),
                        secure=getattr(cookie, 'secure', False),
                        httponly=hasattr(cookie, 'httponly') and cookie.httponly # type: ignore
                    )
                
                return response_data
                
            elif login_response.status_code in [302, 303]:
                # Redirect - login probabilmente riuscito
                response_data = JsonResponse({'success': True, 'message': 'Login effettuato con successo!'})
                
                # Propaga cookie anche nei redirect
                for cookie in login_response.cookies:
                    response_data.set_cookie(
                        cookie.name, 
                        cookie.value, # type: ignore
                        max_age=getattr(cookie, 'max_age', None),
                        domain=getattr(cookie, 'domain', None),
                        path=getattr(cookie, 'path', '/'),
                        secure=getattr(cookie, 'secure', False),
                        httponly=hasattr(cookie, 'httponly') and cookie.httponly # type: ignore
                    )
                
                return response_data
                
            else:
                try:
                    error_data = login_response.json()
                    logger.error(f"Kratos login error: {error_data}")
                    
                    # Gestisci errori login
                    user_messages = []
                    
                    error_id = error_data.get('error', {}).get('id')
                    if error_id == 'security_csrf_violation':
                        user_messages.append('Errore di sicurezza. Ricarica la pagina e riprova.')
                    elif error_id == 'session_already_available':
                        user_messages.append('Sei già loggato.')
                        return JsonResponse({'success': True, 'message': 'Già loggato'})
                    else:
                        ui_messages = error_data.get('ui', {}).get('messages', [])
                        for message in ui_messages:
                            message_text = message.get('text', '')
                            message_id = message.get('id', 0)
                            
                            if message_id == 4000006 or 'credentials are invalid' in message_text.lower() or 'invalid' in message_text.lower():
                                user_messages.append('Email o password non corretti.')
                            elif 'account does not exist' in message_text.lower() or 'no such user' in message_text.lower():
                                user_messages.append('Account non trovato. Verifica l\'email inserita.')
                            elif 'required' in message_text.lower():
                                user_messages.append('Email e password sono obbligatori.')
                            else:
                                user_messages.append(message_text)
                    
                    if not user_messages:
                        user_messages.append('Errore durante il login. Verifica le credenziali.')
                    
                    return JsonResponse({
                        'success': False,
                        'error': user_messages[0]
                    }, status=400)
                    
                except Exception as json_error:
                    logger.error(f"Failed to parse login error: {json_error}")
                    logger.error(f"Raw login response: {login_response.text}")
                    return JsonResponse({
                        'success': False, 
                        'error': 'Errore durante il login. Riprova.'
                    }, status=400)
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in login request: {e}")
            return JsonResponse({'success': False, 'error': 'Dati non validi'}, status=400)
        except Exception as e:
            logger.error(f"Exception in proxy_login: {str(e)}")
            import traceback
            logger.error(f"Full login traceback: {traceback.format_exc()}")
            return JsonResponse({'success': False, 'error': 'Errore del server. Riprova.'}, status=500)
        
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

# === Auth API Views (Per frontend avanzati) ===
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

# === User API Views (Esistenti) ===
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
        identity_id = request.kratos_identity_id # type: ignore
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
            obj.full_clean()
            obj.save()
        except ValidationError as e:
            return JsonResponse({"ok": False, "error": e.message_dict or e.messages}, status=400)

        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)