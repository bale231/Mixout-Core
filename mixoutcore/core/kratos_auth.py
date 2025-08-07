import requests
from django.http import JsonResponse
from functools import wraps

KRATOS_ADMIN_URL = "http://kratos:4434"  # Usa 'kratos' se sei in Docker, altrimenti 'localhost'

def get_kratos_session(request):
    session_cookie = request.COOKIES.get('ory_kratos_session')
    if not session_cookie:
        return None
    try:
        resp = requests.get(
            f"{KRATOS_ADMIN_URL}/sessions/whoami",
            cookies={'ory_kratos_session': session_cookie},
            timeout=3
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print("Errore chiamata Kratos:", e)
    return None

class KratosSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.kratos_session = get_kratos_session(request)
        return self.get_response(request)

def kratos_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not getattr(request, 'kratos_session', None):
            return JsonResponse({'error': 'Not authenticated'}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view