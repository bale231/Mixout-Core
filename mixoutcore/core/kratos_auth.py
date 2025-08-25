# kratos_auth.py
import os
import requests
from django.http import JsonResponse
from functools import wraps

# Usa l'API PUBBLICA di Kratos per whoami (NON l'admin)
KRATOS_PUBLIC_URL = os.environ.get("KRATOS_PUBLIC_URL", "http://kratos-public:4433")

DEFAULT_TIMEOUT = float(os.environ.get("KRATOS_HTTP_TIMEOUT", "5.0"))

def _extract_session_token(request):
    """
    Ritorna eventuale token di sessione da:
    - Header X-Session-Token
    - Authorization: Bearer <token>
    """
    # X-Session-Token
    xst = request.META.get("HTTP_X_SESSION_TOKEN")
    if xst:
        return xst.strip()

    # Authorization: Bearer
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    return None

def get_kratos_session(request):
    """
    Valida la sessione presso Kratos (public) e ritorna il JSON della sessione
    oppure None se non autenticato/invalid.
    Supporta:
      - Cookie: ory_kratos_session
      - Header: X-Session-Token / Authorization: Bearer
    """
    cookies = {}
    headers = {}
    token = _extract_session_token(request)

    if token:
        headers["X-Session-Token"] = token

    if "ory_kratos_session" in request.COOKIES:
        cookies["ory_kratos_session"] = request.COOKIES["ory_kratos_session"]

    if not headers and not cookies:
        return None  # nessun tentativo di auth presente

    try:
        resp = requests.get(
            f"{KRATOS_PUBLIC_URL}/sessions/whoami",
            headers=headers,
            cookies=cookies,
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    # facoltativo: sanity check che identity.id esista
    if not data.get("identity", {}).get("id"):
        return None

    return data

class KratosSessionMiddleware:
    """
    Popola request.kratos_session (dict) e request.kratos_identity_id (str) se autenticato,
    altrimenti None.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = get_kratos_session(request)
        request.kratos_session = session
        request.kratos_identity_id = None

        if session:
            request.kratos_identity_id = session.get("identity", {}).get("id")

            # 🔽🔽🔽 AUTO-SYNC NELL'ADMIN DJANGO (aggiungi QUI)
            try:
                # import locale per evitare import circolari
                from accounts.models import KratosIdentity # type: ignore
                ident = session.get("identity") or {}
                kid = ident.get("id")
                traits = (ident.get("traits") or {})
                email = traits.get("email")
                # alcune installazioni usano traits.emails: [...]
                if not email and isinstance(traits.get("emails"), list) and traits["emails"]:
                    email = traits["emails"][0]

                if kid:
                    KratosIdentity.objects.update_or_create(
                        kratos_id=kid,
                        defaults={"email": email or "", "traits": traits},
                    )
            except Exception:
                # non bloccare la request se la sync fallisce
                pass
            # 🔼🔼🔼 FINE AUTO-SYNC

        return self.get_response(request)



def kratos_login_required(view_func):
    """
    Decorator per view function-based.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not getattr(request, "kratos_identity_id", None):
            return JsonResponse({"ok": False, "error": {"detail": "Unauthorized"}}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def kratos_required_class_based(cls):
    """
    Decorator per class-based view: applica kratos_login_required a dispatch.
    """
    from django.utils.decorators import method_decorator
    cls.dispatch = method_decorator(kratos_login_required)(cls.dispatch)
    return cls
