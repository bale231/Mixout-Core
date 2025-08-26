# core/kratos_auth.py
import os, requests, logging
from django.http import JsonResponse
from functools import wraps

log = logging.getLogger(__name__)

KRATOS_PUBLIC_URL = os.environ.get("KRATOS_PUBLIC_URL", "http://kratos:4433")
DEFAULT_TIMEOUT = float(os.environ.get("KRATOS_HTTP_TIMEOUT", "5.0"))

def _extract_session_token(request):
    xst = request.META.get("HTTP_X_SESSION_TOKEN")
    if xst:
        return xst.strip()
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def get_kratos_session(request):
    cookies, headers = {}, {}
    token = _extract_session_token(request)
    if token:
        headers["X-Session-Token"] = token
    if "ory_kratos_session" in request.COOKIES:
        cookies["ory_kratos_session"] = request.COOKIES["ory_kratos_session"]

    if not headers and not cookies:
        return None

    try:
        r = requests.get(f"{KRATOS_PUBLIC_URL}/sessions/whoami",
                         headers=headers, cookies=cookies, timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get("identity", {}).get("id"):
            return None
        return data
    except requests.RequestException as e:
        log.warning("whoami request failed: %s", e)
        return None

class KratosSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = get_kratos_session(request)
        request.kratos_session = session
        request.kratos_identity_id = session.get("identity", {}).get("id") if session else None

        # 🔽 AUTO-SYNC nell’admin usando accounts.Identity
        if session and request.kratos_identity_id:
            try:
                from accounts.models import Identity
                ident  = session.get("identity") or {}
                traits = ident.get("traits") or {}
                email  = traits.get("email")
                if not email and isinstance(traits.get("emails"), list) and traits["emails"]:
                    email = traits["emails"][0]

                Identity.objects.update_or_create(
                    kratos_id=request.kratos_identity_id,
                    defaults={"email": email or "", "traits": traits},
                )
            except Exception as e:
                # Niente crash, ma lasciamo traccia nei log
                log.error("Identity autosync failed: %s", e)

        return self.get_response(request)

def kratos_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not getattr(request, "kratos_identity_id", None):
            return JsonResponse({"ok": False, "error": {"detail": "Unauthorized"}}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def kratos_required_class_based(cls):
    from django.utils.decorators import method_decorator
    cls.dispatch = method_decorator(kratos_login_required)(cls.dispatch)
    return cls
