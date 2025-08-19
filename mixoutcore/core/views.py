# app/views.py
import json
import os
import requests
from django.views import View
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .models import UserStyleProfile

KRATOS_PUBLIC_URL = os.environ.get("KRATOS_PUBLIC_URL", "http://kratos-public:4433")

ALLOWED_FIELDS = {
    "goals", "knowingStyles", "feelingConfident", "wardrobeWeared",
    "wastedResources", "feelingSecure", "feelingAnxious", "ages", "genders",
    "heightUnit", "weightUnit", "bodyShapes", "eyeColors", "hairColors",
    "skinTones", "aestheticStyles",
}

def get_bearer_token(request: HttpRequest):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None

def resolve_kratos_identity_id(request: HttpRequest):
    """
    Ricava l'identity id di Kratos controllando:
    - header X-Session-Token
    - Authorization: Bearer <token>
    - cookie ory_kratos_session
    Chiama /sessions/whoami del public API di Kratos per validare la sessione.
    """
    session_token = request.META.get("HTTP_X_SESSION_TOKEN") or get_bearer_token(request)
    cookies = {}
    if "ory_kratos_session" in request.COOKIES:
        cookies["ory_kratos_session"] = request.COOKIES["ory_kratos_session"]

    headers = {}
    if session_token:
        headers["X-Session-Token"] = session_token

    try:
        r = requests.get(
            f"{KRATOS_PUBLIC_URL}/sessions/whoami",
            headers=headers,
            cookies=cookies,
            timeout=5,
        )
        if r.status_code != 200:
            return None, {"status": r.status_code, "detail": "Invalid Kratos session"}
        data = r.json()
        identity_id = data.get("identity", {}).get("id")
        return identity_id, None
    except requests.RequestException as e:
        return None, {"status": 503, "detail": f"Kratos not reachable: {e}"}

@method_decorator(csrf_exempt, name="dispatch")
class RegisterDetailsView(View):
    """
    POST /api/registration/details/  -> crea/aggiorna i dettagli del profilo stilistico per l'utente corrente (Kratos)
    GET  /api/registration/details/  -> ritorna i dettagli salvati per l'utente corrente
    """

    def get(self, request: HttpRequest):
        identity_id, err = resolve_kratos_identity_id(request)
        if not identity_id:
            status = err.get("status", 401) if err else 401
            return JsonResponse({"ok": False, "error": err or {"detail": "Unauthorized"}}, status=status)

        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first()
        if not obj:
            return JsonResponse({"ok": True, "profile": None}, status=200)
        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)

    def post(self, request: HttpRequest):
        identity_id, err = resolve_kratos_identity_id(request)
        if not identity_id:
            status = err.get("status", 401) if err else 401
            return JsonResponse({"ok": False, "error": err or {"detail": "Unauthorized"}}, status=status)

        # parse JSON
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": {"detail": "Invalid JSON"}}, status=400)

        # filtra solo i campi consentiti
        data = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS}

        # upsert
        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first()
        if not obj:
            obj = UserStyleProfile(kratos_identity_id=identity_id)

        # assegna i campi
        for k, v in data.items():
            setattr(obj, k, v)

        # valida e salva
        try:
            obj.validate()
            obj.save()
        except Exception as e:
            # mongoengine ValidationError o altri errori
            return JsonResponse({"ok": False, "error": {"detail": str(e)}}, status=400)

        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)
