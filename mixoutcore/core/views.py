# app/views.py
import json
from django.views import View
from django.conf import settings
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .models import UserStyleProfile
from accounts.models import Identity
from .kratos_auth import kratos_required_class_based  # se il file è in un'altra app, aggiorna l'import

ALLOWED_FIELDS = {
    "goals", "knowingStyles", "feelingConfident", "wardrobeWeared",
    "wastedResources", "feelingSecure", "feelingAnxious", "ages", "genders",
    "heightUnit", "weightUnit", "bodyShapes", "eyeColors", "hairColors",
    "skinTones", "aestheticStyles",
}

WEBHOOK_TOKEN = getattr(settings, "KRATOS_WEBHOOK_TOKEN", "dev-secret-123")


@method_decorator(csrf_exempt, name="dispatch")
class KratosRegistrationHookView(View):
    """
    Riceve il webhook 'after registration' da Kratos e sincronizza l'utente in Django.
    Payload previsto (da Jsonnet): { identity_id, email, traits }
    """
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

        # upsert in tabella 'accounts.Identity' (per l'admin)
        obj, _ = Identity.objects.update_or_create(
            kratos_id=identity_id,
            defaults={"email": email, "traits": traits},
        )
        return JsonResponse({"ok": True, "kratos_id": obj.kratos_id}, status=200)


@method_decorator(csrf_exempt, name="dispatch")
@kratos_required_class_based
class WhoAmIView(View):
    """
    Ritorna info minime sull'identità Kratos autenticata.
    Richiede sessione valida (cookie ory_kratos_session o X-Session-Token).
    """
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
    """
    Crea/aggiorna il profilo stile dell'utente autenticato (MongoEngine).
    """
    def get(self, request: HttpRequest):
        identity_id = request.kratos_identity_id  # popolato dal middleware
        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first()
        if not obj:
            return JsonResponse({"ok": True, "profile": None}, status=200)
        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)

    def post(self, request: HttpRequest):
        identity_id = request.kratos_identity_id

        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": {"detail": "Invalid JSON"}}, status=400)

        data = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS}

        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first()
        if not obj:
            obj = UserStyleProfile(kratos_identity_id=identity_id)

        for k, v in data.items():
            setattr(obj, k, v)

        try:
            obj.validate()
            obj.save()
        except Exception as e:
            return JsonResponse({"ok": False, "error": {"detail": str(e)}}, status=400)

        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)
