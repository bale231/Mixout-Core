# app/views.py
import json
from django.views import View
from django.http import JsonResponse, HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .models import UserStyleProfile
from .kratos_auth import kratos_required_class_based  # usa il tuo decorator class-based

ALLOWED_FIELDS = {
    "goals", "knowingStyles", "feelingConfident", "wardrobeWeared",
    "wastedResources", "feelingSecure", "feelingAnxious", "ages", "genders",
    "heightUnit", "weightUnit", "bodyShapes", "eyeColors", "hairColors",
    "skinTones", "aestheticStyles",
}

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
        identity_id = request.kratos_identity_id # pyright: ignore[reportAttributeAccessIssue]
        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first() # pyright: ignore[reportAttributeAccessIssue]
        if not obj:
            return JsonResponse({"ok": True, "profile": None}, status=200)
        return JsonResponse({"ok": True, "profile": obj.to_dict()}, status=200)

    def post(self, request: HttpRequest):
        identity_id = request.kratos_identity_id # pyright: ignore[reportAttributeAccessIssue]

        # parse JSON
        try:
            payload = json.loads(request.body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return JsonResponse({"ok": False, "error": {"detail": "Invalid JSON"}}, status=400)

        data = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS}

        obj = UserStyleProfile.objects(kratos_identity_id=identity_id).first() # type: ignore
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
