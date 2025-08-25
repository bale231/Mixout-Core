from django.core.management.base import BaseCommand
from django.conf import settings
from urllib.request import Request, urlopen
import json, os

from accounts.models import Identity

KRATOS_ADMIN = os.getenv("KRATOS_ADMIN_URL", "http://kratos:4434")

class Command(BaseCommand):
    help = "Sincronizza le identities da Ory Kratos Admin API dentro il DB Django"

    def add_arguments(self, parser):
        parser.add_argument("--per-page", type=int, default=250)

    def handle(self, *args, **opts):
        per_page = opts["per_page"]
        url = f"{KRATOS_ADMIN}/identities?per_page={per_page}"
        self.stdout.write(f"Fetching: {url}")
        req = Request(url, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        created, updated = 0, 0
        for it in data:
            kid = it["id"]
            traits = it.get("traits", {}) or {}
            email = traits.get("email") or traits.get("emails", [None])[0]
            obj, was_created = Identity.objects.update_or_create(
                kratos_id=kid,
                defaults={"email": email or "", "traits": traits},
            )
            created += 1 if was_created else 0
            updated += 0 if was_created else 1

        self.stdout.write(self.style.SUCCESS(
            f"Done. created={created}, updated={updated}, total={len(data)}"
        ))
