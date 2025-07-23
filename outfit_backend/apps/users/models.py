from django.db import models

# This model represents a user in the system, linked to an identity provider like Ory Kratos.
class User(models.Model):
    kratos_id = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    # altri campi aggiuntivi (es. preferenze, avatar, ecc.)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.email} ({self.kratos_id})"