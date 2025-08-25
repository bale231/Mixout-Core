from django.db import models

class Identity(models.Model):
    kratos_id = models.CharField(max_length=64, unique=True)
    email = models.EmailField(db_index=True)
    traits = models.JSONField(default=dict, blank=True)  # tutto il tuo schema (goals, ecc.)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.email} ({self.kratos_id})"
