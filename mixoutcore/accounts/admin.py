from django.contrib import admin
from .models import Identity

@admin.register(Identity)
class IdentityAdmin(admin.ModelAdmin):
    list_display = ("email", "kratos_id", "created_at")
    search_fields = ("email", "kratos_id")
    readonly_fields = ("created_at",)
