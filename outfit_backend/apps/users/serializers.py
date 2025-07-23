# apps/users/serializers.py
# This file contains serializers for the User model, which is used to represent users in the system.

from rest_framework import serializers
from .models import User

# Serializer for the User model
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['kratos_id', 'email', 'first_name', 'last_name', 'created_at', 'updated_at']
        read_only_fields = ['kratos_id', 'email', 'created_at', 'updated_at']