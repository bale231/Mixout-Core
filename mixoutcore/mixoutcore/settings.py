"""
Django settings for mixoutcore project.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# === Core ===
SECRET_KEY = 'django-insecure-+lv_@x&uwr+l9gfhu)=&o%y7c7xq%tr2%&e$!5q$tbcde#he2i'
DEBUG = True

# Accetta richieste da 127.0.0.1/localhost/0.0.0.0 in dev (docker)
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "0.0.0.0", "django"]

# Se fai POST/redirect cross-origin da UI → Django, aggiungi gli origin fidati
CSRF_TRUSTED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:4455",
    "http://localhost:4455",
    "http://127.0.0.1:4433",  # Kratos public
    "http://localhost:4433",  # Kratos public
]

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    'core',
    "django.contrib.postgres",
    # Se usi django-cors-headers:
    "corsheaders",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",  # Aggiungo CORS
    "django.middleware.security.SecurityMiddleware",
    'whitenoise.middleware.WhiteNoiseMiddleware',
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.kratos_auth.KratosSessionMiddleware",  # Il tuo middleware esistente
]

ROOT_URLCONF = "mixoutcore.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "mixoutcore.wsgi.application"

# === Database Configuration ===
# Configurazione per supportare sia database locale (Docker) che remoto (OVH)

# Se POSTGRES_HOST è "postgres", usa configurazione Docker
if os.getenv("POSTGRES_HOST") == "postgres":
    # Configurazione Docker - database unificato
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "mixoutcore"),
            "USER": os.getenv("POSTGRES_USER", "mixout"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD"),
            "HOST": os.getenv("POSTGRES_HOST", "postgres"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {
                "sslmode": "disable",  # No SSL per Docker locale
                "options": "-c search_path=public"  # Django usa schema public
            },
        }
    }
else:
    # Configurazione OVH - database remoto
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "mixoutcore"),
            "USER": os.getenv("POSTGRES_USER"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD"),
            "HOST": os.getenv("POSTGRES_HOST"),
            "PORT": os.getenv("POSTGRES_PORT", "20184"),
            "CONN_MAX_AGE": 60,
            "OPTIONS": {"sslmode": "require"},  # TLS per OVH
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# I18N / TZ
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / 'staticfiles'

# WhiteNoise: auto-reload in debug (comodo in dev)
WHITENOISE_AUTOREFRESH = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Cookie policy (dev defaults ok, ma esplicito per chiarezza)
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# === Kratos Configuration ===
KRATOS_ADMIN_URL = os.getenv("KRATOS_ADMIN_URL", "http://localhost:4434")
KRATOS_PUBLIC_URL = os.getenv("KRATOS_PUBLIC_URL", "http://localhost:4433")
KRATOS_WEBHOOK_TOKEN = os.getenv("KRATOS_WEBHOOK_TOKEN", "dev-secret-123")

# === CORS Configuration ===
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://127.0.0.1:4455",    # Kratos UI
    "http://localhost:4455",    # Kratos UI
    "http://127.0.0.1:4433",    # Kratos Public
    "http://localhost:4433",    # Kratos Public
    "http://127.0.0.1:8000",    # Django stesso
    "http://localhost:8000",    # Django stesso
    "http://127.0.0.1:3000",    # Frontend (se usi React/Vue/etc)
    "http://localhost:3000",    # Frontend (se usi React/Vue/etc)
]

CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
    'x-session-token',
    'x-kratos-webhook-token',
    'cookie',
]

CORS_ALLOWED_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# === Logging Configuration ===
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose' if DEBUG else 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'core.views': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'core.kratos_auth': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}