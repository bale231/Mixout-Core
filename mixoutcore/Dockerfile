# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on

WORKDIR /app

# System deps (build + runtime)
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Project
COPY . /app

# Static (se serve, opzionale in build)
# ENV DJANGO_SETTINGS_MODULE=mixoutcore.settings
# RUN python manage.py collectstatic --noinput || true

# Gunicorn
EXPOSE 8000
CMD ["gunicorn", "mixoutcore.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "90"]
