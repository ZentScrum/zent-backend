"""
Django settings for Zent Anti-Phishing & Digital Fraud Prevention Platform.

Architected with defense-in-depth principles:
- Environment segregation via python-dotenv
- Zero-trust default permissions
- Hardened HTTP security headers
- Ephemeral JWT lifetime with rotation
- Direct compatibility with Supabase PostgreSQL connection pooling
"""

import os
from datetime import timedelta
from pathlib import Path
import dj_database_url
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / '.env')

# ------------------------------------------------------------------------------
# CORE SECURITY CONFIGURATION
# ------------------------------------------------------------------------------
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("CRITICAL SECURITY ERROR: SECRET_KEY environment variable is not set.")

# Explicitly cast DEBUG to boolean; defaults to False for fail-safe security
DEBUG = os.getenv('DEBUG', 'False').strip().lower() in ('true', '1', 't', 'yes')

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1],10.0.2.2,*').split(',')
    if host.strip()
]
if DEBUG and '*' not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append('*')

# ------------------------------------------------------------------------------
# APPLICATION DEFINITION
# ------------------------------------------------------------------------------
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
]

LOCAL_APPS = [
    'users.apps.UsersConfig',
    'security_core.apps.SecurityCoreConfig',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # High priority for CORS handling
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'zent_core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'zent_core.wsgi.application'
ASGI_APPLICATION = 'zent_core.asgi.application'

# ------------------------------------------------------------------------------
# DATABASE CONFIGURATION (Supabase PostgreSQL / dj-database-url)
# ------------------------------------------------------------------------------
DATABASE_URL = os.getenv('DATABASE_URL', f"sqlite:///{BASE_DIR / 'db.sqlite3'}")

DATABASES = {
    'default': dj_database_url.config(
        default=DATABASE_URL,
        conn_max_age=600,
        ssl_require=not DEBUG and 'sqlite' not in DATABASE_URL,
    )
}

# ------------------------------------------------------------------------------
# CUSTOM USER MODEL & AUTHENTICATION
# ------------------------------------------------------------------------------
AUTH_USER_MODEL = 'users.User'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Enforce enterprise-grade password length
        },
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# ------------------------------------------------------------------------------
# REST FRAMEWORK & SIMPLEJWT
# ------------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/minute',
        'user': '300/minute',
    },
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ) if not DEBUG else (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': False,
    'UPDATE_LAST_LOGIN': True,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': 'zent-auth-service',
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',
}

# ------------------------------------------------------------------------------
# CORS CONFIGURATION
# ------------------------------------------------------------------------------
raw_cors = os.getenv('CORS_ALLOWED_ORIGINS', '')
CORS_ALLOWED_ORIGINS = [
    origin.strip() for origin in raw_cors.split(',') if origin.strip()
]
# Soporte integral para desarrollo y dashboard web (Angular 4200, Vite 5173, etc.)
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
    default_dev_origins = [
        "http://localhost:4200",
        "http://127.0.0.1:4200",
        "http://localhost:3000",
        "http://localhost:5173",
    ]
    for origin in default_dev_origins:
        if origin not in CORS_ALLOWED_ORIGINS:
            CORS_ALLOWED_ORIGINS.append(origin)

CORS_ALLOW_CREDENTIALS = True

# ------------------------------------------------------------------------------
# HARDENED HTTP SECURITY HEADERS
# ------------------------------------------------------------------------------
# Prevent MIME type sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# Protect against clickjacking
X_FRAME_OPTIONS = 'DENY'

# Legacy XSS protection filter for compatible browsers
SECURE_BROWSER_XSS_FILTER = True

# Strict-Transport-Security & HTTPS enforcement for Production
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ------------------------------------------------------------------------------
# THREAT INTELLIGENCE APIS
# ------------------------------------------------------------------------------
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

# ------------------------------------------------------------------------------
# INTERNATIONALIZATION & STATIC / MEDIA
# ------------------------------------------------------------------------------
LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'