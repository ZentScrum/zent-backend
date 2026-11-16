# 🛡️ Zent - Anti-Phishing & Fraud Prevention Platform (Backend)

Backend modular desarrollado con **Django 5** y **Django REST Framework (DRF)** para la detección, análisis y mitigación de amenazas digitales (Phishing, Smishing, Vishing y Robo de Credenciales) bajo estándares de **Ciberseguridad Defensiva**, **Ley 1581 de 2012 (Habeas Data)** y las directivas de **Google Play Store** sobre eliminación de cuentas y anonimización de datos.

---

## 🏛️ Arquitectura del Sistema

```
zent-backend/
├── manage.py                          # Gestor de comandos de Django
├── requirements.txt                   # Dependencias fijadas y auditadas
├── .env.example                       # Plantilla documentada de variables de entorno
├── .env                               # Variables locales y credenciales Supabase
├── .gitignore                         # Exclusiones de seguridad para Git
├── zent_core/                         # Configuración central del proyecto
│   ├── __init__.py
│   ├── settings.py                    # Hardening de cabeceras, SimpleJWT y Supabase
│   ├── urls.py                        # Enrutamiento maestro y health-check
│   ├── wsgi.py                        # Punto de entrada WSGI
│   └── asgi.py                        # Punto de entrada ASGI
├── users/                             # App: Autenticación, Roles y Ley 1581 (Habeas Data)
│   ├── admin.py                       # Panel administrativo con auditoría inmutable
│   ├── apps.py
│   ├── models.py                      # User (AbstractUser con email, is_moderator, accepted_terms)
│   ├── serializers.py                 # Serializadores de registro, login y perfil
│   ├── urls.py                        # /api/auth/ (register, login, delete-account)
│   ├── views.py                       # Vistas con auditoría de ciberseguridad y borrado Google Play
│   └── management/
│       └── commands/
│           └── seed_admin.py          # Seeder de superusuario por defecto (admin@zent.security)
└── security_core/                     # App: Análisis de Amenazas y Moderación Ciudadana
    ├── admin.py                       # Panel administrativo y acciones masivas de moderación
    ├── apps.py
    ├── models.py                      # OfficialDomain, ScanHistory, CommunityReport
    ├── permissions.py                 # Permiso RBAC IsModeratorOrAdmin
    ├── serializers.py                 # Serializadores de análisis, historial y denuncias
    ├── urls.py                        # /api/security/
    ├── views.py                       # Escaneo instantáneo, historial y flujo de moderación
    ├── management/
    │   └── commands/
    │       └── seed_official_domains.py # Seeder de los 25 dominios más suplantados en Colombia
    └── services/                      # Lógica desacoplada de Threat Intelligence
        ├── url_scanner.py             # Google Safe Browsing v4 & VirusTotal v3
        └── phone_checker.py           # Normalización E.164 y heurística de riesgo
```

---

## 🔒 Especificaciones de Modelos y Ciberseguridad

### 1. App `users`
- **Modelo `User` (hereda de `AbstractUser`):**
  - Identificador único de inicio de sesión: `email` (`USERNAME_FIELD = 'email'`).
  - `is_moderator`: Boolean (`default=False`), define permisos de revisión de denuncias ciudadanas.
  - `accepted_terms`: Boolean (`default=True`), validación obligatoria en registro bajo la Ley 1581 de 2012 de Habeas Data.
  - `terms_accepted_at`: DateTime (`auto_now_add=True`), marca temporal inmutable de consentimiento legal.
- **Endpoints de Autenticación (`/api/auth/`):**
  - `POST /api/auth/register/`: Exige que `accepted_terms` sea `True`.
  - `POST /api/auth/login/`: Retorna tokens JWT (`access`, `refresh`) + datos del usuario (`id`, `email`, `role`, `is_moderator`, etc.).
  - `DELETE /api/auth/delete-account/`: Exigencia de Google Play y Habeas Data. Elimina la cuenta y desvincula/anonimiza irreversiblemente todos sus reportes y escaneos previos (`reporter=None`, `user=None`).

### 2. App `security_core`
- **Modelo `OfficialDomain`:**
  - `entity_name`, `domain` (único), `category` (Banco, Gobierno, Mensajería, Otro), `is_active`.
- **Modelo `ScanHistory`:**
  - `user` (ForeignKey nullable, `on_delete=SET_NULL`), `analyzed_target` (solo guarda URL o teléfono, NUNCA mensajes privados), `target_type` (URL, PHONE), `risk_level` (SAFE, SUSPICIOUS, DANGEROUS), `risk_score` (0 a 100), `reasons` (JSONField con lista de alertas), `created_at`.
- **Modelo `CommunityReport`:**
  - `reporter` (ForeignKey nullable, `on_delete=SET_NULL`), `report_type` (PHISHING_URL, HACKED_WHATSAPP, FRAUD_PHONE), `reported_value`, `description`, `evidence_image` (ImageField obligatorio), `status` (PENDING, APPROVED, REJECTED - default PENDING para moderación humana previa), `reviewed_by` (ForeignKey a User), `created_at`.

---

## 🚀 Guía de Instalación y Ejecución Paso a Paso

### 1. Clonar el Repositorio y Ubicarse en el Directorio
```bash
cd zent-backend
```

### 2. Crear y Activar el Entorno Virtual

**En Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**En Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Instalar Dependencias

```bash
pip install -r requirements.txt
```

---

### 4. Configurar Variables de Entorno

Asegúrate de que el archivo `.env` contenga la cadena de conexión a tu base de datos PostgreSQL en Supabase:

```ini
SECRET_KEY=django-insecure-zent-platform-dev-key-change-in-production-!#a8$9z_q
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1,[::1]

# Conexión a Supabase (PostgreSQL Pooler o Direct):
DATABASE_URL=postgresql://postgres:[PASSWORD]@[HOST]:[PORT]/postgres?sslmode=require

# Orígenes CORS permitidos:
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Claves de Threat Intelligence (Opcionales para dev):
GOOGLE_SAFE_BROWSING_API_KEY=tu_clave_de_google_cloud
VIRUSTOTAL_API_KEY=tu_clave_de_virustotal
```

---

### 5. Ejecutar Migraciones de Base de Datos

Las migraciones ya se encuentran generadas en el código fuente:

```bash
python manage.py migrate
```

---

### 6. Cargar los 25 Dominios Oficiales de Colombia (Seeder)

Ejecuta el comando para poblar automáticamente los 25 dominios más suplantados (Bancos, Billeteras digitales, Entidades de Gobierno y Empresas de Mensajería):

```bash
python manage.py seed_official_domains
```

---

### 7. Crear o Inicializar el Superusuario Administrador

El sistema incluye una migración automática (`0002_create_default_admin`) y un comando de semilla (`seed_admin`) que crea el superusuario por defecto para desarrollo y monitoreo web:

```bash
# Se ejecuta automáticamente en migrate, o manualmente con:
python manage.py seed_admin

# Credenciales generadas:
# Correo: admin@zent.security
# Contraseña: AdminSecure2026!
```

O si deseas crear uno personalizado:
```bash
python manage.py createsuperuser
```

---

### 8. Iniciar el Servidor de Desarrollo

```bash
python manage.py runserver
```

El backend estará disponible en: `http://127.0.0.1:8000/`

---

## 📡 Catálogo de Endpoints REST

| Método | Endpoint | Descripción | Acceso |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health/` | Health check de disponibilidad | Público |
| `POST` | `/api/auth/register/` | Registro con validación de Ley 1581 (`accepted_terms`) | Público |
| `POST` | `/api/auth/login/` | Autenticación email/password (JWT + datos de usuario) | Público |
| `DELETE` | `/api/auth/delete-account/` | Eliminación definitiva de cuenta y anonimización (Google Play) | Autenticado |
| `POST` | `/api/auth/token/refresh/` | Renovación de access tokens | Público con Refresh |
| `GET/PATCH` | `/api/auth/profile/` | Consulta y actualización de perfil | Autenticado |
| `POST` | `/api/security/scan/` | Análisis en tiempo real de URLs o teléfonos (IOCs) | Rate-limited |
| `GET` | `/api/security/domains/` | Catálogo de dominios oficiales de Colombia | Público / Autenticado |
| `GET` | `/api/security/scans/history/` | Historial personal de análisis del usuario | Autenticado |
| `GET/POST`| `/api/security/community-reports/` | Listar y radicar denuncias (inician en PENDING) | Autenticado |
| `POST` | `/api/security/community-reports/{id}/moderate/` | Dictamen de moderación (Aprobar/Rechazar) | Rol `is_moderator` / `ADMIN` |
