import logging
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.decorators import method_decorator
from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response

try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    def ratelimit(*args, **kwargs):
        def decorator(view_func):
            return view_func
        return decorator


from users.models import UserAuditLog
from users.serializers import (
    RegisterSerializer,
    LoginSerializer,
    UserProfileSerializer,
)

User = get_user_model()
logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Extrae la IP real del cliente considerando reverse proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


class RegisterView(generics.CreateAPIView):
    """
    POST /api/auth/register/
    Registra una nueva cuenta de usuario en Zent validando obligatoriamente
    la aceptación de términos según la Ley 1581 de Habeas Data.
    Protegido con rate limiting contra registros masivos.
    """
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    @method_decorator(ratelimit(key='ip', rate='10/m', block=True))
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Registro de auditoría
        UserAuditLog.objects.create(
            user=user,
            action=UserAuditLog.Action.LOGIN_SUCCESS,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'event': 'account_created'},
        )

        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                "message": "Usuario registrado exitosamente.",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "is_moderator": user.is_moderator,
                    "role": user.role,
                    "accepted_terms": user.accepted_terms,
                    "terms_accepted_at": user.terms_accepted_at,
                }
            },
            status=status.HTTP_201_CREATED,
            headers=headers,
        )


class LoginView(APIView):
    """
    POST /api/auth/login/
    Autentica al usuario por correo y contraseña, generando tokens JWT y retornando
    los datos básicos de perfil y rol con auditoría de ciberseguridad.
    Protegido contra fuerza bruta con rate limit (15 intentos/minuto por IP).
    """
    permission_classes = [permissions.AllowAny]

    @method_decorator(ratelimit(key='ip', rate='15/m', block=True))
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data, context={'request': request})
        ip = get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '')
        email = request.data.get('email', '')

        if not serializer.is_valid():
            # Registro de auditoría para intento fallido
            UserAuditLog.objects.create(
                user=None,
                action=UserAuditLog.Action.LOGIN_FAILURE,
                ip_address=ip,
                user_agent=ua,
                details={'attempted_email': email},
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data

        # Auditoría de inicio de sesión exitoso
        try:
            authenticated_user = User.objects.get(email__iexact=email)
            UserAuditLog.objects.create(
                user=authenticated_user,
                action=UserAuditLog.Action.LOGIN_SUCCESS,
                ip_address=ip,
                user_agent=ua,
            )
        except User.DoesNotExist:
            pass

        return Response(data, status=status.HTTP_200_OK)


class DeleteAccountView(APIView):
    """
    DELETE /api/auth/delete-account/
    Requisito obligatorio de cumplimiento de Google Play Store y Ley 1581 (Habeas Data):
    Permite al usuario autenticado eliminar permanentemente su cuenta y anonimizar
    de forma irreversible sus reportes y escaneos previos.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = request.user
        ip = get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '')

        with transaction.atomic():
            # 1. Anonimizar reportes comunitarios asociados en security_core
            from security_core.models import CommunityReport, ScanHistory

            CommunityReport.objects.filter(reporter=user).update(reporter=None)
            CommunityReport.objects.filter(reviewed_by=user).update(reviewed_by=None)

            # 2. Anonimizar historial de escaneos
            ScanHistory.objects.filter(user=user).update(user=None)

            # 3. Registrar auditoría anónima del borrado
            UserAuditLog.objects.create(
                user=None,
                action=UserAuditLog.Action.ACCOUNT_DELETED,
                ip_address=ip,
                user_agent=ua,
                details={'compliance': 'google_play_and_habeas_data_account_erasure'},
            )

            # 4. Eliminar físicamente al usuario de la base de datos
            user.delete()

        return Response(
            {
                "message": (
                    "Su cuenta ha sido eliminada permanentemente y todos sus reportes "
                    "previos han sido anonimizados conforme a las directivas de Google Play "
                    "y la Ley 1581 de Protección de Datos Personales."
                )
            },
            status=status.HTTP_200_OK,
        )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    GET /api/auth/profile/
    Consulta y actualización del perfil del usuario autenticado.
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class GoogleAuthView(APIView):
    """
    POST /api/auth/google/
    Autentica o registra automáticamente un usuario a partir de un Google ID Token (Credential Manager).
    Valida la autenticidad del token contra los servidores de Google y genera el par de tokens JWT.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        import requests
        from rest_framework_simplejwt.tokens import RefreshToken

        id_token = request.data.get('id_token') or request.data.get('token')
        if not id_token:
            return Response(
                {"error": "El parámetro 'id_token' es obligatorio."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 1. Validar el token con el endpoint de verificación oficial de Google
        try:
            google_res = requests.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": id_token},
                timeout=10
            )
        except Exception as e:
            logger.error(f"Error al contactar API de verificación de Google: {e}")
            return Response(
                {"error": "No se pudo verificar el token de Google. Fallo de conexión externa."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        if google_res.status_code != 200:
            logger.warning(f"Google tokeninfo falló: {google_res.text}")
            return Response(
                {"error": "Token de Google inválido o expirado."},
                status=status.HTTP_400_BAD_REQUEST
            )

        payload = google_res.json()
        email = payload.get('email')
        email_verified = payload.get('email_verified')

        if not email or str(email_verified).lower() not in ('true', '1'):
            return Response(
                {"error": "El correo de la cuenta de Google no es válido o no está verificado."},
                status=status.HTTP_400_BAD_REQUEST
            )

        given_name = payload.get('given_name') or ''
        family_name = payload.get('family_name') or ''

        # 2. Buscar o crear el usuario en Zent
        ip = get_client_ip(request)
        ua = request.META.get('HTTP_USER_AGENT', '')

        with transaction.atomic():
            user, created = User.objects.get_or_create(
                email=email.lower().strip(),
                defaults={
                    'first_name': given_name,
                    'last_name': family_name,
                    'accepted_terms': True,
                    'is_active': True,
                }
            )

            if created:
                user.set_unusable_password()
                user.save()
                UserAuditLog.objects.create(
                    user=user,
                    action=UserAuditLog.Action.LOGIN_SUCCESS,
                    ip_address=ip,
                    user_agent=ua,
                    details={'event': 'account_created_google_oauth'},
                )
            else:
                updated = False
                if not user.first_name and given_name:
                    user.first_name = given_name
                    updated = True
                if not user.last_name and family_name:
                    user.last_name = family_name
                    updated = True
                if updated:
                    user.save(update_fields=['first_name', 'last_name'])

                UserAuditLog.objects.create(
                    user=user,
                    action=UserAuditLog.Action.LOGIN_SUCCESS,
                    ip_address=ip,
                    user_agent=ua,
                    details={'event': 'login_google_oauth'},
                )

        # 3. Generar par de tokens JWT (Refresh + Access)
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "is_moderator": user.is_moderator,
                    "role": user.role,
                    "accepted_terms": user.accepted_terms,
                    "terms_accepted_at": str(user.terms_accepted_at),
                }
            },
            status=status.HTTP_200_OK
        )
