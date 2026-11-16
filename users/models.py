import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """
    Manager personalizado para el modelo User donde el email es el identificador único
    para la autenticación en lugar del username.
    """

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('El correo electrónico es obligatorio.'))
        email = self.normalize_email(email)
        extra_fields.setdefault('is_active', True)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_moderator', True)
        extra_fields.setdefault('accepted_terms', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser debe tener is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser debe tener is_superuser=True.'))

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Modelo de Usuario extendido desde AbstractUser usando email como identificador único.
    Incluye campos específicos para moderación y cumplimiento de Ley 1581 de 2012 (Habeas Data).
    """

    # Desactivamos el campo username predeterminado de Django
    username = None

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('correo electrónico'), unique=True, db_index=True)

    # Rol de moderación de contenido y denuncias ciudadanas
    is_moderator = models.BooleanField(
        _('es moderador'),
        default=False,
        help_text=_('Indica si el usuario tiene privilegios para revisar y moderar reportes comunitarios.'),
    )

    # Cumplimiento Ley 1581 de 2012 (Habeas Data) y Políticas de Privacidad
    accepted_terms = models.BooleanField(
        _('términos y condiciones aceptados'),
        default=True,
        help_text=_('Obligatorio según la Ley 1581 de 2012 de Protección de Datos Personales.'),
    )
    terms_accepted_at = models.DateTimeField(
        _('fecha de aceptación de términos'),
        auto_now_add=True,
        help_text=_('Registro temporal inmutable del momento de aceptación de términos.'),
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = _('usuario')
        verbose_name_plural = _('usuarios')
        ordering = ['-date_joined']

    def __str__(self):
        role_tag = "Moderador" if self.is_moderator else ("Admin" if self.is_staff else "Ciudadano")
        return f"{self.email} ({role_tag})"

    @property
    def role(self) -> str:
        if self.is_superuser or self.is_staff:
            return "ADMIN"
        if self.is_moderator:
            return "MODERATOR"
        return "USER"


class UserAuditLog(models.Model):
    """
    Registro inmutable de auditoría para eventos críticos de autenticación y seguridad de usuarios.
    """

    class Action(models.TextChoices):
        LOGIN_SUCCESS = 'LOGIN_SUCCESS', _('Inicio de Sesión Exitoso')
        LOGIN_FAILURE = 'LOGIN_FAILURE', _('Fallo de Autenticación')
        LOGOUT = 'LOGOUT', _('Cierre de Sesión')
        ACCOUNT_DELETED = 'ACCOUNT_DELETED', _('Cuenta Eliminada (Google Play / Habeas Data)')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
    )
    action = models.CharField(max_length=40, choices=Action.choices)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name = _('registro de auditoría de usuario')
        verbose_name_plural = _('registros de auditoría de usuarios')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.created_at} | {self.action} | {self.ip_address}"
