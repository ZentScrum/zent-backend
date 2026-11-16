import uuid
from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _


class OfficialDomain(models.Model):
    """
    Catálogo de dominios oficiales e institucionales para contraste de homoglyphs,
    typosquatting y validación de legitimidad frente a ataques de suplantación.
    """

    class Category(models.TextChoices):
        BANK = 'Banco', _('Banco')
        GOVERNMENT = 'Gobierno', _('Gobierno')
        COURIER = 'Mensajería', _('Mensajería')
        OTHER = 'Otro', _('Otro')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entity_name = models.CharField(
        _('nombre de la entidad'),
        max_length=150,
        help_text=_('Ejemplo: Bancolombia, DIAN, Registraduría'),
    )
    domain = models.CharField(
        _('dominio oficial'),
        max_length=255,
        unique=True,
        db_index=True,
        help_text=_('Ejemplo: bancolombia.com (sin https:// ni rutas)'),
    )
    category = models.CharField(
        _('categoría'),
        max_length=40,
        choices=Category.choices,
        default=Category.OTHER,
        db_index=True,
    )
    is_active = models.BooleanField(
        _('activo'),
        default=True,
        help_text=_('Habilita o deshabilita la verificación de este dominio.'),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('dominio oficial')
        verbose_name_plural = _('dominios oficiales')
        ordering = ['entity_name']

    def __str__(self):
        return f"{self.entity_name} ({self.domain})"

    def clean(self):
        # Normaliza el dominio a minúsculas y sin prefijos http/https ni barras finales
        if self.domain:
            self.domain = (
                self.domain.strip()
                .lower()
                .replace('https://', '')
                .replace('http://', '')
                .split('/')[0]
            )

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class InstitutionalContact(models.Model):
    """
    Lista blanca institucional para proteger números de contacto, códigos cortos de SMS (shortcodes)
    y canales oficiales de entidades reconocidas (bancos, fiscalía, policía, DIAN, etc.).
    Evita falsos positivos y ataques de difamación o brigading contra números legítimos.
    """
    class Category(models.TextChoices):
        BANK = 'Banco', _('Banco / Entidad Financiera')
        GOVERNMENT = 'Gobierno', _('Gobierno / Entidad Pública')
        EMERGENCY = 'Emergencia', _('Línea de Emergencia / Seguridad')
        OTHER = 'Otro', _('Otro Canal Oficial')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entity_name = models.CharField(
        _('nombre de la entidad'),
        max_length=150,
        help_text=_('Ejemplo: Bancolombia, Banco de Bogotá, Fiscalía, Policía Nacional')
    )
    phone_or_code = models.CharField(
        _('número telefónico o código SMS oficial'),
        max_length=50,
        unique=True,
        db_index=True,
        help_text=_('Ejemplo: +573001234567, 890099, 123, +34900123456')
    )
    category = models.CharField(
        _('categoría'),
        max_length=40,
        choices=Category.choices,
        default=Category.OTHER,
        db_index=True
    )
    description = models.CharField(
        _('descripción del canal'),
        max_length=255,
        blank=True,
        help_text=_('Ejemplo: Mensajería transaccional oficial SMS, conmutador central')
    )
    is_active = models.BooleanField(
        _('activo'),
        default=True,
        help_text=_('Habilita o deshabilita la protección de este contacto.')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('contacto institucional oficial')
        verbose_name_plural = _('contactos institucionales oficiales')
        ordering = ['entity_name']

    def __str__(self):
        return f"{self.entity_name} ({self.phone_or_code})"

    def clean(self):
        if self.phone_or_code:
            self.phone_or_code = self.phone_or_code.strip()

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class ScanHistory(models.Model):
    """
    Historial inmutable de análisis de seguridad ejecutados por usuarios o visitantes.
    PRINCIPIO DE PRIVACIDAD: Solo guarda la URL o número telefónico analizado, NUNCA mensajes privados.
    """

    class TargetType(models.TextChoices):
        URL = 'URL', _('URL o Enlace Web')
        PHONE = 'PHONE', _('Número Telefónico')

    class RiskLevel(models.TextChoices):
        SAFE = 'SAFE', _('Seguro')
        SUSPICIOUS = 'SUSPICIOUS', _('Sospechoso')
        DANGEROUS = 'DANGEROUS', _('Peligroso / Amenaza Detectada')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan_histories',
        help_text=_('Usuario autenticado que realizó el escaneo o null si fue anónimo.'),
    )
    analyzed_target = models.CharField(
        _('objetivo analizado'),
        max_length=2048,
        db_index=True,
        help_text=_('Solo guarda la URL o el número analizado. NUNCA mensajes privados ni contenido sensible.'),
    )
    target_type = models.CharField(
        _('tipo de objetivo'),
        max_length=10,
        choices=TargetType.choices,
        db_index=True,
    )
    risk_level = models.CharField(
        _('nivel de riesgo'),
        max_length=20,
        choices=RiskLevel.choices,
        default=RiskLevel.SAFE,
        db_index=True,
    )
    risk_score = models.PositiveSmallIntegerField(
        _('puntaje de riesgo (0-100)'),
        default=0,
        help_text=_('Puntaje normalizado de 0 (seguro) a 100 (peligroso).'),
    )
    reasons = models.JSONField(
        _('alertas y razones detectadas'),
        default=list,
        blank=True,
        help_text=_('Lista estructurada de alertas o razones que fundamentan el dictamen de riesgo.'),
    )
    created_at = models.DateTimeField(
        _('fecha de análisis'),
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        verbose_name = _('historial de escaneo')
        verbose_name_plural = _('historiales de escaneo')
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.risk_level} - {self.risk_score}/100] {self.analyzed_target}"


class CommunityReport(models.Model):
    """
    Denuncias comunitarias de ciberfraudes con evidencia gráfica obligatoria.
    Inicia obligatoriamente en PENDING para moderación humana previa antes de alertar a la comunidad.
    """

    class ReportType(models.TextChoices):
        PHISHING_URL = 'PHISHING_URL', _('URL de Phishing')
        HACKED_WHATSAPP = 'HACKED_WHATSAPP', _('WhatsApp Hackeado / Suplantación')
        FRAUD_PHONE = 'FRAUD_PHONE', _('Número Telefónico Fraudulento')

    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pendiente de Moderación')
        APPROVED = 'APPROVED', _('Aprobado / Verificado')
        REJECTED = 'REJECTED', _('Rechazado / Falsa Alarma')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='community_reports',
        help_text=_('Usuario que envía la denuncia. Al borrar la cuenta se anonimiza automáticamente a NULL.'),
    )
    report_type = models.CharField(
        _('tipo de reporte'),
        max_length=30,
        choices=ReportType.choices,
        db_index=True,
    )
    reported_value = models.CharField(
        _('valor reportado'),
        max_length=2048,
        db_index=True,
        help_text=_('URL fraudulenta o número telefónico del estafador.'),
    )
    description = models.TextField(
        _('descripción de los hechos'),
        help_text=_('Detalle de cómo se originó el intento de fraude.'),
    )
    evidence_image = models.ImageField(
        _('pantallazo de prueba obligatorio'),
        upload_to='evidence/community/%Y/%m/',
        help_text=_('Captura de pantalla como soporte probatorio de la denuncia.'),
    )
    status = models.CharField(
        _('estado de moderación'),
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
        help_text=_('Inicia en PENDING para moderación humana obligatoria y prevención de falsas denuncias.'),
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_reports',
        help_text=_('Moderador o analista que dictaminó la aprobación o rechazo.'),
    )
    created_at = models.DateTimeField(
        _('fecha de reporte'),
        auto_now_add=True,
        db_index=True,
    )
    reviewed_at = models.DateTimeField(
        _('fecha de moderación'),
        null=True,
        blank=True,
    )
    moderation_notes = models.TextField(
        _('notas de moderación'),
        blank=True,
        help_text=_('Justificación del moderador para aprobar o rechazar la denuncia.'),
    )

    class Meta:
        verbose_name = _('reporte comunitario')
        verbose_name_plural = _('reportes comunitarios')
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.status}] {self.get_report_type_display()}: {self.reported_value}"
