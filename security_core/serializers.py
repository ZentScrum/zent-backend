import io
from PIL import Image
from rest_framework import serializers
from security_core.models import (
    OfficialDomain,
    ScanHistory,
    CommunityReport,
    InstitutionalContact,
)


class OfficialDomainSerializer(serializers.ModelSerializer):
    """
    Serializador para consulta y verificación de dominios oficiales de entidades reconocidas.
    """
    class Meta:
        model = OfficialDomain
        fields = (
            'id',
            'entity_name',
            'domain',
            'category',
            'is_active',
            'created_at',
            'updated_at',
        )
        read_only_fields = ('id', 'created_at', 'updated_at')


class ScanHistorySerializer(serializers.ModelSerializer):
    """
    Serializador para el historial de análisis de URLs o teléfonos.
    Garantiza la preservación de la privacidad del usuario y expone metadatos limpios
    compatibles con el dashboard web en Angular y la app móvil.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    target = serializers.CharField(source='analyzed_target', read_only=True)
    type = serializers.CharField(source='target_type', read_only=True)

    class Meta:
        model = ScanHistory
        fields = (
            'id',
            'user',
            'user_email',
            'analyzed_target',
            'target',
            'target_type',
            'type',
            'risk_level',
            'risk_score',
            'reasons',
            'created_at',
        )
        read_only_fields = (
            'id',
            'user',
            'user_email',
            'created_at',
        )


class ScanTargetInputSerializer(serializers.Serializer):
    """
    Serializador de entrada para solicitar el análisis de una URL o un número telefónico.
    Acepta tanto 'target'/'type' como 'target'/'target_type' para máxima compatibilidad con frontend y API specs.
    """
    target = serializers.CharField(required=True, max_length=2048)
    type = serializers.ChoiceField(
        choices=ScanHistory.TargetType.choices,
        required=False,
        help_text="Tipo de objetivo: URL o PHONE"
    )
    target_type = serializers.ChoiceField(
        choices=ScanHistory.TargetType.choices,
        required=False,
        help_text="Alias alternativo para type"
    )

    def validate(self, attrs):
        cleaned_target = attrs.get('target', '').strip()
        if not cleaned_target:
            raise serializers.ValidationError({"target": "El objetivo a analizar no puede estar vacío."})
        attrs['target'] = cleaned_target

        # Unificar type y target_type
        t_type = attrs.get('type') or attrs.get('target_type') or ScanHistory.TargetType.URL
        attrs['type'] = t_type
        attrs['target_type'] = t_type
        return attrs


class CommunityReportSerializer(serializers.ModelSerializer):
    """
    Serializador para el envío y consulta de denuncias ciudadanas.
    Exige la captura de pantalla como evidencia gráfica obligatoria y valida formato con Pillow.
    Expone campos unificados 'target_value' y 'target_type' para consumo en Angular y Android.
    """
    reporter_email = serializers.EmailField(source='reporter.email', read_only=True)
    reviewed_by_email = serializers.EmailField(source='reviewed_by.email', read_only=True)
    target_value = serializers.CharField(source='reported_value', read_only=True)
    target_type = serializers.CharField(source='report_type', read_only=True)

    class Meta:
        model = CommunityReport
        fields = (
            'id',
            'reporter',
            'reporter_email',
            'report_type',
            'target_type',
            'reported_value',
            'target_value',
            'description',
            'evidence_image',
            'status',
            'reviewed_by',
            'reviewed_by_email',
            'created_at',
            'reviewed_at',
            'moderation_notes',
        )
        read_only_fields = (
            'id',
            'reporter',
            'reporter_email',
            'status',
            'reviewed_by',
            'reviewed_by_email',
            'created_at',
            'reviewed_at',
            'moderation_notes',
        )

    def to_internal_value(self, data):
        # Mapeo flexible para clientes móviles y dashboard web
        mutable_data = data.copy() if hasattr(data, 'copy') else dict(data)
        if 'target_value' in mutable_data and 'reported_value' not in mutable_data:
            mutable_data['reported_value'] = mutable_data['target_value']
        if 'target_type' in mutable_data and 'report_type' not in mutable_data:
            t_type = mutable_data['target_type']
            if t_type == 'URL':
                mutable_data['report_type'] = CommunityReport.ReportType.PHISHING_URL
            elif t_type == 'PHONE':
                mutable_data['report_type'] = CommunityReport.ReportType.FRAUD_PHONE
            else:
                mutable_data['report_type'] = t_type
        return super().to_internal_value(mutable_data)

    def validate_evidence_image(self, value):
        if not value:
            raise serializers.ValidationError("El pantallazo de prueba es estrictamente obligatorio para radicar la denuncia.")

        # 1. Validación de tamaño de archivo (máx 10 MB para prevenir DoS en storage)
        max_size = 10 * 1024 * 1024
        if value.size > max_size:
            raise serializers.ValidationError("La imagen probatoria no debe superar los 10 MB.")

        # 2. Validación de integridad y formato con Pillow (JPEG, PNG, WEBP)
        try:
            # Leer buffer inicial sin consumir el stream permanente
            image_content = value.read()
            value.seek(0)
            
            with Image.open(io.BytesIO(image_content)) as img:
                img.verify()  # Valida que sea una imagen válida y no esté corrupta
                img_format = (img.format or '').upper()
                allowed_formats = {'JPEG', 'JPG', 'PNG', 'WEBP'}
                if img_format not in allowed_formats:
                    raise serializers.ValidationError(
                        f"Formato de imagen no permitido ({img_format}). Formatos admitidos: JPEG, PNG, WEBP."
                    )
        except serializers.ValidationError:
            raise
        except Exception as exc:
            raise serializers.ValidationError(f"El archivo subido no es una imagen válida o está corrupta: {str(exc)}")

        return value


class ModerateCommunityReportSerializer(serializers.Serializer):
    """
    Serializador para dictamen de moderación humana (Aprobación o Rechazo).
    """
    status = serializers.ChoiceField(
        choices=[CommunityReport.Status.APPROVED, CommunityReport.Status.REJECTED],
        required=True,
    )
    moderation_notes = serializers.CharField(required=True, min_length=5)


class InstitutionalContactSerializer(serializers.ModelSerializer):
    """
    Serializador para la administración y consulta de la lista blanca institucional.
    """
    class Meta:
        model = InstitutionalContact
        fields = (
            'id',
            'entity_name',
            'phone_or_code',
            'category',
            'description',
            'is_active',
            'created_at',
            'updated_at',
        )
        read_only_fields = ('id', 'created_at', 'updated_at')

