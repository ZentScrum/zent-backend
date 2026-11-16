from django.utils import timezone
from rest_framework import viewsets, permissions, status, generics
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.pagination import PageNumberPagination
from django.utils.decorators import method_decorator

try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    # Fallback si django-ratelimit no está disponible en algún entorno
    def ratelimit(*args, **kwargs):
        def decorator(view_func):
            return view_func
        return decorator

from security_core.models import (
    OfficialDomain,
    ScanHistory,
    CommunityReport,
    InstitutionalContact,
)
from security_core.serializers import (
    OfficialDomainSerializer,
    ScanHistorySerializer,
    ScanTargetInputSerializer,
    CommunityReportSerializer,
    ModerateCommunityReportSerializer,
    InstitutionalContactSerializer,
)
from security_core.permissions import IsModeratorOrAdmin
from security_core.services.analyzer import analyze_target


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 50


class OfficialDomainViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Consulta del catálogo de dominios oficiales verificados de Colombia.
    Permite a la aplicación frontend y móviles validar instantáneamente la legitimidad.
    """
    queryset = OfficialDomain.objects.filter(is_active=True)
    serializer_class = OfficialDomainSerializer
    permission_classes = [permissions.AllowAny]
    search_fields = ['entity_name', 'domain']
    filterset_fields = ['category']


class AnalyzeTargetView(APIView):
    """
    POST /api/security/analyze/ (y /api/security/scan/ por retrocompatibilidad)
    
    Analiza una URL o número telefónico contra el motor heurístico anti-phishing,
    detección de typosquatting contra OfficialDomain, bases comunitarias de fraude y APIs externas.
    
    Guarda el registro en ScanHistory (asociado al usuario si está autenticado, o anónimo si no).
    Protegido contra abusos con ratelimit (30 peticiones/minuto por IP).
    """
    permission_classes = [permissions.AllowAny]

    @method_decorator(ratelimit(key='ip', rate='30/m', block=True))
    def post(self, request, *args, **kwargs):
        serializer = ScanTargetInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        target = serializer.validated_data['target']
        target_type = serializer.validated_data['target_type']

        # Ejecutar el motor heurístico unificado
        analysis_result = analyze_target(target, target_type)

        risk_level = analysis_result['risk_level']
        risk_score = analysis_result['risk_score']
        reasons = analysis_result['reasons']

        # Registrar en ScanHistory (respetando la privacidad)
        user = request.user if request.user.is_authenticated else None
        scan_record = ScanHistory.objects.create(
            user=user,
            analyzed_target=target,
            target_type=target_type,
            risk_level=risk_level,
            risk_score=risk_score,
            reasons=reasons,
        )

        response_data = {
            "id": str(scan_record.id),
            "analyzed_target": scan_record.analyzed_target,
            "target_type": scan_record.target_type,
            "risk_level": scan_record.risk_level,
            "risk_score": scan_record.risk_score,
            "reasons": scan_record.reasons,
            "created_at": scan_record.created_at,
        }
        
        # Añadir campos informativos adicionales si existen (ej. verified_reports_count)
        if 'verified_reports_count' in analysis_result:
            response_data['verified_reports_count'] = analysis_result['verified_reports_count']
        if 'sanitized_phone' in analysis_result:
            response_data['sanitized_phone'] = analysis_result['sanitized_phone']

        return Response(response_data, status=status.HTTP_200_OK)


class ScanHistoryListView(generics.ListAPIView):
    """
    GET /api/security/history/
    Lista el historial de escaneos del usuario autenticado ordenado por fecha reciente.
    """
    serializer_class = ScanHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return ScanHistory.objects.filter(user=self.request.user).order_by('-created_at')


class ScanHistoryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet para historial de escaneos personales del usuario autenticado.
    """
    serializer_class = ScanHistorySerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return ScanHistory.objects.filter(user=self.request.user).order_by('-created_at')


class CommunityReportCreateView(generics.CreateAPIView):
    """
    POST /api/security/reports/
    Permite crear un CommunityReport (soporta multipart/form-data para subir evidence_image),
    validando tamaño/formato de imagen con Pillow y dejándolo en estado PENDING.
    """
    serializer_class = CommunityReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def perform_create(self, serializer):
        serializer.save(
            reporter=self.request.user,
            status=CommunityReport.Status.PENDING,
        )


class CommunityReportFeedView(generics.ListAPIView):
    """
    GET /api/security/reports/feed/
    Feed público paginado de amenazas recientes con estado APPROVED para alertar a la comunidad.
    """
    serializer_class = CommunityReportSerializer
    permission_classes = [permissions.AllowAny]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return CommunityReport.objects.filter(
            status=CommunityReport.Status.APPROVED
        ).order_by('-created_at')


class ModerateReportView(APIView):
    """
    PATCH /api/security/reports/<int:pk>/moderate/ y /api/security/reports/<uuid:pk>/moderate/
    Endpoint exclusivo para usuarios con is_moderator=True (o staff/admin)
    para dictaminar aprobación o rechazo de reportes pendientes.
    """
    permission_classes = [IsModeratorOrAdmin]

    def patch(self, request, pk, *args, **kwargs):
        try:
            report = CommunityReport.objects.get(pk=pk)
        except (CommunityReport.DoesNotExist, ValueError):
            return Response(
                {"error": "El reporte solicitado no existe."},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = ModerateCommunityReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data['status']
        notes = serializer.validated_data['moderation_notes']

        report.status = new_status
        report.moderation_notes = notes
        report.reviewed_by = request.user
        report.reviewed_at = timezone.now()
        report.save(update_fields=['status', 'moderation_notes', 'reviewed_by', 'reviewed_at'])

        return Response(
            {
                "message": f"Reporte moderado con éxito. Estado actualizado a '{report.get_status_display()}'.",
                "report_id": str(report.id),
                "status": report.status,
                "reviewed_by": request.user.email,
                "reviewed_at": report.reviewed_at,
                "moderation_notes": report.moderation_notes,
            },
            status=status.HTTP_200_OK,
        )


class CommunityReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet completo de gestión de denuncias comunitarias.
    """
    serializer_class = CommunityReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        user = self.request.user
        if user.is_moderator or user.is_staff or user.is_superuser:
            return CommunityReport.objects.all().order_by('-created_at')
        return CommunityReport.objects.filter(reporter=user).order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(
            reporter=self.request.user,
            status=CommunityReport.Status.PENDING,
        )

    @action(
        detail=True,
        methods=['patch', 'post'],
        permission_classes=[IsModeratorOrAdmin],
        url_path='moderate',
    )
    def moderate(self, request, pk=None):
        report = self.get_object()
        serializer = ModerateCommunityReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_status = serializer.validated_data['status']
        notes = serializer.validated_data['moderation_notes']

        report.status = new_status
        report.moderation_notes = notes
        report.reviewed_by = request.user
        report.reviewed_at = timezone.now()
        report.save(update_fields=['status', 'moderation_notes', 'reviewed_by', 'reviewed_at'])

        return Response(
            {
                "message": f"Reporte moderado con éxito como '{report.get_status_display()}'.",
                "report_id": str(report.id),
                "status": report.status,
                "reviewed_by": request.user.email,
                "reviewed_at": report.reviewed_at,
                "moderation_notes": report.moderation_notes,
            },
            status=status.HTTP_200_OK,
        )


class InstitutionalContactViewSet(viewsets.ModelViewSet):
    """
    CRUD completo para la lista blanca institucional de números y códigos SMS protegidos.
    """
    queryset = InstitutionalContact.objects.all().order_by('entity_name')
    serializer_class = InstitutionalContactSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    search_fields = ['entity_name', 'phone_or_code', 'description']
    filterset_fields = ['category', 'is_active']


class DashboardStatsView(APIView):
    """
    GET /api/security/stats/
    Retorna métricas consolidadas en tiempo real para las tarjetas KPI del Dashboard administrativo:
    - total_scans
    - threats_blocked (DANGEROUS)
    - suspicious_scans (SUSPICIOUS)
    - safe_scans (SAFE)
    - active_reports (PENDING + APPROVED)
    - pending_reports (PENDING)
    - whitelist_contacts (InstitutionalContact activos)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        total_scans = ScanHistory.objects.count()
        threats_blocked = ScanHistory.objects.filter(risk_level=ScanHistory.RiskLevel.DANGEROUS).count()
        suspicious_scans = ScanHistory.objects.filter(risk_level=ScanHistory.RiskLevel.SUSPICIOUS).count()
        safe_scans = ScanHistory.objects.filter(risk_level=ScanHistory.RiskLevel.SAFE).count()
        pending_reports = CommunityReport.objects.filter(status=CommunityReport.Status.PENDING).count()
        approved_reports = CommunityReport.objects.filter(status=CommunityReport.Status.APPROVED).count()
        active_reports = pending_reports + approved_reports
        whitelist_contacts = InstitutionalContact.objects.filter(is_active=True).count()

        return Response({
            "total_scans": total_scans,
            "threats_blocked": threats_blocked,
            "suspicious_scans": suspicious_scans,
            "safe_scans": safe_scans,
            "active_reports": active_reports,
            "pending_reports": pending_reports,
            "whitelist_contacts": whitelist_contacts,
        }, status=status.HTTP_200_OK)

