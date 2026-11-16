import re
from django.urls import path, include, register_converter
from rest_framework.routers import DefaultRouter

from security_core.views import (
    OfficialDomainViewSet,
    AnalyzeTargetView,
    ScanHistoryListView,
    ScanHistoryViewSet,
    CommunityReportCreateView,
    CommunityReportFeedView,
    ModerateReportView,
    CommunityReportViewSet,
    InstitutionalContactViewSet,
    DashboardStatsView,
)

# Convertidor flexible de PK para soportar tanto enteros como UUIDs en URLs
class FlexiblePKConverter:
    regex = r'[0-9a-fA-F-]+'

    def to_python(self, value):
        return value

    def to_url(self, value):
        return str(value)

register_converter(FlexiblePKConverter, 'flex_pk')

app_name = 'security_core'

router = DefaultRouter()
router.register(r'domains', OfficialDomainViewSet, basename='official-domain')
router.register(r'scans/history', ScanHistoryViewSet, basename='scan-history')
router.register(r'community-reports', CommunityReportViewSet, basename='community-report')
router.register(r'contacts', InstitutionalContactViewSet, basename='institutional-contact')
router.register(r'institutional-contacts', InstitutionalContactViewSet, basename='institutional-contacts')

urlpatterns = [
    # 0. Métricas del Dashboard administrativo (Tarjetas KPI)
    path('stats/', DashboardStatsView.as_view(), name='dashboard-stats'),

    # 1. Endpoint principal de análisis de enlaces / números
    path('analyze/', AnalyzeTargetView.as_view(), name='analyze-target'),
    # Alias retrocompatible
    path('scan/', AnalyzeTargetView.as_view(), name='scan-target'),

    # 2. Historial de escaneos del usuario autenticado
    path('history/', ScanHistoryListView.as_view(), name='scan-history-list'),

    # 3. Creación y feed de reportes comunitarios
    path('reports/', CommunityReportCreateView.as_view(), name='community-report-create'),
    path('reports/feed/', CommunityReportFeedView.as_view(), name='community-report-feed'),
    path('reports/<flex_pk:pk>/moderate/', ModerateReportView.as_view(), name='community-report-moderate'),

    # 4. Viewsets REST complementarios (domains, scans, reports, contacts)
    path('', include(router.urls)),
]
