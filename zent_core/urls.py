"""
URL configuration for Zent Anti-Phishing & Digital Fraud Prevention Platform.
"""

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.conf import settings
from django.conf.urls.static import static
from security_core.views import CommunityReportViewSet, ModerateReportView



def health_check(request):
    """
    Lightweight health check endpoint for uptime monitors and orchestrators.
    """
    return JsonResponse(
        {
            "status": "healthy",
            "service": "zent-backend",
            "version": "1.0.0",
        },
        status=200,
    )


urlpatterns = [
    # Panel administrativo
    path('admin/', admin.site.urls),

    # Monitoreo de disponibilidad
    path('api/health/', health_check, name='health-check'),

    # Endpoints de Autenticación y Cumplimiento Legal (Ley 1581 / Google Play)
    path('api/auth/', include('users.urls', namespace='users_auth')),

    # Endpoints de Ciberseguridad y Detección de Fraude
    path('api/security/', include('security_core.urls', namespace='security_core')),

    # Alias directo para gestión y moderación comunitaria (/api/community/)
    path('api/community/', CommunityReportViewSet.as_view({'get': 'list', 'post': 'create'}), name='community-list'),
    path('api/community/<flex_pk:pk>/', CommunityReportViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='community-detail'),
    path('api/community/<flex_pk:pk>/moderate/', ModerateReportView.as_view(), name='community-moderate'),
]

# Servir archivos estáticos y media durante desarrollo
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
