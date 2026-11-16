from django.contrib import admin
from django.utils import timezone
from security_core.models import OfficialDomain, InstitutionalContact, ScanHistory, CommunityReport


@admin.register(InstitutionalContact)
class InstitutionalContactAdmin(admin.ModelAdmin):
    list_display = ('entity_name', 'phone_or_code', 'category', 'is_active', 'updated_at')
    list_filter = ('category', 'is_active')
    search_fields = ('entity_name', 'phone_or_code', 'description')
    ordering = ('entity_name',)
    list_editable = ('is_active',)


@admin.register(OfficialDomain)
class OfficialDomainAdmin(admin.ModelAdmin):
    list_display = ('entity_name', 'domain', 'category', 'is_active', 'updated_at')
    list_filter = ('category', 'is_active')
    search_fields = ('entity_name', 'domain')
    ordering = ('entity_name',)
    list_editable = ('is_active',)


@admin.register(ScanHistory)
class ScanHistoryAdmin(admin.ModelAdmin):
    list_display = ('analyzed_target', 'target_type', 'risk_level', 'risk_score', 'user', 'created_at')
    list_filter = ('risk_level', 'target_type', 'created_at')
    search_fields = ('analyzed_target', 'user__email')
    readonly_fields = ('id', 'user', 'analyzed_target', 'target_type', 'risk_level', 'risk_score', 'reasons', 'created_at')
    ordering = ('-created_at',)

    def has_add_permission(self, request):
        return False


@admin.register(CommunityReport)
class CommunityReportAdmin(admin.ModelAdmin):
    list_display = ('report_type', 'reported_value', 'status', 'reporter', 'reviewed_by', 'created_at')
    list_filter = ('status', 'report_type', 'created_at')
    search_fields = ('reported_value', 'description', 'reporter__email', 'moderation_notes')
    readonly_fields = ('id', 'created_at', 'reviewed_at')
    ordering = ('-created_at',)
    actions = ['approve_reports', 'reject_reports']

    fieldsets = (
        ('Detalles de la Denuncia', {
            'fields': ('reporter', 'report_type', 'reported_value', 'description', 'evidence_image')
        }),
        ('Estado de Moderación Humana', {
            'fields': ('status', 'reviewed_by', 'reviewed_at', 'moderation_notes')
        }),
        ('Metadatos', {
            'fields': ('id', 'created_at')
        }),
    )

    @admin.action(description="Aprobar denuncias seleccionadas")
    def approve_reports(self, request, queryset):
        queryset.update(
            status=CommunityReport.Status.APPROVED,
            reviewed_by=request.user,
            reviewed_at=timezone.now(),
            moderation_notes="Aprobado en lote desde el panel de administración."
        )

    @admin.action(description="Rechazar denuncias seleccionadas (Falsa Alarma)")
    def reject_reports(self, request, queryset):
        queryset.update(
            status=CommunityReport.Status.REJECTED,
            reviewed_by=request.user,
            reviewed_at=timezone.now(),
            moderation_notes="Rechazado en lote desde el panel de administración."
        )
