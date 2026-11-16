from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from users.models import User, UserAuditLog


@admin.register(User)
class CustomUserAdmin(BaseUserAdmin):
    list_display = (
        'email',
        'first_name',
        'last_name',
        'is_moderator',
        'is_staff',
        'is_active',
        'accepted_terms',
        'terms_accepted_at',
    )
    list_filter = ('is_moderator', 'is_staff', 'is_active', 'accepted_terms')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Información Personal', {'fields': ('first_name', 'last_name')}),
        ('Roles y Permisos', {
            'fields': (
                'is_moderator',
                'is_staff',
                'is_superuser',
                'is_active',
                'groups',
                'user_permissions',
            )
        }),
        ('Cumplimiento Ley 1581 (Habeas Data)', {
            'fields': (
                'accepted_terms',
                'terms_accepted_at',
            )
        }),
        ('Fechas de Auditoría', {'fields': ('last_login', 'date_joined')}),
    )

    readonly_fields = ('terms_accepted_at', 'last_login', 'date_joined')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email',
                'password1',
                'password2',
                'first_name',
                'last_name',
                'is_moderator',
                'accepted_terms',
            ),
        }),
    )


@admin.register(UserAuditLog)
class UserAuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'action', 'user', 'ip_address')
    list_filter = ('action', 'created_at')
    search_fields = ('user__email', 'ip_address', 'action')
    readonly_fields = ('id', 'user', 'action', 'ip_address', 'user_agent', 'details', 'created_at')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
