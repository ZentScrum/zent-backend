from rest_framework import permissions


class IsModeratorOrAdmin(permissions.BasePermission):
    """
    Permite el acceso a operaciones restringidas únicamente a usuarios autenticados
    que tengan asignado el rol de moderador (is_moderator=True) o sean administradores de la plataforma.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return bool(user.is_moderator or user.is_staff or user.is_superuser)
