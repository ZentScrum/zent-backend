from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from users.views import (
    RegisterView,
    LoginView,
    DeleteAccountView,
    UserProfileView,
    GoogleAuthView,
)

app_name = 'users'

urlpatterns = [
    # Endpoints de autenticación requeridos
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('google/', GoogleAuthView.as_view(), name='google-login'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),

    # Utilidades JWT y perfil de usuario
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    path('profile/', UserProfileView.as_view(), name='profile'),
]
