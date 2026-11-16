import io
from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

from security_core.models import CommunityReport, ScanHistory
from users.models import UserAuditLog

User = get_user_model()


def generate_test_image(format='PNG'):
    file = io.BytesIO()
    image = Image.new('RGB', (100, 100), color='blue')
    image.save(file, format=format)
    file.seek(0)
    return SimpleUploadedFile(f"test_evidence.{format.lower()}", file.read(), content_type=f"image/{format.lower()}")


class UserAuthTests(APITestCase):
    """
    Pruebas unitarias para autenticación, cumplimiento legal (Ley 1581)
    y eliminación de cuentas (Google Play / Derecho al Olvido).
    """

    def setUp(self):
        self.register_url = reverse('users_auth:register')
        self.login_url = reverse('users_auth:login')
        self.delete_account_url = reverse('users_auth:delete-account')

        self.valid_user_data = {
            "email": "juan.perez@example.com",
            "first_name": "Juan",
            "last_name": "Pérez",
            "password": "StrongPassword123!",
            "password_confirm": "StrongPassword123!",
            "accepted_terms": True,
        }

    def test_register_success_with_accepted_terms(self):
        """
        Valida el registro exitoso aceptando explícitamente los términos bajo la Ley 1581.
        """
        response = self.client.post(self.register_url, self.valid_user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("user", response.data)
        self.assertEqual(response.data["user"]["email"], "juan.perez@example.com")
        self.assertTrue(response.data["user"]["accepted_terms"])
        self.assertIsNotNone(response.data["user"]["terms_accepted_at"])

        # Verificar en base de datos
        user = User.objects.get(email="juan.perez@example.com")
        self.assertTrue(user.check_password("StrongPassword123!"))
        self.assertTrue(user.accepted_terms)
        self.assertFalse(user.is_moderator)

        # Verificar auditoría
        self.assertTrue(UserAuditLog.objects.filter(user=user).exists())

    def test_register_rejection_without_accepted_terms(self):
        """
        Valida que el registro sea rechazado si el usuario no acepta los términos (accepted_terms=False).
        """
        invalid_data = self.valid_user_data.copy()
        invalid_data["accepted_terms"] = False

        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("accepted_terms", response.data)
        self.assertFalse(User.objects.filter(email=invalid_data["email"]).exists())

    def test_register_rejection_password_mismatch(self):
        """
        Valida el rechazo si las contraseñas no coinciden.
        """
        invalid_data = self.valid_user_data.copy()
        invalid_data["password_confirm"] = "DifferentPassword123!"

        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password_confirm", response.data)

    def test_login_jwt_success_and_claims(self):
        """
        Valida la autenticación exitosa mediante SimpleJWT y la recepción
        de access, refresh y datos del perfil (incluyendo rol e is_moderator).
        """
        user = User.objects.create_user(
            email="maria.gomez@example.com",
            first_name="María",
            last_name="Gómez",
            password="StrongPassword123!",
            accepted_terms=True,
            is_moderator=True,
        )

        login_data = {
            "email": "maria.gomez@example.com",
            "password": "StrongPassword123!",
        }

        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("user", response.data)

        user_info = response.data["user"]
        self.assertEqual(user_info["email"], "maria.gomez@example.com")
        self.assertTrue(user_info["is_moderator"])
        self.assertEqual(user_info["role"], "MODERATOR")

        # Verificar auditoría de login exitoso
        self.assertTrue(
            UserAuditLog.objects.filter(
                user=user,
                action=UserAuditLog.Action.LOGIN_SUCCESS
            ).exists()
        )

    def test_login_failure_invalid_credentials(self):
        """
        Valida el fallo con credenciales incorrectas y auditoría de seguridad.
        """
        User.objects.create_user(
            email="carlos@example.com",
            password="StrongPassword123!",
            accepted_terms=True,
        )

        login_data = {
            "email": "carlos@example.com",
            "password": "WrongPassword!",
        }

        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Auditoría de fallo de autenticación
        self.assertTrue(
            UserAuditLog.objects.filter(
                action=UserAuditLog.Action.LOGIN_FAILURE,
                details__attempted_email="carlos@example.com"
            ).exists()
        )

    def test_delete_account_and_anonymization(self):
        """
        Valida el cumplimiento de Google Play y la Ley 1581 (Habeas Data):
        - Eliminación permanente del registro de usuario.
        - Anonimización de reportes comunitarios y escaneos previos (reporter=None).
        """
        user = User.objects.create_user(
            email="usuario.eliminar@example.com",
            first_name="Usuario",
            last_name="Temporal",
            password="StrongPassword123!",
            accepted_terms=True,
        )

        # Crear un reporte comunitario y un escaneo asociados al usuario
        report = CommunityReport.objects.create(
            reporter=user,
            report_type=CommunityReport.ReportType.PHISHING_URL,
            reported_value="http://banco-trampa.xyz",
            description="Intento de phishing bancario vía SMS",
            evidence_image=generate_test_image(),
            status=CommunityReport.Status.PENDING,
        )

        scan = ScanHistory.objects.create(
            user=user,
            analyzed_target="http://banco-trampa.xyz",
            target_type=ScanHistory.TargetType.URL,
            risk_level=ScanHistory.RiskLevel.DANGEROUS,
            risk_score=90,
            reasons=["Alerta de phishing"]
        )

        # Autenticar al usuario
        self.client.force_authenticate(user=user)

        # Invocar la eliminación de cuenta
        response = self.client.delete(self.delete_account_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # 1. El usuario ya no existe en la base de datos
        self.assertFalse(User.objects.filter(email="usuario.eliminar@example.com").exists())

        # 2. Los reportes comunitarios persisten para la seguridad colectiva pero anonimizados (reporter=None)
        report.refresh_from_db()
        self.assertIsNone(report.reporter)

        # 3. Los historiales de escaneos también se anonimizan (user=None)
        scan.refresh_from_db()
        self.assertIsNone(scan.user)

        # 4. Se registró la auditoría de cumplimiento
        self.assertTrue(
            UserAuditLog.objects.filter(
                action=UserAuditLog.Action.ACCOUNT_DELETED,
                details__compliance='google_play_and_habeas_data_account_erasure'
            ).exists()
        )
