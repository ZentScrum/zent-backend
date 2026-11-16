import io
from PIL import Image
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

from security_core.models import OfficialDomain, ScanHistory, CommunityReport
from security_core.services.analyzer import analyze_target, clean_colombian_phone

User = get_user_model()


def generate_test_image(format='PNG'):
    file = io.BytesIO()
    image = Image.new('RGB', (100, 100), color='red')
    image.save(file, format=format)
    file.seek(0)
    return SimpleUploadedFile(f"test_evidence.{format.lower()}", file.read(), content_type=f"image/{format.lower()}")


class SecurityAnalyzerTests(APITestCase):
    def setUp(self):
        self.official_banco = OfficialDomain.objects.create(
            entity_name="Bancolombia",
            domain="bancolombia.com",
            category=OfficialDomain.Category.BANK,
            is_active=True
        )
        self.official_dian = OfficialDomain.objects.create(
            entity_name="DIAN",
            domain="dian.gov.co",
            category=OfficialDomain.Category.GOVERNMENT,
            is_active=True
        )
        self.official_nequi = OfficialDomain.objects.create(
            entity_name="Nequi",
            domain="nequi.com.co",
            category=OfficialDomain.Category.BANK,
            is_active=True
        )

    def test_official_domain_safe(self):
        res = analyze_target("https://www.bancolombia.com/personas", "URL")
        self.assertEqual(res["risk_level"], ScanHistory.RiskLevel.SAFE)
        self.assertEqual(res["risk_score"], 0)

    def test_typosquatting_detection(self):
        # bancol0mbia.com imita a Bancolombia
        res = analyze_target("http://bancol0mbia.com/login", "URL")
        self.assertEqual(res["risk_level"], ScanHistory.RiskLevel.DANGEROUS)
        self.assertGreaterEqual(res["risk_score"], 85)
        self.assertTrue(any("Typosquatting" in r for r in res["reasons"]))

        # dian-tramites.co imita a dian.gov.co
        res_dian = analyze_target("http://dian-tramites.co/declaracion", "URL")
        self.assertEqual(res_dian["risk_level"], ScanHistory.RiskLevel.DANGEROUS)
        self.assertGreaterEqual(res_dian["risk_score"], 85)

        # nequi-bono.xyz imita a nequi.com.co
        res_nequi = analyze_target("http://nequi-bono.xyz/reclamar", "URL")
        self.assertEqual(res_nequi["risk_level"], ScanHistory.RiskLevel.DANGEROUS)
        self.assertGreaterEqual(res_nequi["risk_score"], 85)

    def test_heuristic_signals(self):
        # IP directa, sin SSL, palabra clave y TLD de abuso
        res = analyze_target("http://192.168.1.50/premio-bono.xyz", "URL")
        self.assertEqual(res["risk_level"], ScanHistory.RiskLevel.DANGEROUS)
        reasons_text = " ".join(res["reasons"])
        self.assertIn("IP directa", reasons_text)
        self.assertIn("HTTP sin certificado", reasons_text)
        self.assertIn("urgencia", reasons_text)

    def test_phone_sanitization_and_reputation(self):
        cleaned = clean_colombian_phone("300 123 4567")
        self.assertEqual(cleaned, "+573001234567")

        # Sin reportes
        res_clean = analyze_target("+573001234567", "PHONE")
        self.assertEqual(res_clean["risk_level"], ScanHistory.RiskLevel.SAFE)
        self.assertEqual(res_clean["verified_reports_count"], 0)

        # Con reporte aprobado
        CommunityReport.objects.create(
            report_type=CommunityReport.ReportType.FRAUD_PHONE,
            reported_value="+573001234567",
            description="Llamada de extorsión carcelaria",
            evidence_image=generate_test_image(),
            status=CommunityReport.Status.APPROVED
        )

        res_reported = analyze_target("3001234567", "PHONE")
        self.assertEqual(res_reported["risk_level"], ScanHistory.RiskLevel.SUSPICIOUS)
        self.assertEqual(res_reported["verified_reports_count"], 1)


class SecurityEndpointsTests(APITestCase):
    def setUp(self):
        self.official_dian = OfficialDomain.objects.create(
            entity_name="DIAN",
            domain="dian.gov.co",
            category=OfficialDomain.Category.GOVERNMENT,
            is_active=True
        )
        self.user = User.objects.create_user(
            email="citizen@example.com",
            first_name="Ciudadano",
            last_name="Ejemplar",
            password="StrongPassword123!"
        )
        self.moderator = User.objects.create_user(
            email="moderator@example.com",
            first_name="Moderador",
            last_name="Zent",
            password="StrongPassword123!",
            is_moderator=True
        )

    def test_post_analyze_anonymous_and_authenticated(self):
        # 1. Anónimo
        payload = {"target": "https://seguro.bancolombia.com", "type": "URL"}
        resp = self.client.post("/api/security/analyze/", payload, format="json")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("risk_level", resp.data)
        self.assertIn("risk_score", resp.data)
        self.assertIn("reasons", resp.data)

        # 2. Autenticado
        self.client.force_authenticate(user=self.user)
        payload = {"target": "http://dian-tramites.co/bono", "type": "URL"}
        resp_auth = self.client.post("/api/security/analyze/", payload, format="json")
        self.assertEqual(resp_auth.status_code, status.HTTP_200_OK)
        self.assertEqual(resp_auth.data["risk_level"], ScanHistory.RiskLevel.DANGEROUS)

        # Verificar guardado en ScanHistory
        self.assertEqual(ScanHistory.objects.filter(user=self.user).count(), 1)

    def test_get_history(self):
        self.client.force_authenticate(user=self.user)
        # Crear un escaneo
        self.client.post("/api/security/analyze/", {"target": "https://bancolombia.com", "type": "URL"}, format="json")

        resp = self.client.get("/api/security/history/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data["results"]), 1)

    def test_create_report_and_feed(self):
        self.client.force_authenticate(user=self.user)
        
        test_img = generate_test_image()
        data = {
            "report_type": CommunityReport.ReportType.PHISHING_URL,
            "reported_value": "http://falso-banco.xyz",
            "description": "Mensaje de texto solicitando actualización de cuenta",
            "evidence_image": test_img,
        }
        resp = self.client.post("/api/security/reports/", data, format="multipart")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        report_id = resp.data["id"]
        self.assertEqual(resp.data["status"], CommunityReport.Status.PENDING)

        # Verificar que NO aparezca en el feed público mientras esté en PENDING
        feed_resp = self.client.get("/api/security/reports/feed/")
        self.assertEqual(feed_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(feed_resp.data["results"]), 0)

        # Moderador aprueba el reporte
        self.client.force_authenticate(user=self.moderator)
        mod_resp = self.client.patch(
            f"/api/security/reports/{report_id}/moderate/",
            {
                "status": CommunityReport.Status.APPROVED,
                "moderation_notes": "Evidencia contundente de phishing comprobada."
            },
            format="json"
        )
        self.assertEqual(mod_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(mod_resp.data["status"], CommunityReport.Status.APPROVED)

        # Ahora el feed público debe listar la amenaza aprobada
        self.client.logout()
        feed_resp2 = self.client.get("/api/security/reports/feed/")
        self.assertEqual(feed_resp2.status_code, status.HTTP_200_OK)
        self.assertEqual(len(feed_resp2.data["results"]), 1)
        self.assertEqual(feed_resp2.data["results"][0]["reported_value"], "http://falso-banco.xyz")
