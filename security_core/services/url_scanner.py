import base64
import logging
import requests
from typing import Dict, Any
from django.conf import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 6.0


class URLThreatScanner:
    """
    Servicio de Threat Intelligence para enriquecimiento automático de URLs
    mediante Google Safe Browsing v4 y VirusTotal v3.
    """

    @classmethod
    def scan_google_safe_browsing(cls, target_url: str) -> Dict[str, Any]:
        """
        Consulta la API de Google Safe Browsing v4.
        """
        api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
        if not api_key:
            return {"status": "skipped", "reason": "GOOGLE_SAFE_BROWSING_API_KEY no configurada"}

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "zent-platform",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}],
            },
        }

        try:
            response = requests.post(
                endpoint,
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
            matches = data.get("matches", [])
            is_malicious = len(matches) > 0

            return {
                "status": "success",
                "is_malicious": is_malicious,
                "matches": matches,
            }
        except requests.RequestException as exc:
            logger.warning(f"Fallo al consultar Google Safe Browsing: {exc}")
            return {"status": "error", "message": str(exc)}

    @classmethod
    def scan_virustotal(cls, target_url: str) -> Dict[str, Any]:
        """
        Consulta la API de VirusTotal v3 para análisis de URLs.
        Utiliza el identificador de URL codificado en Base64 sin padding (URL-safe).
        """
        api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        if not api_key:
            return {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY no configurada"}

        # Genera el ID en formato VirusTotal: base64(url) sin signo '='
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        try:
            response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
            if response.status_code == 404:
                # La URL aún no ha sido analizada por VirusTotal
                return {
                    "status": "not_found",
                    "message": "URL no catalogada previamente en VirusTotal.",
                }

            response.raise_for_status()
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            return {
                "status": "success",
                "stats": stats,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
            }
        except requests.RequestException as exc:
            logger.warning(f"Fallo al consultar VirusTotal v3: {exc}")
            return {"status": "error", "message": str(exc)}

    @classmethod
    def compute_aggregate_risk_score(cls, gsb_result: Dict[str, Any], vt_result: Dict[str, Any]) -> int:
        """
        Calcula un score de riesgo consolidado (0-100) combinando los resultados de inteligencia.
        """
        score = 0

        # Si Google Safe Browsing detecta amenaza, es indicativo crítico de ingeniería social
        if gsb_result.get("is_malicious"):
            score = max(score, 85)

        # Si VirusTotal tiene detecciones de motores de seguridad
        vt_malicious = vt_result.get("malicious_count", 0)
        vt_suspicious = vt_result.get("suspicious_count", 0)

        if vt_malicious >= 5:
            score = max(score, 95)
        elif vt_malicious >= 2:
            score = max(score, 75)
        elif vt_malicious == 1 or vt_suspicious >= 2:
            score = max(score, 50)

        return min(score, 100)
