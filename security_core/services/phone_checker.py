import re
from typing import Dict, Any, Tuple, Optional


# Códigos de marcación internacional comunes y longitudes nacionales típicas (mínimo, máximo)
INTERNATIONAL_PREFIXES = {
    '1': (10, 10, 'Estados Unidos / Canadá'),
    '34': (9, 9, 'España'),
    '44': (10, 10, 'Reino Unido'),
    '49': (10, 11, 'Alemania'),
    '52': (10, 10, 'México'),
    '54': (10, 10, 'Argentina'),
    '55': (10, 11, 'Brasil'),
    '56': (9, 9, 'Chile'),
    '57': (10, 10, 'Colombia'),
    '58': (10, 10, 'Venezuela'),
    '51': (9, 9, 'Perú'),
    '593': (9, 9, 'Ecuador'),
    '591': (8, 8, 'Bolivia'),
    '595': (9, 9, 'Paraguay'),
    '598': (8, 8, 'Uruguay'),
    '507': (7, 8, 'Panamá'),
    '506': (8, 8, 'Costa Rica'),
    '502': (8, 8, 'Guatemala'),
    '33': (9, 9, 'Francia'),
    '39': (9, 10, 'Italia'),
}


class PhoneNumberAnalyzer:
    """
    Servicio de normalización universal (formato E.164) y análisis heurístico de reputación
    para números telefónicos y códigos SMS institucionales a escala global.
    """

    @staticmethod
    def normalize_e164(raw_phone: str) -> str:
        """
        Normaliza cualquier número telefónico al estándar internacional E.164 (+{código_país}{número}).
        Soporta cualquier código de país del mundo (+34, +1, +52, +593, +57, etc.) y preserva
        códigos cortos (shortcodes de 3 a 6 dígitos utilizados por bancos o entidades públicas).
        """
        if not raw_phone:
            return ""

        trimmed = raw_phone.strip()

        # Reemplazar prefijos de salida internacional como '00' por '+'
        if trimmed.startswith('00'):
            trimmed = '+' + trimmed[2:]

        # Extraer solo dígitos preservando el '+' inicial si existe
        has_plus = trimmed.startswith('+')
        digits_only = re.sub(r'\D', '', trimmed)

        if not digits_only:
            return raw_phone.strip()

        # Si es un código corto institucional (ej. 890099, 85432, 123)
        if len(digits_only) <= 6:
            return digits_only

        # Si ya traía el '+', validar longitud E.164 (entre 7 y 15 dígitos)
        if has_plus:
            return f"+{digits_only}"

        # Caso Colombia por defecto: 10 dígitos iniciando por 3 (móvil)
        if len(digits_only) == 10 and digits_only.startswith('3'):
            return f"+57{digits_only}"

        # Detección inteligente por coincidencia de prefijos internacionales conocidos
        for prefix in sorted(INTERNATIONAL_PREFIXES.keys(), key=lambda x: -len(x)):
            if digits_only.startswith(prefix):
                national_length = len(digits_only) - len(prefix)
                min_len, max_len, _ = INTERNATIONAL_PREFIXES[prefix]
                if min_len <= national_length <= max_len:
                    return f"+{digits_only}"

        # Si no tiene '+' y tiene longitud típica de número internacional (entre 8 y 15 dígitos)
        if len(digits_only) >= 11:
            return f"+{digits_only}"

        # Si tiene 10 dígitos (longitud estándar en muchos países) y no coincide con prefijo
        if len(digits_only) == 10:
            return f"+57{digits_only}"

        return f"+{digits_only}"

    @classmethod
    def evaluate_phone_risk(
        cls,
        report_count: int,
        distinct_reporters_count: int,
        is_verified_by_moderator: bool,
        is_institutional_whitelist: bool = False,
        entity_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calcula el nivel de riesgo aplicando umbral de consenso comunitario,
        ponderación de moderación y protección de lista blanca institucional.
        """
        # 1. Protección de Lista Blanca Institucional (Inmunidad contra difamación / brigading)
        if is_institutional_whitelist:
            return {
                "risk_level": "SAFE",
                "risk_score": 0,
                "reasons": [
                    f"Contacto institucional oficial y verificado de {entity_name or 'entidad oficial'}. "
                    f"Protegido por lista blanca institucional de Zent."
                ],
                "is_whitelisted": True,
            }

        # 2. Aprobado formalmente por moderador humano de Zent
        if is_verified_by_moderator:
            return {
                "risk_level": "DANGEROUS",
                "risk_score": 95,
                "reasons": [
                    "Alerta crítica: Número verificado y confirmado como fraudulento por analistas de seguridad de Zent."
                ],
                "is_whitelisted": False,
            }

        # 3. Umbral de Consenso Comunitario:
        # Exige múltiples denunciantes independientes antes de elevar a DANGEROUS
        if distinct_reporters_count >= 3:
            return {
                "risk_level": "DANGEROUS",
                "risk_score": 85,
                "reasons": [
                    f"Alerta comunitaria: Acumula {report_count} reportes ciudadanos independientes confirmados por la comunidad."
                ],
                "is_whitelisted": False,
            }
        elif distinct_reporters_count in (1, 2):
            return {
                "risk_level": "SUSPICIOUS",
                "risk_score": 50,
                "reasons": [
                    f"Precaución: Registra {distinct_reporters_count} reporte(s) comunitario(s) preliminar(es) en proceso de verificación."
                ],
                "is_whitelisted": False,
            }

        return {
            "risk_level": "SAFE",
            "risk_score": 0,
            "reasons": [
                "No se registran denuncias ciudadanas ni alertas activas para este número."
            ],
            "is_whitelisted": False,
        }
