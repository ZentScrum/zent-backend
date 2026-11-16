import re
import difflib
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple
from django.conf import settings
from django.db import models

from security_core.models import (
    OfficialDomain,
    InstitutionalContact,
    ScanHistory,
    CommunityReport,
)
from security_core.services.url_scanner import URLThreatScanner
from security_core.services.phone_checker import PhoneNumberAnalyzer


# Palabras clave de urgencia, coerción, premios o fraude en URL / path
URGENCY_KEYWORDS = [
    'premio', 'bloqueo', 'actualizar', 'bono', 'multa', 'envio', 'pendiente',
    'verificar', 'seguridad', 'suspension', 'cancelacion', 'recompensa',
    'urgente', 'clave', 'banca', 'login', 'iniciar-sesion', 'confirmar',
]

# TLDs de alto abuso comúnmente empleados en campañas de phishing
HIGH_ABUSE_TLDS = {
    '.xyz', '.top', '.click', '.tk', '.gq', '.cf', '.ga', '.ml', '.work',
    '.buzz', '.live', '.rest', '.sbs', '.cam', '.cfd'
}

# Dominios acortadores populares utilizados para ocultar destinos maliciosos
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'tiny.cc', 't.co', 'cutt.ly', 'is.gd',
    'buff.ly', 'ow.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy'
}

# Caracteres similares comunes en typosquatting / homoglyphs
CHAR_REPLACEMENTS = {
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b',
    'v': 'u', 'w': 'vv'
}


def normalize_url(raw_url: str) -> Tuple[str, str, str]:
    """
    Normaliza la URL dada y extrae:
    - cleaned_url: URL con esquema http/https
    - hostname: nombre de host completo en minúsculas (ej: 'dian-tramites.co')
    - path_query: la ruta y parámetros de búsqueda para inspección de keywords
    """
    url = raw_url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        # Si no tiene esquema, asumir http:// inicialmente para extraer componentes
        url_for_parsing = f"http://{url}"
    else:
        url_for_parsing = url

    parsed = urlparse(url_for_parsing)
    hostname = (parsed.netloc or parsed.path).lower().split(':')[0]
    # Limpiar posibles barras o puertos residuales
    hostname = hostname.strip('/')
    
    path_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()
    return url, hostname, path_query


def extract_base_domain(hostname: str) -> str:
    """
    Extrae el dominio base (SLD + TLD) simplificado para Colombia y ccTLDs comunes.
    Ejemplo: 'login.bancolombia.com' -> 'bancolombia.com'
             'tramites.dian.gov.co' -> 'dian.gov.co'
             'sub.bancolombia.com.co' -> 'bancolombia.com.co'
    """
    parts = hostname.split('.')
    if len(parts) <= 2:
        return hostname

    # Manejo de dominios de segundo nivel comunes (.gov.co, .com.co, .edu.co, .org.co, etc.)
    second_level_cctlds = {'gov.co', 'com.co', 'edu.co', 'org.co', 'net.co', 'mil.co'}
    last_two = f"{parts[-2]}.{parts[-1]}"
    
    if last_two in second_level_cctlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    
    return f"{parts[-2]}.{parts[-1]}"


def is_ip_address(hostname: str) -> bool:
    """Verifica si el hostname es una dirección IPv4."""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, hostname))


def check_typosquatting(hostname: str, official_domains: List[Tuple[str, str]]) -> Tuple[bool, str, str, float]:
    """
    Evalúa si el hostname intenta suplantar a alguno de los dominios oficiales.
    official_domains: Lista de tuplas (domain_str, entity_name)
    Retorna: (is_squatting, matched_official_domain, matched_entity_name, similarity_score)
    """
    base_domain = extract_base_domain(hostname)
    
    # Nombre raíz sin TLD para análisis de similitud
    # Ej: 'bancol0mbia' de 'bancol0mbia.com'
    def get_domain_root(dom: str) -> str:
        parts = dom.split('.')
        # si termina en .gov.co o .com.co
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in {'gov.co', 'com.co', 'edu.co', 'org.co'}:
            return parts[-3]
        return parts[0]

    input_root = get_domain_root(base_domain)
    
    # Versión sustituida de números por letras (ej: banc0l0mbia -> bancolombia)
    input_normalized = input_root
    for num, char in CHAR_REPLACEMENTS.items():
        input_normalized = input_normalized.replace(num, char)

    for off_domain, entity_name in official_domains:
        off_root = get_domain_root(off_domain)

        # 1. Si el dominio coincide exactamente con el oficial, NO es typosquatting
        if base_domain == off_domain or hostname == off_domain or hostname.endswith(f".{off_domain}"):
            continue

        # 2. Contención de nombre de entidad o raíz oficial en el hostname
        # Ej: 'nequi-bono.xyz' contiene 'nequi', 'dian-tramites.co' contiene 'dian'
        # o 'bancolombia-alerta.com' contiene 'bancolombia'
        if off_root in base_domain or off_root in hostname:
            return True, off_domain, entity_name, 0.95

        # 3. Contención con sustitución de homoglyphs
        if off_root in input_normalized:
            return True, off_domain, entity_name, 0.92

        # 4. Similitud por Levenshtein / SequenceMatcher entre raíces de dominio
        similarity = difflib.SequenceMatcher(None, input_root, off_root).ratio()
        if similarity >= 0.78:
            return True, off_domain, entity_name, similarity

        similarity_norm = difflib.SequenceMatcher(None, input_normalized, off_root).ratio()
        if similarity_norm >= 0.78:
            return True, off_domain, entity_name, similarity_norm

        # 5. Similitud entre dominios base completos
        full_similarity = difflib.SequenceMatcher(None, base_domain, off_domain).ratio()
        if full_similarity >= 0.82:
            return True, off_domain, entity_name, full_similarity

    return False, '', '', 0.0


def clean_colombian_phone(raw_phone: str) -> str:
    """
    Función de compatibilidad: delega al normalizador universal E.164.
    """
    return PhoneNumberAnalyzer.normalize_e164(raw_phone)


def normalize_phone(raw_phone: str) -> str:
    """
    Normaliza cualquier número telefónico al estándar internacional E.164
    soportando cualquier prefijo del mundo (+1, +34, +52, +57, +593, etc.) o shortcodes.
    """
    return PhoneNumberAnalyzer.normalize_e164(raw_phone)


def analyze_url_target(target_value: str) -> Dict[str, Any]:
    """
    Motor heurístico de detección anti-phishing para enlaces (URLs).
    Retorna: risk_level, risk_score, reasons
    """
    reasons = []
    risk_score = 0

    original_url, hostname, path_query = normalize_url(target_value)
    base_domain = extract_base_domain(hostname)

    # 1. Verificar si está en OfficialDomain (lista blanca verificada)
    # Comprobar si el hostname o base_domain es un dominio oficial activo
    official_match = OfficialDomain.objects.filter(
        domain__in=[hostname, base_domain],
        is_active=True
    ).first()

    # Si es un subdominio legítimo de un dominio oficial activo (ej: portal.bancolombia.com)
    if not official_match:
        for off in OfficialDomain.objects.filter(is_active=True):
            if hostname == off.domain or hostname.endswith(f".{off.domain}"):
                official_match = off
                break

    if official_match:
        return {
            "risk_level": ScanHistory.RiskLevel.SAFE,
            "risk_score": 0,
            "reasons": [
                f"Dominio oficial verificado de la entidad '{official_match.entity_name}' ({official_match.domain}).",
                "Sitio web seguro y catalogado en la lista blanca de confianza."
            ]
        }

    # 2. Typosquatting / Suplantación contra OfficialDomain
    all_official = list(OfficialDomain.objects.filter(is_active=True).values_list('domain', 'entity_name'))
    is_squatting, target_domain, entity_name, sim_score = check_typosquatting(hostname, all_official)

    if is_squatting:
        risk_score = max(risk_score, 90)
        reasons.append(
            f"Alerta de Typosquatting / Suplantación: El dominio '{hostname}' intenta imitar al dominio oficial "
            f"'{target_domain}' de '{entity_name}' sin serlo."
        )

    # 3. Señales Heurísticas de Riesgo
    # A) Uso de HTTP sin SSL / TLS
    if original_url.lower().startswith('http://'):
        risk_score += 25
        reasons.append("Conexión no cifrada (HTTP sin certificado de seguridad SSL/TLS). Los sitios bancarios y oficiales siempre usan HTTPS.")

    # B) Direcciones IP directas en lugar de nombre de dominio
    if is_ip_address(hostname):
        risk_score += 45
        reasons.append(f"El enlace usa una dirección IP directa ({hostname}) en lugar de un nombre de dominio registrado, táctica común en servidores de ataque.")

    # C) Subdominios excesivos (> 3 niveles)
    subdomain_parts = hostname.split('.')
    # Si tiene más de 3 niveles de subdominio (ej: login.seguro.verificacion.banco.xyz)
    if len(subdomain_parts) > 3:
        risk_score += 20
        reasons.append(f"Estructura sospechosa de subdominios excesivos ({len(subdomain_parts)} partes), frecuentemente usada para evadir filtros de reputación.")

    # D) Palabras clave de urgencia, coerción o fraude en la URL
    full_url_lower = original_url.lower()
    matched_keywords = [kw for kw in URGENCY_KEYWORDS if kw in full_url_lower]
    if matched_keywords:
        risk_score += 30
        reasons.append(
            f"Contiene términos sospechosos de urgencia o ingeniería social: {', '.join(matched_keywords[:4])}."
        )

    # E) Servicios acortadores de URL
    if hostname in URL_SHORTENERS:
        risk_score += 35
        reasons.append(f"Usa un servicio acortador de enlaces ({hostname}), el cual oculta el destino real y suele emplearse en mensajes de spam y smishing.")

    # F) TLDs de alto abuso
    matched_abuse_tld = next((tld for tld in HIGH_ABUSE_TLDS if hostname.endswith(tld)), None)
    if matched_abuse_tld:
        risk_score += 30
        reasons.append(f"El dominio utiliza una extensión de alto índice de abuso y ciberfraude ({matched_abuse_tld}).")

    # 4. Reportes comunitarios aprobados en Zent
    approved_reports = CommunityReport.objects.filter(
        reported_value__icontains=hostname,
        status=CommunityReport.Status.APPROVED
    ).count()

    if approved_reports > 0:
        risk_score = max(risk_score, 90)
        reasons.append(f"Este enlace registra {approved_reports} denuncia(s) comunitaria(s) verificada(s) y aprobada(s) por moderadores de Zent.")

    # 5. Integración con Threat Intelligence externa (Google Safe Browsing & VirusTotal)
    try:
        gsb_result = URLThreatScanner.scan_google_safe_browsing(original_url)
        if gsb_result.get("is_malicious"):
            risk_score = max(risk_score, 95)
            reasons.append("Detectado como sitio malicioso o de ingeniería social en Google Safe Browsing.")
    except Exception:
        pass

    try:
        vt_result = URLThreatScanner.scan_virustotal(original_url)
        vt_malicious = vt_result.get("malicious_count", 0)
        if vt_malicious > 0:
            risk_score = max(risk_score, min(70 + vt_malicious * 10, 100))
            reasons.append(f"Identificado como peligroso por {vt_malicious} motores de antivirus en VirusTotal.")
    except Exception:
        pass

    # Normalizar score a máximo 100
    risk_score = min(risk_score, 100)

    # Determinar risk_level final
    if risk_score >= 70:
        risk_level = ScanHistory.RiskLevel.DANGEROUS
    elif risk_score >= 30:
        risk_level = ScanHistory.RiskLevel.SUSPICIOUS
    else:
        risk_level = ScanHistory.RiskLevel.SAFE
        if not reasons:
            reasons.append("No se detectaron indicios de suplantación, malware ni reportes adversos para este enlace.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
    }


def analyze_phone_target(target_value: str) -> Dict[str, Any]:
    """
    Motor heurístico y de reputación para números telefónicos internacionales y códigos cortos.
    Aplica lista blanca institucional de protección y filtro de consenso comunitario.
    Retorna: risk_level, risk_score, reasons, verified_reports_count, sanitized_phone
    """
    sanitized_phone = PhoneNumberAnalyzer.normalize_e164(target_value)
    digits_only = re.sub(r'\D', '', sanitized_phone)

    # 1. Filtro de Lista Blanca Institucional (Protección contra difamación y falsos positivos)
    # Busca por coincidencia del número normalizado E.164, los dígitos, o el valor original
    whitelisted_contact = InstitutionalContact.objects.filter(is_active=True).filter(
        models.Q(phone_or_code=sanitized_phone) |
        models.Q(phone_or_code=target_value.strip()) |
        models.Q(phone_or_code=digits_only)
    ).first()

    if not whitelisted_contact and digits_only:
        # Búsqueda por dígitos limpios en la lista institucional
        for contact in InstitutionalContact.objects.filter(is_active=True):
            contact_digits = re.sub(r'\D', '', contact.phone_or_code)
            if contact_digits == digits_only:
                whitelisted_contact = contact
                break

    if whitelisted_contact:
        return {
            "risk_level": ScanHistory.RiskLevel.SAFE,
            "risk_score": 0,
            "reasons": [
                f"Canal o contacto institucional oficial verificado de {whitelisted_contact.entity_name} "
                f"({whitelisted_contact.get_category_display()}). Protegido contra difamaciones y falsos reportes."
            ],
            "verified_reports_count": 0,
            "sanitized_phone": sanitized_phone,
            "is_whitelisted": True,
        }

    # 2. Análisis de Reportes Comunitarios con Sistema de Consenso
    # Buscamos coincidencias con reportes aprobados y reportes comunitarios
    reports_qs = CommunityReport.objects.filter(
        status__in=[CommunityReport.Status.APPROVED, CommunityReport.Status.PENDING]
    )
    matching_reports = [
        r for r in reports_qs
        if digits_only and digits_only in re.sub(r'\D', '', r.reported_value)
    ]

    approved_reports = [r for r in matching_reports if r.status == CommunityReport.Status.APPROVED]
    approved_count = len(approved_reports)

    # Conteo de denunciantes independientes (evita brigading / ataque coordinado de una sola cuenta)
    unique_reporters = set(r.reporter_id for r in matching_reports if r.reporter_id)
    distinct_reporters_count = len(unique_reporters) if unique_reporters else (1 if matching_reports else 0)

    # Evaluación mediante el motor de consenso
    eval_result = PhoneNumberAnalyzer.evaluate_phone_risk(
        report_count=len(matching_reports),
        distinct_reporters_count=distinct_reporters_count,
        is_verified_by_moderator=(approved_count > 0)
    )

    risk_score = eval_result["risk_score"]
    risk_level_str = eval_result["risk_level"]
    risk_level = getattr(ScanHistory.RiskLevel, risk_level_str, ScanHistory.RiskLevel.SAFE)
    reasons = list(eval_result["reasons"])

    # Detalle adicional si hay reportes específicos
    whatsapp_count = sum(1 for r in matching_reports if r.report_type == CommunityReport.ReportType.HACKED_WHATSAPP)
    fraud_phone_count = sum(1 for r in matching_reports if r.report_type == CommunityReport.ReportType.FRAUD_PHONE)

    if whatsapp_count > 0:
        reasons.append(f"Se registran {whatsapp_count} alerta(s) de cuenta de WhatsApp suplantada o hackeada.")
    if fraud_phone_count > 0:
        reasons.append(f"Se registran {fraud_phone_count} alerta(s) por llamadas extorsivas o fraude telefónico.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "verified_reports_count": approved_count,
        "sanitized_phone": sanitized_phone,
    }


def analyze_target(target_value: str, target_type: str) -> Dict[str, Any]:
    """
    Función central del motor heurístico de ciberseguridad Zent.
    Evalúa riesgos en tiempo real para URLs o Teléfonos.
    
    Retorna un diccionario con:
    - risk_level: SAFE | SUSPICIOUS | DANGEROUS
    - risk_score: 0 a 100
    - reasons: Lista de cadenas claras en español
    """
    cleaned_target = (target_value or '').strip()
    target_type_upper = (target_type or '').upper()

    if target_type_upper == ScanHistory.TargetType.URL:
        return analyze_url_target(cleaned_target)
    elif target_type_upper == ScanHistory.TargetType.PHONE:
        return analyze_phone_target(cleaned_target)
    else:
        return {
            "risk_level": ScanHistory.RiskLevel.SUSPICIOUS,
            "risk_score": 50,
            "reasons": [f"Tipo de objetivo no soportado: '{target_type}'."],
        }
