from django.core.management.base import BaseCommand
from security_core.models import OfficialDomain


class Command(BaseCommand):
    help = 'Puebla la base de datos con los 25 dominios oficiales más suplantados en Colombia.'

    # Catálogo verificado de las 25 entidades colombianas con mayor índice de ataques de phishing/suplantación
    OFFICIAL_DOMAINS = [
        # --- Sector Bancario y Billeteras Digitales ---
        {
            "entity_name": "Bancolombia",
            "domain": "bancolombia.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco de Bogotá",
            "domain": "bancodebogota.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Davivienda",
            "domain": "davivienda.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "BBVA Colombia",
            "domain": "bbva.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco de Occidente",
            "domain": "bancodeoccidente.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco Popular",
            "domain": "bancopopular.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco AV Villas",
            "domain": "avvillas.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Scotiabank Colpatria",
            "domain": "scotiabankcolpatria.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco Caja Social",
            "domain": "bancocajasocial.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco Agrario de Colombia",
            "domain": "bancoagrario.gov.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco Falabella Colombia",
            "domain": "bancofalabella.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Banco Pichincha Colombia",
            "domain": "bancopichincha.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Nequi",
            "domain": "nequi.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Daviplata",
            "domain": "daviplata.com",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Dale!",
            "domain": "dale.com.co",
            "category": OfficialDomain.Category.BANK,
        },
        {
            "entity_name": "Movii",
            "domain": "movii.com.co",
            "category": OfficialDomain.Category.BANK,
        },

        # --- Entidades Gubernamentales y de Justicia ---
        {
            "entity_name": "DIAN (Dirección de Impuestos y Aduanas Nacionales)",
            "domain": "dian.gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },
        {
            "entity_name": "Registraduría Nacional del Estado Civil",
            "domain": "registraduria.gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },
        {
            "entity_name": "Fiscalía General de la Nación",
            "domain": "fiscalia.gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },
        {
            "entity_name": "Policía Nacional de Colombia / CAI Virtual",
            "domain": "policia.gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },
        {
            "entity_name": "Rama Judicial de Colombia",
            "domain": "ramajudicial.gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },
        {
            "entity_name": "Portal del Estado Colombiano (GOV.CO)",
            "domain": "gov.co",
            "category": OfficialDomain.Category.GOVERNMENT,
        },

        # --- Empresas de Envíos, Paquetería y Mensajería ---
        {
            "entity_name": "Servientrega",
            "domain": "servientrega.com",
            "category": OfficialDomain.Category.COURIER,
        },
        {
            "entity_name": "4-72 (Servicios Postales Nacionales)",
            "domain": "4-72.com.co",
            "category": OfficialDomain.Category.COURIER,
        },
        {
            "entity_name": "Inter Rapidísimo",
            "domain": "interrapidisimo.com",
            "category": OfficialDomain.Category.COURIER,
        },
    ]

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE("Iniciando carga de dominios oficiales de Colombia en Zent..."))
        created_count = 0
        updated_count = 0

        for item in self.OFFICIAL_DOMAINS:
            obj, created = OfficialDomain.objects.update_or_create(
                domain=item['domain'].strip().lower(),
                defaults={
                    'entity_name': item['entity_name'],
                    'category': item['category'],
                    'is_active': True,
                }
            )
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f"  [+] Creado: {obj.entity_name} ({obj.domain})"))
            else:
                updated_count += 1
                self.stdout.write(self.style.WARNING(f"  [*] Actualizado: {obj.entity_name} ({obj.domain})"))

        total = created_count + updated_count
        self.stdout.write(
            self.style.SUCCESS(
                f"\nCarga completada con éxito. Total procesados: {total} "
                f"(Nuevos: {created_count}, Actualizados: {updated_count})"
            )
        )
