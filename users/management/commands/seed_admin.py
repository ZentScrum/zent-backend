from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = 'Crea o actualiza el superusuario por defecto (admin@zent.security) para desarrollo y monitoreo web.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            default='admin@zent.security',
            help='Correo electrónico del superusuario',
        )
        parser.add_argument(
            '--password',
            type=str,
            default='AdminSecure2026!',
            help='Contraseña segura del superusuario',
        )

    def handle(self, *args, **options):
        email = options['email'].strip().lower()
        password = options['password']

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'first_name': 'Administrador',
                'last_name': 'Zent Enterprise',
                'is_staff': True,
                'is_superuser': True,
                'is_moderator': True,
                'accepted_terms': True,
                'is_active': True,
            }
        )

        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_moderator = True
        user.accepted_terms = True
        user.is_active = True
        user.first_name = 'Administrador'
        user.last_name = 'Zent Enterprise'
        user.save()

        if created:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Superusuario '{email}' creado exitosamente con credenciales por defecto."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Superusuario '{email}' actualizado exitosamente con la contraseña configurada."
                )
            )
