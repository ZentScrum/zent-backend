from django.db import migrations


def create_default_admin_user(apps, schema_editor):
    User = apps.get_model('users', 'User')
    email = 'admin@zent.security'

    user = User.objects.filter(email=email).first()
    if not user:
        from django.contrib.auth.hashers import make_password
        user = User.objects.create(
            email=email,
            password=make_password('AdminSecure2026!'),
            first_name='Administrador',
            last_name='Zent Enterprise',
            is_staff=True,
            is_superuser=True,
            is_moderator=True,
            accepted_terms=True,
            is_active=True,
        )


def reverse_default_admin_user(apps, schema_editor):
    User = apps.get_model('users', 'User')
    User.objects.filter(email='admin@zent.security').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_default_admin_user, reverse_default_admin_user),
    ]
