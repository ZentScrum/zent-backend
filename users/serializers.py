from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializador de registro para nuevos usuarios de Zent.
    Exige la aceptación explícita de términos bajo la Ley 1581 de Habeas Data.
    """
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
    )
    accepted_terms = serializers.BooleanField(required=True)

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'first_name',
            'last_name',
            'password',
            'password_confirm',
            'accepted_terms',
            'terms_accepted_at',
        )
        read_only_fields = ('id', 'terms_accepted_at')

    def validate_accepted_terms(self, value):
        if value is not True:
            raise serializers.ValidationError(
                "Debe aceptar expresamente los términos y la política de tratamiento de datos personales (Ley 1581 de 2012)."
            )
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Las contraseñas no coinciden."})

        # Validación con las directivas enterprise de contraseñas de Django
        user_dummy = User(email=attrs['email'])
        validate_password(attrs['password'], user=user_dummy)

        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializador para autenticación por correo electrónico y contraseña.
    Retorna tokens JWT junto con el perfil y rol del usuario.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'},
    )

    def validate(self, attrs):
        email = attrs.get('email', '').strip().lower()
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password,
        )

        if not user:
            raise serializers.ValidationError(
                {"detail": "Credenciales inválidas. Verifique su correo y contraseña."}
            )

        if not user.is_active:
            raise serializers.ValidationError(
                {"detail": "Esta cuenta ha sido desactivada o suspendida por seguridad."}
            )

        # Generación de tokens JWT
        refresh = RefreshToken.for_user(user)
        refresh['email'] = user.email
        refresh['is_moderator'] = user.is_moderator
        refresh['role'] = user.role

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_moderator': user.is_moderator,
                'role': user.role,
                'accepted_terms': user.accepted_terms,
                'terms_accepted_at': user.terms_accepted_at,
            }
        }


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializador de consulta de perfil de usuario.
    """
    role = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'first_name',
            'last_name',
            'is_moderator',
            'role',
            'accepted_terms',
            'terms_accepted_at',
            'date_joined',
        )
        read_only_fields = (
            'id',
            'email',
            'is_moderator',
            'role',
            'accepted_terms',
            'terms_accepted_at',
            'date_joined',
        )
