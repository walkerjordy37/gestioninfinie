"""
Serializers for IAM module.
"""
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from apps.core.serializers import BaseModelSerializer
from .models import User, Role, CompanyMembership


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT token serializer with additional claims."""

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = user.email
        token['full_name'] = user.full_name

        # Add default company
        default_membership = user.memberships.filter(is_default=True, is_active=True).first()
        if default_membership:
            token['company_id'] = str(default_membership.company.id)
            token['company_name'] = default_membership.company.name
            token['role'] = default_membership.role

        return token


class UserSerializer(BaseModelSerializer):
    full_name = serializers.CharField(read_only=True)
    companies = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone', 'avatar', 'is_active', 'language', 'timezone',
            'date_joined', 'last_login', 'companies'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']

    def get_companies(self, obj):
        memberships = obj.memberships.filter(is_active=True).select_related('company')
        return [
            {
                'id': str(m.company.id),
                'code': m.company.code,
                'name': m.company.name,
                'role': m.role,
                'is_default': m.is_default,
                'membership_id': str(m.id)
            }
            for m in memberships
        ]


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'first_name', 'last_name', 'phone']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Les mots de passe ne correspondent pas'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """Serializer for admin to create users in their company."""
    password = serializers.CharField(write_only=True, required=False)
    role = serializers.ChoiceField(
        choices=['member', 'manager', 'admin'],
        default='member',
        write_only=True
    )

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name', 'phone', 'role']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Un utilisateur avec cet email existe déjà.")
        return value

    def create(self, validated_data):
        role = validated_data.pop('role', 'member')
        password = validated_data.pop('password', None)
        
        # Generate password if not provided
        if not password:
            import secrets
            password = secrets.token_urlsafe(12)
        
        user = User.objects.create_user(password=password, **validated_data)
        
        # Create membership in admin's company
        company = self.context.get('company')
        if company:
            CompanyMembership.objects.create(
                user=user,
                company=company,
                role=role,
                is_active=True,
                is_default=True
            )
        
        # Store generated password to return it
        user._generated_password = password
        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({'new_password_confirm': 'Les mots de passe ne correspondent pas'})
        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Mot de passe actuel incorrect')
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])
    new_password_confirm = serializers.CharField()

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({'new_password_confirm': 'Les mots de passe ne correspondent pas'})
        return attrs


class RoleSerializer(BaseModelSerializer):
    class Meta:
        model = Role
        fields = [
            'id', 'name', 'code', 'description', 'is_system',
            'can_view_financials', 'can_post_accounting', 'can_manage_inventory',
            'can_approve_purchases', 'can_manage_sales', 'can_manage_partners',
            'can_view_reports', 'can_manage_users', 'can_manage_settings'
        ]
        read_only_fields = ['id', 'is_system']


class CompanyMembershipSerializer(BaseModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    company_name = serializers.CharField(source='company.name', read_only=True)
    branch_name = serializers.CharField(source='branch.name', read_only=True)

    class Meta:
        model = CompanyMembership
        fields = [
            'id', 'user', 'user_email', 'user_name',
            'company', 'company_name', 'role', 'custom_role',
            'branch', 'branch_name', 'is_active', 'is_default',
            'can_view_financials', 'can_post_accounting',
            'can_manage_inventory', 'can_approve_purchases',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class CompanyMembershipCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyMembership
        fields = [
            'user', 'company', 'role', 'custom_role', 'branch',
            'can_view_financials', 'can_post_accounting',
            'can_manage_inventory', 'can_approve_purchases'
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user to update their own profile."""
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'avatar', 'language', 'timezone']
