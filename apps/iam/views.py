"""
Views for IAM module.
"""
import uuid
from datetime import timedelta
from django.utils import timezone
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from apps.core.viewsets import BaseViewSet, CompanyScopedViewSet
from apps.core.permissions import IsCompanyAdmin
from .models import User, Role, CompanyMembership, PasswordResetToken
from .serializers import (
    CustomTokenObtainPairSerializer, UserSerializer, UserCreateSerializer,
    ChangePasswordSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, RoleSerializer, CompanyMembershipSerializer,
    CompanyMembershipCreateSerializer, UserProfileSerializer, AdminUserCreateSerializer
)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom login endpoint with extended token claims."""
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Add user info to response
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid()
            user = serializer.user
            
            # Get user's companies
            memberships = user.memberships.filter(is_active=True).select_related('company')
            companies = [
                {
                    'id': str(m.company.id),
                    'code': m.company.code,
                    'name': m.company.name,
                    'role': m.role,
                    'is_default': m.is_default
                }
                for m in memberships
            ]
            
            # Find default company
            default_company = None
            for m in memberships:
                if m.is_default:
                    default_company = str(m.company.id)
                    break
            if not default_company and memberships.exists():
                default_company = str(memberships.first().company.id)
            
            response.data['user'] = {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'companies': companies,
                'default_company': default_company,
            }
        
        return response


class RegisterView(generics.CreateAPIView):
    """User registration endpoint."""
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = UserCreateSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Generate tokens for auto-login
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)


class UserViewSet(BaseViewSet):
    """Manage users."""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    filterset_fields = ['is_active', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name', 'phone']

    def get_queryset(self):
        if self.request.user.is_superuser:
            return super().get_queryset()
        # Return users in the same companies
        company_ids = self.request.user.memberships.filter(
            is_active=True
        ).values_list('company_id', flat=True)
        return User.objects.filter(
            memberships__company_id__in=company_ids
        ).distinct()

    @action(detail=False, methods=['get', 'patch'])
    def me(self, request):
        """Get or update current user profile."""
        if request.method == 'PATCH':
            serializer = UserProfileSerializer(
                request.user,
                data=request.data,
                partial=True
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()

        return Response(UserSerializer(request.user).data)

    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """Change current user's password."""
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()

        return Response({'message': 'Mot de passe modifié avec succès'})

    @action(detail=False, methods=['post'], permission_classes=[IsCompanyAdmin])
    def create_member(self, request):
        """Create a new user in the admin's company."""
        # Get company from request
        company = self._get_company()
        if not company:
            return Response(
                {'error': 'Aucune entreprise associée'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = AdminUserCreateSerializer(
            data=request.data,
            context={'request': request, 'company': company}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        return Response({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'password': getattr(user, '_generated_password', None),
            'message': 'Utilisateur créé avec succès'
        }, status=status.HTTP_201_CREATED)

    def _get_company(self):
        """Get company from header or user's default."""
        company = getattr(self.request, 'company', None)
        if company:
            return company
        
        if not self.request.user.is_authenticated:
            return None
        
        company_id = self.request.headers.get('X-Company-ID')
        if company_id:
            try:
                membership = self.request.user.memberships.get(
                    company_id=company_id, is_active=True
                )
                return membership.company
            except Exception:
                pass
        
        membership = self.request.user.memberships.filter(
            is_active=True, is_default=True
        ).first() or self.request.user.memberships.filter(is_active=True).first()
        
        return membership.company if membership else None

    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def password_reset_request(self, request):
        """Request password reset email."""
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = PasswordResetToken.objects.create(
                user=user,
                token=str(uuid.uuid4()),
                expires_at=timezone.now() + timedelta(hours=24)
            )
            # TODO: Send email with reset link
        except User.DoesNotExist:
            pass  # Don't reveal if email exists

        return Response({'message': 'Si cet email existe, un lien de réinitialisation a été envoyé'})

    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def password_reset_confirm(self, request):
        """Confirm password reset with token."""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token_obj = PasswordResetToken.objects.get(
                token=serializer.validated_data['token']
            )
            if not token_obj.is_valid:
                return Response(
                    {'error': 'Token invalide ou expiré'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            token_obj.user.set_password(serializer.validated_data['new_password'])
            token_obj.user.save()
            token_obj.is_used = True
            token_obj.save()

            return Response({'message': 'Mot de passe réinitialisé avec succès'})
        except PasswordResetToken.DoesNotExist:
            return Response(
                {'error': 'Token invalide'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'])
    def switch_company(self, request):
        """Switch the user's active company."""
        company_id = request.data.get('company_id')
        if not company_id:
            return Response(
                {'error': 'company_id requis'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            membership = request.user.memberships.get(
                company_id=company_id,
                is_active=True
            )
            # Set as default
            request.user.memberships.filter(is_default=True).update(is_default=False)
            membership.is_default = True
            membership.save()

            # Generate new token with updated company
            refresh = RefreshToken.for_user(request.user)
            refresh['company_id'] = str(membership.company.id)
            refresh['company_name'] = membership.company.name
            refresh['role'] = membership.role

            return Response({
                'company': {
                    'id': str(membership.company.id),
                    'name': membership.company.name
                },
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            })
        except CompanyMembership.DoesNotExist:
            return Response(
                {'error': 'Accès non autorisé à cette entreprise'},
                status=status.HTTP_403_FORBIDDEN
            )


class RoleViewSet(BaseViewSet):
    """Manage roles."""
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    filterset_fields = ['is_system']
    search_fields = ['name', 'code']

    def destroy(self, request, *args, **kwargs):
        role = self.get_object()
        if role.is_system:
            return Response(
                {'error': 'Impossible de supprimer un rôle système'},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().destroy(request, *args, **kwargs)


class CompanyMembershipViewSet(CompanyScopedViewSet):
    """Manage company memberships."""
    queryset = CompanyMembership.objects.select_related('user', 'company', 'branch', 'custom_role')
    serializer_class = CompanyMembershipSerializer
    permission_classes = [IsCompanyAdmin]
    filterset_fields = ['role', 'is_active', 'branch']
    search_fields = ['user__email', 'user__first_name', 'user__last_name']

    def get_serializer_class(self):
        if self.action == 'create':
            return CompanyMembershipCreateSerializer
        return CompanyMembershipSerializer

    def perform_create(self, serializer):
        serializer.save(company=self.request.company)

    @action(detail=True, methods=['post'])
    def deactivate(self, request, pk=None):
        """Deactivate a membership."""
        membership = self.get_object()
        membership.is_active = False
        membership.save()
        return Response({'status': 'deactivated'})

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate a membership."""
        membership = self.get_object()
        membership.is_active = True
        membership.save()
        return Response({'status': 'activated'})
