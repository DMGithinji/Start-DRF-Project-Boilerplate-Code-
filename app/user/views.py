from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import generics, permissions
from rest_framework.settings import api_settings
from .serializers import UserSerializer, AuthTokenPairSerializer


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]


class CustomJWTPairView(TokenObtainPairView):
    serializer_class = AuthTokenPairSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer

    def get_object(self):
        """Retrieve and return authentication user"""
        return self.request.user
