from rest_framework import generics
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import UserSerializer, AuthTokenPairSerializer


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer


class CustomJWTPairView(TokenObtainPairView):
    serializer_class = AuthTokenPairSerializer
