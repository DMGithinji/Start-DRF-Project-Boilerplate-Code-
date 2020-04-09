from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView
from .views import CustomJWTPairView

from . import views


app_name = 'user'

urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name='create'),
    path('token/', CustomJWTPairView.as_view(), name='token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
