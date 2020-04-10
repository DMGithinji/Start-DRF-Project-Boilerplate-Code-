import jwt

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status


CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')


def create_user(**params):
    """helper function to create users for tests"""
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):
    """Tests for signup and signin for non authenticated users"""

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_successfully(self):
        """Test creating user with valid payload is successful"""
        payload = {
            'email': 'testuser@email.com',
            'password': 'Testpassword123',
            'name': 'Testestrone'
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(**res.data)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)

    def test_user_already_exists(self):
        """Test creating a user who already exists fails"""
        payload = {'email': 'testuser@email.com', 'password': 'Testpass123'}
        create_user(**payload)

        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        """Test creating user fails if password too short"""
        payload = {'email': 'testuser@email.com',  'password': 'Test'}
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_jwt_for_authenticated_user(self):
        """Test access and refresh tokens creation for successful login"""
        payload = {'email': 'testuser@email.com',  'password': 'Test'}
        create_user(**payload)
        res = self.client.post(TOKEN_URL, payload)

        self.assertIn('access', res.data)
        self.assertIn('refresh', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_no_jwt_if_invalid_credentials(self):
        """Test that tokens not created if invalid user credentials"""
        create_user(email='testuser@email.com', password='secretpassword')
        payload = {'email': 'testuser@email.com',  'password': 'wrongpass'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('access', res.data)
        self.assertNotIn('refresh', res.data)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_no_jwt_if_not_user(self):
        """Test that token is not created if user does not exist"""
        payload = {'email': 'testuser@email.com',  'password': 'testpass'}
        res = self.client.post(TOKEN_URL, payload)

        self.assertNotIn('access', res.data)
        self.assertNotIn('refresh', res.data)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_custom_fields_in_jwt(self):
        """Test that JWT access token contains added custom fields"""
        payload = {
            'email': 'testuser@email.com',
            'password': 'testpass',
            'name': 'Testosterone'
        }
        create_user(**payload)
        res = self.client.post(TOKEN_URL, payload)
        decodedPayload = jwt.decode(res.data['access'], None, None)

        self.assertIn('name', decodedPayload)
        self.assertIn('email', decodedPayload)
