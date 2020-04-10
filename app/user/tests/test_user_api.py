import jwt

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status


CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')
ACCESS_TOKEN_URL = reverse('user:token_refresh')
USER_URL = reverse('user:user_detail')


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
        """Test creating user fails if password shorter than 8 chars"""
        payload = {'email': 'testuser@email.com',  'password': 'Test123'}
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

    def test_refresh_token_endpoint(self):
        """Test that refresh token results in new access token"""
        payload = {
            'email': 'testuser@email.com',
            'password': 'testpass',
            'name': 'Testosterone'
        }
        create_user(**payload)
        tokens = self.client.post(TOKEN_URL, payload)
        refresh_token = tokens.data['refresh']
        res = self.client.post(ACCESS_TOKEN_URL, {'refresh': refresh_token})

        self.assertIn('access', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_retrieve_user_fail_if_anauthorized(self):
        """Test that authentication is required for users"""
        res = self.client.get(USER_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserAPiTest(TestCase):
    """Test API requests that require authentication"""

    def setUp(self):
        self.user = create_user(
            email='logged_in_user@email.com',
            password='a_strong_password',
            name='Testosterone'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_retrieve_profile_success(self):
        """Test retrieving profile is successful for authenticated user"""
        res = self.client.get(USER_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'name': self.user.name,
            'email': self.user.email
        })

    def test_post_user_detail_not_allowed(self):
        """Test that post is not allowed on user detail url"""
        res = self.client.post(USER_URL, {})

        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        """Test updating the user profile for authenticated user"""
        payload = {'name': 'New Name', 'password': 'Newpassword123'}

        res = self.client.patch(USER_URL, payload)

        self.user.refresh_from_db()  # update user from latest updates from db
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
