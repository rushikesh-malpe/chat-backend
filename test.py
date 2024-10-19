import requests
from django.conf import settings
from rest_framework.response import Response
from rest_framework.views import APIView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter


class GoogleAuthView(APIView):
    def post(self, request, *args, **kwargs):
        code = request.data.get('code')

        if not code:
            return Response({'error': 'No code provided'}, status=400)

        # Step 1: Exchange the code for a token from Google
        token_url = "https://oauth2.googleapis.com/token"
        token_data = {
            'code': code,
            'client_id': settings.SOCIAL_AUTH_GOOGLE_CLIENT_ID,
            'client_secret': settings.SOCIAL_AUTH_GOOGLE_SECRET,
            'redirect_uri': request.data.get('redirect_uri'),
            'grant_type': 'authorization_code',
        }

        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()

        if 'access_token' not in token_json:
            return Response({'error': 'Failed to get access token from Google'}, status=400)

        access_token = token_json['access_token']

        # Step 2: Get user information from Google
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        user_info_response = requests.get(user_info_url, headers={'Authorization': f'Bearer {access_token}'})
        user_info = user_info_response.json()

        if not user_info.get('email'):
            return Response({'error': 'Failed to retrieve user info from Google'}, status=400)

        email = user_info['email']
        first_name = user_info.get('given_name', '')
        last_name = user_info.get('family_name', '')

        # Step 3: Check if the user exists, otherwise create a new user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = User.objects.create(
                username=email,
                email=email,
                first_name=first_name,
                last_name=last_name,
            )

        # Step 4: Generate JWT token for the user
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
