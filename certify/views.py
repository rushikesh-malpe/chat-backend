# from django.conf import settings
import requests
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
import pyotp
from api.common.models import Users
from api.common.utils import send_verification_email
from certify import constants
from certify.enums import MessageEnum, StatusEnum,GrantTypeEnum
from certify.serializers import GoogleAuthSerializer, LoginSerializer, ResendVeriOtpSerializer, UserCreateSerializer, UserLoginSerializer, VerifyOtpSerializer
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate



class RegisterView(APIView):
    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
            "status": StatusEnum.SUCCESS.value, 
            "message": MessageEnum.OTP_SENT.value, 
        }, status=status.HTTP_201_CREATED)
        return Response({
            "status": StatusEnum.ERROR.value, 
            "message":serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)



class VerifyOtpView(APIView):
    def post(self, request):
        serializer = VerifyOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        
        user = Users.objects.filter(email=email).first()

        if user is None:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.ACCOUNT_NOT_FOUND.value,
            }, status=status.HTTP_404_NOT_FOUND)
        
        if user.otp_verified:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message":MessageEnum.OTP_ALREADY_VARIFIED.value ,
            }, status=status.HTTP_400_BAD_REQUEST)

        if int(user.otp) == int(otp) and pyotp.TOTP(settings.OTP_SECRET,interval=600).verify(otp):
            user.is_active = True
            user.is_email_verified = True
            user.otp_verified = True
            user.save()
            return Response({
                "status": StatusEnum.SUCCESS.value,
                "message": MessageEnum.EMAIL_VERIFIED.value,
            }, status=status.HTTP_200_OK)

        return Response({
            "status": StatusEnum.ERROR.value,
            "message": MessageEnum.INVALID_OTP.value,
        }, status=status.HTTP_400_BAD_REQUEST)



class ResendOtpView(APIView):
    def post(self, request):
        serializer = ResendVeriOtpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        user = Users.objects.filter(email=email).first()

        if user is None:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.ACCOUNT_NOT_FOUND.value,
            }, status=status.HTTP_404_NOT_FOUND)
        
        if user.otp_sent_at and timezone.now() < user.otp_sent_at + timedelta(minutes=1):
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.OTP_RESENT_TIME_LIMIT.value,
            }, status=status.HTTP_400_BAD_REQUEST)

        user.otp = pyotp.TOTP(settings.OTP_SECRET).now()
        user.otp_sent_at = timezone.now()  
        user.save()
        send_verification_email(email,user.otp)
        return Response({
            "status": StatusEnum.SUCCESS.value, 
            "message": MessageEnum.OTP_SENT.value, 
        }, status=status.HTTP_200_OK)



class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.INVALID_CREDENTIALS.value,
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        refresh = RefreshToken.for_user(user)
        return Response({
            "status": StatusEnum.SUCCESS.value,
            "message":MessageEnum.LOGIN_SUCCESSFUL.value,
            "data": {"refresh": str(refresh),"access": str(refresh.access_token)},
        }, status=status.HTTP_200_OK)



class GoogleAuthView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = GoogleAuthSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": serializer.errors,
            }, status=status.HTTP_400_BAD_REQUEST)
        
        code = serializer.validated_data.get('code')
        redirect_uri = serializer.validated_data.get('redirect_uri')

        if not code:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.NO_AUTH_CODE_PROVIDED.value,
            }, status=status.HTTP_400_BAD_REQUEST)
        

        token_url = constants.GOOGLE_TOKEN_EXCHANGE_URL
        token_data = {
            'code': code,
            'client_id': settings.SOCIAL_AUTH_GOOGLE_CLIENT_ID,
            'client_secret': settings.SOCIAL_AUTH_GOOGLE_SECRET,
            'redirect_uri': redirect_uri,
            'grant_type':GrantTypeEnum.GOOGLE_AUTH_GRANT_TYPE.value,
        }

        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        print("TOKEN",token_json)

        if 'access_token' not in token_json:
            return Response(
                {
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.FAILED_TO_GET_AUTH_TOKEN.value,
            }, status=status.HTTP_400_BAD_REQUEST
            )

        access_token = token_json['access_token']


        user_info_url = constants.GOOGLE_USER_INFO_URL

        user_info_response = requests.get(
            user_info_url, headers={'Authorization': f'Bearer {access_token}'})
        
        user_info = user_info_response.json()
        print("USER_INFO",user_info)
        
        if not user_info.get('email'):
            return Response({'error': 'Failed to retrieve user info from Google'}, status=400)

        email = user_info['email']
        first_name = user_info.get('given_name')
        last_name = user_info.get('family_name')
        profile_url = user_info.get('picture')
        is_email_verified = user_info.get('verified_email',False)

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            user = Users.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                profile_url=profile_url,
                is_email_verified=is_email_verified
            )

        if not is_email_verified:
            user.otp = pyotp.TOTP(settings.OTP_SECRET).now()
            user.otp_sent_at = timezone.now()  
            user.save()
            send_verification_email(email,user.otp)
            return Response({
                    "status": StatusEnum.SUCCESS.value, 
                    "message": MessageEnum.OTP_SENT.value, 
                }, status=status.HTTP_200_OK)
        
        refresh = RefreshToken.for_user(user)
        return Response({
            "status": StatusEnum.SUCCESS.value,
            "message":MessageEnum.LOGIN_SUCCESSFUL.value,
            "data": {"refresh": str(refresh),"access": str(refresh.access_token)},
        }, status=status.HTTP_200_OK)




