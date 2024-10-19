# from django.conf import settings
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
import pyotp
from api.common.models import Users
from api.common.utils import send_verification_email
from certify.enums import MessageEnum, StatusEnum
from certify.serializers import LoginSerializer, ResendVeriOtpSerializer, UserCreateSerializer, UserLoginSerializer, VerifyOtpSerializer
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

        # Authenticate the user
        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({
                "status": StatusEnum.ERROR.value,
                "message": MessageEnum.INVALID_CREDENTIALS.value,
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            "status": StatusEnum.SUCCESS.value,
            "message":MessageEnum.LOGIN_SUCCESSFUL.value,
            "data": {"refresh": str(refresh),"access": str(refresh.access_token)},
        }, status=status.HTTP_200_OK)







