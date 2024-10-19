from rest_framework import serializers
from django.contrib.auth import get_user_model,authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
import pyotp

from api.common.models import Users



from rest_framework import serializers

import pyotp
from django.conf import settings
from rest_framework import serializers

from api.common.utils import send_verification_email
from certify.enums import MessageEnum


class UserCreateSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(read_only=True)

    class Meta:
        model = Users
        fields = ('email', 'password', 'otp')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user,otp=Users.objects.create_user(**validated_data)
        send_verification_email(user.email,otp)
        return user




class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, min_length=6, max_length=6)

    def validate_otp(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        return value


class ResendVeriOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6, write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        user = Users.objects.filter(email=email).first()
        if user is None:
            raise serializers.ValidationError(MessageEnum.INVALID_CREDENTIALS.value)
        
        return attrs

class GoogleAuthSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, help_text="Authorization code from Facebook")
    redirect_uri = serializers.URLField(required=True, help_text="The redirect URI for Facebook OAuth")

# class UserCreateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Users
#         fields = ['email', 'password']

#     def create(self, validated_data):
#         otp = pyotp.TOTP(settings.OTP_SECRECT).now()
#         user = Users.objects.create(
#             email=validated_data['email'],
#             password=validated_data['password'],
#             otp=otp
#         )
#         user.is_active = False  
#         user.save()

        
#         print(otp)
#         # send_verification_email(user.email, otp)  
#         return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data['email'], password=data['password'])
        if user and user.is_active:
            refresh = RefreshToken.for_user(user)
            return {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        raise serializers.ValidationError("Invalid credentials or unverified account")
