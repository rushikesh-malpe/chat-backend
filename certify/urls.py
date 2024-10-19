"""
This module contains URL configurations for the API.

"""
from django.urls import path
from certify.views import GoogleAuthView, LoginView, RegisterView, ResendOtpView, VerifyOtpView

urlpatterns = [
    path('register/', RegisterView.as_view(authentication_classes=[]), name='register'),
    path('verify/', VerifyOtpView.as_view(authentication_classes=[]), name='verify'),
    path('resend_activation/', ResendOtpView.as_view(authentication_classes=[]), name='otp-send'),
    path('login/', LoginView.as_view(authentication_classes=[]), name='login'),
    path('social/google/', GoogleAuthView.as_view(authentication_classes=[]), name='social-google'),

]