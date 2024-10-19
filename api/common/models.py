from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
import pyotp

class UserManager(BaseUserManager):


    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        otp = pyotp.TOTP(settings.OTP_SECRET,interval=600).now()
        user = self.model(email=email,otp=otp ,**extra_fields)
        user.set_password(password) 
        user.save(using=self._db)
        return user,otp

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

class Users(AbstractBaseUser):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6, blank=True)
    otp_sent_at = models.DateTimeField(blank=True, null=True)
    cts = models.DateTimeField(auto_now_add=True)  # Auto-sets at creation
    uts = models.DateTimeField(auto_now=True)  # Auto-updates on save
    first_name = models.CharField(max_length=30, blank=True, null=True)
    last_name = models.CharField(max_length=30, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    phone_number = models.TextField(blank=True, null=True)
    profile_url = models.TextField(blank=True, null=True)
    is_active=models.BooleanField(blank=True, null=True)
    is_email_verified=models.BooleanField(blank=True, null=True)
    otp_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = 'users'

    def __str__(self):
        return self.email