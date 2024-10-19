from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings



def send_verification_email(email,otp):

    subject = 'Email Verification'
    html_content = render_to_string('verification_email.html', {'user': email, 'otp': otp})
    text_content = strip_tags(html_content)
    
    email = EmailMultiAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, [email])
    email.attach_alternative(html_content, "text/html")
    email.send()

