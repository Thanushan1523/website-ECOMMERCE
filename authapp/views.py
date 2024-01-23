from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import TokenGenerator, generate_token
from django.utils.encoding import force_bytes,force_str, DjangoUnicodeDecodeError

from django.core.mail import EmailMessage
from django.conf import settings


def signup(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("pass1")
        confirm_password = request.POST.get("pass2")

        if password != confirm_password:
            messages.info(request, 'Password is not matching')
            return redirect('/auth/signup/')

        try:
            if User.objects.get(username=email):
                messages.info(request, "Email is already taken")
                return redirect('/auth/signup/')
        except User.DoesNotExist:
            pass

        user = User.objects.create_user(email, email, password)
        user.is_active = False
        user.save()

        email_subject = "Activate Your Account"
        message = render_to_string('activate.html', {
            'user': user,
            'domain': '127.0.0.1:8000/',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': TokenGenerator().make_token(user)
        })

        email_message = EmailMessage(
            email_subject, message, settings.EMAIL_HOST_USER, [email])
        email_message.send()

        messages.success(
            request, "Activate your account by clicking the link in your email.")
        return redirect('/auth/login/')

    return render(request, "authentication/signup.html")


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, DjangoUnicodeDecodeError, User.DoesNotExist):
            user = None

        if user is not None and TokenGenerator().check_token(user, token):
            user.is_active = True

            user.save()
            messages.success(request, "Account Activated Successfully")
            return redirect('/auth/login')
        else:
            return render(request, 'auth/activatefail.html')


def handlelogin(request):
    return render(request, "authentication/login.html")


def handlelogout(request):
    return redirect("/auth/login/")
