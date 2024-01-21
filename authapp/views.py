from django.shortcuts import render ,redirect,HttpResponse
from django.contrib.auth.models import User
# Create your views here.
from django.shortcuts import render
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from django.template.loader_tags import render_to_string
from django.utils.http import urlsafe_base64_decode , urlsafe_base64_encode
from .utils import TokenGenerator , generate_token
# Create your views here.
def signup(request):
   
    if request.method=="POST":
        email=request.POST.get("email")
        password =request.POST.get("pass1")
        confirm_password =request.POST.get("pass2")
        if password != confirm_password:
            messages.info(request,'password is not matching')
            return redirect('/auth/signup/')
        try:
            if User.objects.get(username=email):
                messages.info(request,"email is taken")
                return HttpResponse("usercreated")
                return redirect('/auth/signup/')
        except Exception as identifier :
            pass
        user=User.objects.create_user(email,email,password)
        user.is_active=False

        user.save()
        email_subject="Active Your Account "
        message =render_to_string('activate.html',{'user':user,
                                                        'domain':'127.0.0.1:8000',
                                                        'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                                                        'token':generate_token.make_token(user)
                                                        })
        messages.success(request,'USER IS CREATED PLEASE LOGIN')
        return HttpResponse("usercreated")
        return redirect('/auth/login/')
    return render (request ,"authentication/signup.html")

def handlelogin(request):
    return render (request ,"authentication/login.html")
 

def handlelogout(request):
    return redirect("/auth/login/")