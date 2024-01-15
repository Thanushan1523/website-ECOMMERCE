from django.shortcuts import render ,redirect,HttpResponse
from django.contrib.auth.models import User
# Create your views here.
from django.shortcuts import render
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages

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
                messages.warning(request,"email is taken")
                return HttpResponse("usercreated")
                return redirect('/auth/signup/')
        except Exception as identifier :
            pass
        user=User.objects.create_user(email,email,password)
        user.save()
        messages.success(request,'USER IS CREATED PLEASE LOGIN')
        return HttpResponse("usercreated")
        return redirect('/auth/login/')
    return render (request ,"authentication/signup.html")

def handlelogin(request):
    return render (request ,"authentication/login.html")
 

def handlelogout(request):
    return redirect("/auth/login/")