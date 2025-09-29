from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout




@login_required
def home(request):
    return render(request, 'index.html')


@login_required
def report(request):
    return HttpResponse("This is the Report page")

@login_required
def history(request):
    return HttpResponse("This is the History page")

def login_view(request):
    error = ""
    if request.user.is_authenticated:
        return redirect("home")

    if(request.method == "POST"):
        u = request.POST.get("username")
        p = request.POST.get("password")
        user = authenticate(request, username=u, password=p)
        if user:
            login(request,user)
            return redirect("home") 
        else:
            error = "Wrong Creds"
    return render(request, "login.html", {"error": error})

def logout_view(request):
    logout(request)
    return redirect("login") 
