from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.files.base import ContentFile


@login_required
def home(request):
    uploaded_file_url = None
    error = None

    if request.method == "POST" and request.FILES.get("myUploadedFile"):
        myuploadedfile = request.FILES["myUploadedFile"]
        
        name = myuploadedfile.name.lower()
        if not (name.endswith(".zip") or name.endswith(".crx")):
            error = "Please upload a valid .zip or .crx file."
            return render(request, "home.html", {"uploaded_file_url": uploaded_file_url, "error": error})

        fs = FileSystemStorage()
        filename = fs.save(myuploadedfile.name, myuploadedfile)
        uploaded_file_url = fs.url(filename)

        return render(request, "home.html", {"uploaded_file_url": uploaded_file_url, "error": None})

    if request.method == "POST":
        webstore_id = (request.POST.get("mytext") or request.POST.get("webstore_id") or "").strip()
        if webstore_id:
            if not (len(webstore_id) == 32 and webstore_id.isalpha() and webstore_id.islower()):
                error = "Webstore ID must be 32 lowercase letters (a–z)."
                return render(request, "home.html", {"uploaded_file_url": None, "error": error})

            fs = FileSystemStorage()
            txt_name = "webstore_id.txt"
            if fs.exists(txt_name):
                fs.delete(txt_name)
            fs.save(txt_name, ContentFile(webstore_id + "\n"))

            return render(request, "home.html", {"uploaded_file_url": None, "error": None})

    return render(request, "home.html")

@login_required
def report(request):
    return HttpResponse("This is the Report page")

@login_required
def history(request):
    return render(request, "history.html")

@login_required
def results(request):
    return render(request, "results.html")

@login_required
def settings(request):
    return render(request, "settings.html")

@login_required
def mitre_attack(request):
    return render(request, "mitre_attack.html")

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
            error = "Wrong Credentials"
    return render(request, "login.html", {"error": error})

def logout_view(request):
    logout(request)
    return redirect("login") 

def report_view(request, sha256=None):
    dummy = {
        "name": "Example Ad Blocker",
        "extension_id": "abcd1234efgh5678",
        "created_at": "2025-10-08 15:00",
        "score": 82,
        "verdict": "Malicious",
        "summary": "This extension collects browsing data and injects ads.",
        "permissions": ["tabs", "storage", "https://*/*"],
        "findings": [
            {"category": "Privacy", "description": "Tracks URLs visited", "severity": "High"},
            {"category": "Injection", "description": "Injects remote JS", "severity": "Critical"},
        ],
        "iocs": ["malicious.example.com", "198.51.100.22"],
        "sha256": sha256 or "dummyhash1234567890",
    }
    return render(request, "result.html", {"report": dummy})
