from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.files.base import ContentFile
import sqlite3
import json
    
@login_required
def home(request):
    uploaded_file_url = None
    error = None

    #top_reports = Report.objects.order_by('-score')[:5]
    #change when DB is ready
    top_reports = []


    if request.method == "POST":
        submit_type = request.POST.get("submit_type")
        fs = FileSystemStorage()

        # --- 🔹 Case 1: ZIP eller CRX uppladdning ---
        if submit_type in ["zip", "crx"]:
            upload = request.FILES.get("submission_file")
            if not upload:
                error = f"Please select a valid .{submit_type} file."
                return render(request, "home.html", {"error": error})

            name = upload.name.lower()
            if submit_type == "zip" and not name.endswith(".zip"):
                error = "Uploaded file must be a .zip file."
                return render(request, "home.html", {"error": error})
            if submit_type == "crx" and not name.endswith(".crx"):
                error = "Uploaded file must be a .crx file."
                return render(request, "home.html", {"error": error})

            filename = fs.save(upload.name, upload)
            uploaded_file_url = fs.url(filename)
            return render(request, "home.html", {
                "uploaded_file_url": uploaded_file_url,
                "error": None
            })

        # --- 🔹 Case 2: Webstore ID ---
        elif submit_type == "id":
            webstore_id = (request.POST.get("submission_value") or "").strip()
            if not webstore_id:
                error = "Please enter an Extension ID."
                return render(request, "home.html", {"error": error})

            if not (len(webstore_id) == 32 and webstore_id.isalpha() and webstore_id.islower()):
                error = "Webstore ID must be 32 lowercase letters (a–z)."
                return render(request, "home.html", {"error": error})

            txt_name = "webstore_id.txt"
            if fs.exists(txt_name):
                fs.delete(txt_name)
            fs.save(txt_name, ContentFile(webstore_id + "\n"))

            return render(request, "home.html", {"error": None})

        # --- 🔹 Case 3: okänd typ ---
        else:
            error = "Invalid submission type."
            return render(request, "home.html", {"error": error})

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
    error = None

    if request.method == "POST":
        extension_id = (request.POST.get("extension_id") or "").strip()

        if not (len(extension_id) == 32 and extension_id.isalpha() and extension_id.islower()):
            error = "Extension ID must be 32 lowercase letters (a–z)."
            return render(request, "mitre_attack.html", {"error": error})

        #report = Report.objects.filter(extension_id=extension_id).first()
        #if not report:
        #    error = "Extension not found in database."
        #    return render(request, "mitre_attack.html", {"error": error})

        # Finns -> redirect till rapport-sida
        return redirect("mitre_report", extension_id=extension_id)

    return render(request, "mitre_attack.html", {"error": error})

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
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row  # This allows fetching rows as dictionaries
    
    
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM reports WHERE file_hash=?;", (sha256,))
    
    row = cursor.fetchone()

    if row:
        result = dict(row)  # Convert sqlite3.Row to dict
        # print(result)
    else:
        print("No record found.") 
    
    #print(json_output)

    '''
    file_hash = cursor.execute("SELECT file_hash FROM reports WHERE file_hash=?;", (sha256,))
    extention_id = cursor.execute("SELECT extention_id FROM reports WHERE file_hash=?;", (sha256,))
    created_at = cursor.execute("SELECT date FROM reports WHERE file_hash=?;", (sha256,))
    score = cursor.execute("SELECT score FROM reports WHERE file_hash=?;", (sha256,))
    verdict = cursor.execute("SELECT verdict FROM reports WHERE file_hash=?;", (sha256,))
    summary = cursor.execute("SELECT description FROM reports WHERE file_hash=?;", (sha256,))
    permissions = cursor.execute("SELECT permissions FROM reports WHERE file_hash=?;", (sha256,))
    findings = cursor.execute("SELECT risks FROM reports WHERE file_hash=?;", (sha256,))
    malware_types = cursor.execute("SELECT malware_types FROM reports WHERE file_hash=?;", (sha256,))
    
    
    dummy = {
        "file_hash": file_hash,
        "extension_id": extention_id,
        "created_at": created_at,
        "score": score,
        "verdict": verdict,
        "summary": summary,
        "permissions": permissions,
        "findings": findings,
        "malware_types": malware_types,
        "sha256": sha256 or "abc123",
    }
    
    print(dummy)
    '''
    return render(request, "result.html", {"report": result})
