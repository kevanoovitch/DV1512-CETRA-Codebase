from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.files.base import ContentFile
from app.backend.api import apiCaller
from app.backend.mitreFolder.mitre import mitreCall
from app.backend.utils.Checkfileidindb import check_existing_report 
import sqlite3
import json
import zipfile
import math

    
@login_required
def home(request):
    error = None
    status_message = None

    def handle_not_on_store(request, api_result, load_top_reports):
        """
        Checks the return value of the apiCaller() and stops and displays an error if invalid
        """
        if api_result == -1:
                return render(request, "home.html", {
                    "error": "This extension is not on the Chrome Web Store and thus is not supported.",
                    "status_message": None, 
                    "top_reports": load_top_reports(),
                })
        return None


    def load_top_reports():
        conn = sqlite3.connect('db.sqlite3')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT file_hash, extention_id, date, score
            FROM reports
            WHERE score IS NOT NULL
            ORDER BY score DESC
            LIMIT 5;
        """)
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "file_hash": row["file_hash"],
                "extention_id": row["extention_id"],
                "date": row["date"],
                "score": row["score"],
            }
            for row in rows
        ]

    if request.method == "POST":
        submit_type = request.POST.get("submit_type")
        fs = FileSystemStorage()

        # --- Case 1: ZIP or CRX upload ---
        if submit_type in ["zip", "crx"]:
            upload = request.FILES.get("submission_file")
            if not upload:
                error = f"Please select a valid .{submit_type} file."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })

            name = upload.name.lower()
            if submit_type == "zip" and not name.endswith(".zip"):
                error = "Uploaded file must be a .zip file."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })
            if submit_type == "crx" and not name.endswith(".crx"):
                error = "Uploaded file must be a .crx file."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })
            
            filename = fs.save(upload.name, upload)
            file_path = fs.path(filename)

            if not check_zip(file_path):
                error = "manifest.json not found inside the uploaded file. Not an Extension package."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })
            
            check = check_existing_report(file_path=file_path)
            if check["exists"]:
                # Show message instead of running analysis
                return render(request, "home.html", {
                    "existing_report": True,
                    "hash": check["hash"],
                    "extention_id": check.get("extention_id"),
                    "report_date": check["date"],
                    "top_reports": load_top_reports(),
                })

            result = apiCaller(file_path, "file")
            response = handle_not_on_store(request, result, load_top_reports)
            if response:
                return response

            status_message = "Analysis finished. See the History tab for full results."

            return render(request, "home.html", {
                "error": None,
                "status_message": status_message,
                "top_reports": load_top_reports(),
            })

        # --- Case 2: Webstore ID ---
        elif submit_type == "id":
            webstore_id = (request.POST.get("submission_value") or "").strip()
            if not webstore_id:
                error = "Please enter an Extension ID."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })

            if not (len(webstore_id) == 32 and webstore_id.isalpha() and webstore_id.islower()):
                error = "Webstore ID must be 32 lowercase letters (a–z)."
                return render(request, "home.html", {
                    "error": error,
                    "top_reports": load_top_reports(),
                })

            txt_name = "webstore_id.txt"
            if fs.exists(txt_name):
                fs.delete(txt_name)
            fs.save(txt_name, ContentFile(webstore_id + "\n"))

            check = check_existing_report(ext_id=webstore_id)

            if check["exists"]:
                return render(request, "home.html", {
                    "existing_report": True,
                    "hash": check["hash"],
                    "extention_id": webstore_id,
                    "report_date": check["date"],
                    "top_reports": load_top_reports(),
                })

            result = apiCaller(webstore_id, "id")
            response = handle_not_on_store(request, result, load_top_reports)
            if response:
                return response
           

            status_message = "Analysis finished. See the History tab for full results."

            return render(request, "home.html", {
                "error": None,
                "status_message": status_message,
                "top_reports": load_top_reports(),
            })

        # --- Case 3: unknown type ---
        else:
            error = "Invalid submission type."
            return render(request, "home.html", {
                "error": error,
                "top_reports": load_top_reports(),
            })

    return render(request, "home.html", {"top_reports": load_top_reports()})


def check_zip(file_path: str) -> bool:
    """
    Returns True if manifest.json exists inside the zip/crx file.
    """
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                if name.lower().endswith("manifest.json"):
                    return True
        return False
    except Exception:
        return False


@login_required
def report(request):
    return HttpResponse("This is the Report page")

@login_required
def history(request):
    page = int(request.GET.get("page", 1))
    per_page = 5
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row  # This allows fetching rows as dictionaries
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports;")
    total = cursor.fetchone()[0]

    offset = (page - 1) * per_page
    cursor.execute("""
        SELECT file_hash, extention_id, date, score
        FROM reports
        ORDER BY date DESC
        LIMIT ? OFFSET ?;
    """, (per_page, offset))
    rows = cursor.fetchall()
    conn.close()

    reports = [
        {
            "file_hash": row[0],
            "extention_id": row[1],
            "date": row[2],
            "score": row[3],
        }
        for row in rows
    ]

    total_pages = math.ceil(total / per_page)
    has_prev = page > 1
    has_next = page < total_pages

    context = {
        "reports": reports,
        "page": page,
        "has_prev": has_prev,
        "has_next": has_next,
        "total_pages": total_pages,
        "total": total,
        "start_index": offset + 1 if total > 0 else 0,
        "end_index": min(offset + per_page, total),
    }
    #conn.close()
    return render(request, "history.html", context)

@login_required
def settings(request):
    return render(request, "settings.html")

@login_required
def mitre_attack(request):
    mitre_error = request.session.pop("mitre_error", None)
    mitre_temp_block = request.session.pop("mitre_temp_block", None)

    # Fetch reports
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_hash, date
        FROM reports
        ORDER BY date DESC;
    """)
    reports = cursor.fetchall()
    conn.close()

    # Fetch MITRE rows
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT file_hash
        FROM mitre;
    """)
    mitre_rows = cursor.fetchall()
    conn.close()

    mitre_map = {row["file_hash"]: True for row in mitre_rows}

    merged = []
    for r in reports:
        filehash = r["file_hash"]

        if filehash in mitre_map:
            status = "done"
        else:
            status = "none"

        merged.append({
            "filehash": filehash,
            "date": r["date"],
            "mitre_status": status
        })

    return render(request, "mitre_attack.html", {
        "rows": merged,
        "mitre_error": mitre_error,
        "mitre_temp_block": mitre_temp_block,
    })

@login_required
def mitre_analyze(request, filehash):
# Check if already analyzed
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("SELECT file_hash FROM mitre WHERE file_hash=?", (filehash,))
    exists = cursor.fetchone()
    conn.close()

    if exists:
        return redirect("mitre_attack")

    # Run MITRE analysis
    result = mitreCall(filehash)

    # If MITRE has no data -> show message + TEMPORARILY hide analyze button
    if result.get("success") is False:
        request.session["mitre_error"] = result.get("message")
        request.session["mitre_temp_block"] = filehash
        return redirect("mitre_attack")

    return redirect("mitre_attack")


@login_required
def mitre_view(request, filehash):
    conn = sqlite3.connect("db.sqlite3")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sandbox, tactics, techniques, date
        FROM mitre
        WHERE file_hash=?
    """, (filehash,))
    rows = cursor.fetchall()
    conn.close()

    parsed = []

    for row in rows:
        parsed.append({
            "sandbox": row["sandbox"],
            "date": row["date"],
            "tactics": json.loads(row["tactics"]) if row["tactics"] else [],
            "techniques": json.loads(row["techniques"]) if row["techniques"] else []
        })

    return render(request, "mitreresult.html", {
        "filehash": filehash,
        "entries": parsed
    })


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
    else:
        print("No record found.") 

    conn.close()
    return render(request, "result.html", {"report": result})

def mitre_report_view(request, sha256=None):
    conn = sqlite3.connect('db.sqlite3')
    conn.row_factory = sqlite3.Row  # This allows fetching rows as dictionaries
    
    
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM mitre WHERE file_hash=?;", (sha256,))
    
    row = cursor.fetchall()

    if row:
        result = dict(row)  # Convert sqlite3.Row to dict
    else:
        print("No record found.") 

    conn.close()
    return render(request, "mitre_result.html", {"mitre_report": result})