from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth import logout
from django.core.files.base import ContentFile
from app.backend.api import apiCaller
from app.backend.mitreFolder.mitre import mitreCall
from app.backend.utils.Checkfileidindb import delete_report_by_hash, delete_report_by_id, check_existing_report
from app.backend.api import compute_file_hash

import sqlite3
import json
import zipfile
import math

    
@login_required
def home(request):
    error = None
    status_message = None

    # Load top 5 reports
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
        return [{
            "file_hash": row["file_hash"],
            "extention_id": row["extention_id"],
            "date": row["date"],
            "score": row["score"],
        } for row in rows]

    if request.method == "POST":
        submit_type = request.POST.get("submit_type")
        force = request.POST.get("force") == "true"

        ext_id = request.POST.get("extention_id") or ""
        file_path = request.POST.get("file_path") or ""

        fs = FileSystemStorage()

        if force:
            if file_path:
                try:
                    filehash = compute_file_hash(file_path)
                except:
                    return render(request, "home.html", {
                        "error": "Could not open stored file for re-analysis.",
                        "top_reports": load_top_reports(),
                    })

                delete_report_by_hash(filehash)
                apiCaller(file_path, "file")

                return render(request, "home.html", {
                    "status_message": "A new analysis has been created.",
                    "top_reports": load_top_reports(),
                })

            if ext_id:
                delete_report_by_id(ext_id)
                apiCaller(ext_id, "id")

                return render(request, "home.html", {
                    "status_message": "A new analysis has been created.",
                    "top_reports": load_top_reports(),
                })

            # Nothing to force
            return render(request, "home.html", {
                "error": "Could not determine original submission type.",
                "top_reports": load_top_reports()
            })

        if submit_type in ["zip", "crx"]:
            upload = request.FILES.get("submission_file")

            if not upload:
                return render(request, "home.html", {
                    "error": f"Please select a valid .{submit_type} file.",
                    "top_reports": load_top_reports(),
                })

            filename = fs.save(upload.name, upload)
            file_path = fs.path(filename)

            if not check_zip(file_path):
                return render(request, "home.html", {
                    "error": "manifest.json not found inside archive.",
                    "top_reports": load_top_reports(),
                })

            # DB lookup based on hash
            result = check_existing_report(file_path=file_path)
            if result["exists"]:
                return render(request, "home.html", {
                    "existing_report": True,
                    "hash": result["hash"],
                    "extention_id": result["extention_id"],
                    "file_path": file_path,
                    "report_date": result["date"],
                    "top_reports": load_top_reports(),
                })

            # New analysis
            apiCaller(file_path, "file")
            return render(request, "home.html", {
                "status_message": "Analysis complete.",
                "top_reports": load_top_reports()
            })

        if submit_type == "id":
            ext_id = request.POST.get("submission_value").strip()

            result = check_existing_report(ext_id=ext_id)
            if result["exists"]:
                return render(request, "home.html", {
                    "existing_report": True,
                    "hash": result["hash"],
                    "extention_id": ext_id,
                    "file_path": "",     # IDs have no file
                    "report_date": result["date"],
                    "top_reports": load_top_reports(),
                })

            apiCaller(ext_id, "id")
            return render(request, "home.html", {
                "status_message": "Analysis complete.",
                "top_reports": load_top_reports()
            })

        # Invalid
        return render(request, "home.html", {
            "error": "Invalid submission type.",
            "top_reports": load_top_reports()
        })

    return render(request, "home.html", {
        "top_reports": load_top_reports(),
    })

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