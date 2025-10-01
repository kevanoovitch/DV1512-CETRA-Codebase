from django.shortcuts import render
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage

def home(request):
    uploaded_file_url = None
    
    if request.method == "POST" and request.FILES.get("myUploadedFile"):
        myuploadedfile = request.FILES["myUploadedFile"]
        
        fs = FileSystemStorage()
        filename = fs.save(myuploadedfile.name, myuploadedfile)
        uploaded_file_url = fs.url(filename)
        return render(request, "home.html")
    
    return render(request, 'home.html')

def report(request):
    return HttpResponse("This is the Report page")

def history(request):
    return render(request, "history.html")

def results(request):
    return render(request, "results.html")

def settings(request):
    return render(request, "settings.html")

def login(request):
    return render(request, "login.html")