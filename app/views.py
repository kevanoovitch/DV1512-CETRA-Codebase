from django.shortcuts import render
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage

def home(request):
    uploaded_file_url = None
    
    
    if request.method == "POST" and request.FILES.get("myZip"):
        myzip = request.FILES["myZip"]
        
        fs = FileSystemStorage()
        filename = fs.save(myzip.name, myzip)
        uploaded_file_url = fs.url(filename)
        return render(request, "home.html") #, {"uploaded_file_url": uploaded_file_url})
    
    return render(request, 'home.html')

def report(request):
    return HttpResponse("This is the Report page")

def history(request):
    return HttpResponse("This is the History page")