from django.shortcuts import render
from django.http import HttpResponse

def index(request):
    return render(request, 'index.html')

def report(request):
    return HttpResponse("This is the Report page")

def history(request):
    return HttpResponse("This is the History page")
