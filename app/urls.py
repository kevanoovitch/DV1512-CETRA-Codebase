from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='home'),
    path('report/', views.report, name='report'),
    path('history/', views.history, name='history'),
]