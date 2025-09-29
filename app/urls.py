from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('report/', views.report, name='report'),
    path('history/', views.history, name='history'),
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout')
]