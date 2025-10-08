from django.urls import path
from . import views

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('report/', views.report, name='report'),
    path('history/', views.history, name='history'),
    path('result/', views.results, name='results'),
    path('settings/', views.settings, name='settings'),
    path('mitre_attack/', views.mitre_attack, name='mitre_attack'),
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)