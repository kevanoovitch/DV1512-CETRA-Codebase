from django.urls import path
from . import views

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('report/', views.report, name='report'),
    path('history/', views.history, name='history'),
    path('settings/', views.settings, name='settings'),
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path("report/<str:filehash>/", views.report_view, name="results"),
    path("mitre-attack/", views.mitre_attack, name="mitre_attack"),
    path("mitre/analyze/<str:filehash>/", views.mitre_analyze, name="mitre_analyze"),
    path("mitre-attack/<str:filehash>/", views.mitre_view, name="mitre_view"),
    path("report/json/<str:filehash>/", views.download_json, name="download_json"),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)