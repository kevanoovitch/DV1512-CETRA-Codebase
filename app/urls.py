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
    path('accounts/login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path("report/<str:sha256>/", views.report_view, name="results"),
    path("mitre-attack/", views.mitre_attack, name="mitre_attack"),
    path("mitre-report/<str:sha256>/", views.mitre_report_view, name="mitreresult"),
    #path("report/<str:sha256>/json/", views.report_json, name="report_json"),
    #path("report/<str:sha256>/pdf/", views.report_pdf, name="report_pdf"),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)