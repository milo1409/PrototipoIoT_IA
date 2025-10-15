from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import HealthView, LoginView, ShodanSearchView, ShodanHostView, ShodanScanView, ShodanAccountView, InternetDBHostView, AIReportView

urlpatterns = [
    path("health", HealthView.as_view(), name="health"),
    path("auth/login", LoginView.as_view(), name="login"),
    path("auth/refresh", TokenRefreshView.as_view(), name="token_refresh"),
    path("shodan/search", ShodanSearchView.as_view(), name="shodan_search"),
    path("shodan/host/<str:ip>", ShodanHostView.as_view(), name="shodan_host"),
    path("shodan/scan", ShodanScanView.as_view(), name="shodan_scan"),
    path("shodan/account", ShodanAccountView.as_view(), name="shodan_account"),
    path("internetdb/host/<str:ip>", InternetDBHostView.as_view(), name="internetdb_host"),
    path("ai/report", AIReportView.as_view(), name="ai_report"),
]
