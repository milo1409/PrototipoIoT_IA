from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.views import TokenObtainPairView
import shodan

class LoginView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        resp = super().post(request, *args, **kwargs)
        if resp.status_code != status.HTTP_200_OK:
            return resp
        data = resp.data
        token = data.get("access")
        email_or_user = request.data.get("username") or request.data.get("email")
        return Response({
            "token": token,
            "refresh": data.get("refresh"),
            "user": {"email": email_or_user}
        }, status=200)

def get_shodan():
    api_key = getattr(settings, "SHODAN_API_KEY", "")
    if not api_key:
        raise RuntimeError("Falta SHODAN_API_KEY en .env")
    return shodan.Shodan(api_key)

class ShodanSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        q = request.query_params.get("q")
        if not q:
            return Response({"detail": "Parámetro 'q' es requerido."}, status=400)
        page = int(request.query_params.get("page", 1))
        facets = request.query_params.get("facets")
        try:
            api = get_shodan()
            data = api.search(q, page=page, facets=facets)
            return Response(data)
        except shodan.APIError as e:
            return Response({"error": str(e)}, status=502)

class ShodanHostView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, ip):
        try:
            api = get_shodan()
            data = api.host(ip)
            return Response(data)
        except shodan.APIError as e:
            return Response({"error": str(e)}, status=502)

class ShodanScanView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        targets = request.data.get("targets", [])
        if not isinstance(targets, list) or not targets:
            return Response({"detail": "Envía 'targets': [ \"1.2.3.4\", \"1.2.3.0/24\" ]"}, status=400)
        try:
            api = get_shodan()
            data = api.scan(",".join(targets))  # Requiere plan con permisos de scan
            return Response(data)
        except shodan.APIError as e:
            return Response({"error": str(e)}, status=402)