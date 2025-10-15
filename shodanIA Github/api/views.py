from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework_simplejwt.views import TokenObtainPairView
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from .services import ShodanClient
import shodan as shodan_lib
from django.conf import settings
import re, requests
from openai import OpenAI
import json
import io
import csv

def _s(v):
    return "" if v is None else str(v).strip()

def _rows_to_csv(rows):
    out = ["IP,Port,Org,Product,Title"]
    for r in rows:
        ip = _s(r.get("ip") or r.get("ip_str"))
        port = _s(r.get("port"))
        org = _s(r.get("org") or r.get("isp"))
        product = _s(r.get("product") or r.get("module"))
        title = _s(r.get("title") or r.get("hostname"))
       
        def esc(x): 
            return f"\"{x.replace('\"','\"\"')}\"" if "," in x or "\"" in x else x
        out.append(",".join(map(esc, [ip, port, org, product, title])))
    return "\n".join(out)

def get_shodan():
    key = getattr(settings, "SHODAN_API_KEY", "")
    if not key:
        raise RuntimeError("Falta SHODAN_API_KEY en .env")
    return shodan_lib.Shodan(key)

class HealthView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        return Response({"status": "ok"})

class LoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]
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

class ShodanSearchView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        import re
        q = request.query_params.get("q")
        if not q:
            return Response({"detail": "Parámetro 'q' es requerido."}, status=400)
        q = q.strip()
        re_ipv4 = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
        re_host = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')

        try:
            api = get_shodan()

            # Si parece IP/host → usa host() y envuelve resultado en forma similar a search
            if re_ipv4.match(q) or re_host.match(q):
                host = api.host(q)
                wrapped = {
                    "total": len(host.get("ports", [])),
                    "matches": [
                        {
                            "ip_str": host.get("ip_str"),
                            "port": p,
                            "org": host.get("org") or host.get("isp"),
                            "product": "",
                            "http": {"title": (host.get("hostnames") or [""])[0] if host.get("hostnames") else ""},
                            "_shodan": {"module": ""},
                        } for p in host.get("ports", [])
                    ]
                }
                return Response(wrapped)

            # Caso contrario → intenta search (tu plan puede bloquearlo)
            page = int(request.query_params.get("page", 1))
            facets = request.query_params.get("facets")
            data = api.search(q, page=page, facets=facets)
            return Response(data)

        except shodan_lib.APIError as e:
            msg = str(e)
            if "Invalid API key" in msg or "No API key provided" in msg:
                return Response({"error": msg}, status=401)
            if "Access denied" in msg:
                return Response({"error": msg}, status=403)
            if "Insufficient credits" in msg or "Not enough query credits" in msg:
                return Response({"error": msg}, status=402)
            return Response({"error": msg}, status=502)

class ShodanHostView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, ip):
        try:
            data = ShodanClient().host(ip)
            return Response(data)
        except shodan_lib.APIError as e:
            msg = str(e)
            # Mapea códigos útiles según el mensaje
            if "Invalid API key" in msg or "No API key provided" in msg:
                return Response({"error": msg}, status=401)
            if "Access denied" in msg:
                return Response({"error": msg}, status=403)
            if "Insufficient credits" in msg or "Not enough query credits" in msg:
                return Response({"error": msg}, status=402)  # o 429 si prefieres rate/credits
            if "scan" in msg.lower() and "not available" in msg.lower():
                return Response({"error": msg}, status=403)
            # Por defecto: 502 Bad Gateway para errores aguas arriba
            return Response({"error": msg}, status=502)

class ShodanScanView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        targets = request.data.get("targets", [])
        if not isinstance(targets, list) or not targets:
            return Response({"detail": "Envía 'targets': []"}, status=400)
        try:
            data = ShodanClient().scan(targets)
            return Response(data)
        except shodan_lib.APIError as e:
            msg = str(e)
            # Mapea códigos útiles según el mensaje
            if "Invalid API key" in msg or "No API key provided" in msg:
                return Response({"error": msg}, status=401)
            if "Access denied" in msg:
                return Response({"error": msg}, status=403)
            if "Insufficient credits" in msg or "Not enough query credits" in msg:
                return Response({"error": msg}, status=402)  # o 429 si prefieres rate/credits
            if "scan" in msg.lower() and "not available" in msg.lower():
                return Response({"error": msg}, status=403)
            # Por defecto: 502 Bad Gateway para errores aguas arriba
            return Response({"error": msg}, status=502)

class ShodanAccountView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        try:
            client = ShodanClient()
            info = client.api.info()  # plan, query_credits, etc.
            return Response(info)
        except shodan_lib.APIError as e:
            return Response({"error": str(e)}, status=403)
        
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

class InternetDBHostView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, ip):
        if not _IPV4.match(ip):
            return Response({"error": "IP inválida"}, status=400)
        try:
            r = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=8,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 404:
                return Response({"error": "IP no encontrada en InternetDB"}, status=404)
            if not r.ok:
                return Response({"error": f"InternetDB {r.status_code}"}, status=502)
            data = r.json()
        
            return Response(data)
        except requests.Timeout:
            return Response({"error": "Timeout consultando InternetDB"}, status=504)
        except Exception as e:
            return Response({"error": str(e)}, status=502)
        
@method_decorator(never_cache, name="dispatch")
class AIReportView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # 0) API key
        if not getattr(settings, "OPENAI_API_KEY", None):
            return Response({"error": "Falta OPENAI_API_KEY en .env"}, status=500)

        payload = request.data or {}
        source = _s(payload.get("source") or "desconocido")
        data = payload.get("data") or {}

        # 1) Validar/normalizar filas
        rows = []
        if source == "table_ports":
            rows = data.get("rows") or []
            if not isinstance(rows, list):
                return Response({"error": "data.rows debe ser una lista"}, status=400)
            if not rows:
                return Response({"error": "No hay filas en data.rows"}, status=400)
            # por seguridad, limita a N filas
            rows = rows[:200]

        # 2) (opcional) versión recortada del JSON original para debugging
        try:
            raw_json = json.dumps(data, ensure_ascii=False)
        except Exception:
            raw_json = str(data)
        raw_json = raw_json[:16000]

        # 3) Cliente OpenAI
        client = OpenAI(api_key=settings.OPENAI_API_KEY)

        system_msg = (
            "Eres un analista de seguridad. NUNCA inventes datos. "
            "Tu análisis debe basarse exclusivamente en la tabla proporcionada."
        )

        if source == "table_ports":
            csv_table = _rows_to_csv(rows)
            summary = _s(data.get("summary"))

            # ¡Incluimos el CSV real en el mensaje!
            user_msg = (
                "Genera un INFORME TÉCNICO de vulnerabilidades usando EXCLUSIVAMENTE "
                "la siguiente tabla (CSV). Requisitos:\n"
                "- Primero, imprime una tabla Markdown **idéntica** a la CSV (mismas filas/columnas/orden/valores).\n"
                "- Luego: resumen ejecutivo (2–4 líneas), hallazgos por IP:PUERTO con severidad (Alto/Medio/Bajo), "
                "evidencia breve (usa product/title si aplica), recomendaciones concretas y próximos pasos.\n"
                "- No agregues filas, no inventes IPs/puertos. Si hay valores vacíos, respétalos.\n\n"
                f"Resumen (opcional): {summary}\n\n"
                "TABLA (CSV):\n"
                f"{csv_table}"
            )
        else:
            user_msg = (
                "Genera un informe técnico de vulnerabilidades. No inventes datos.\n"
                "Entrada (JSON recortado):\n"
                f"{raw_json}"
            )

        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
                top_p=1.0,
            )
            report = resp.choices[0].message.content
            return Response({"report": report}, status=200, headers={"Cache-Control": "no-store"})
        except Exception as e:
            return Response({"error": str(e)}, status=502)