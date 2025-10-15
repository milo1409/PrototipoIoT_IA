import shodan
from django.conf import settings

class ShodanClient:
    def __init__(self):
        api_key = getattr(settings, "SHODAN_API_KEY", "")
        if not api_key:
            raise RuntimeError("Falta SHODAN_API_KEY en .env")
        self.api = shodan.Shodan(api_key)

    def search(self, query, page=1, facets=None):
        return self.api.search(query, page=page, facets=facets)

    def host(self, ip):
        return self.api.host(ip)

    def scan(self, targets):
        return self.api.scan(",".join(targets))
