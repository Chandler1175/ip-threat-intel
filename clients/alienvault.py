import os
import requests
from dotenv import load_dotenv


class AlienVaultClient:
    def __init__(self):
        load_dotenv(override=True)
        self.api_key = os.getenv("AlienVault_Key")
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/IPv4"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def get_raw(self, ip):
        url = f"{self.base_url}/{ip}"
        response = requests.get(url, headers=self.headers)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}

    def get_report(self, ip):
        data = self.get_raw(ip)

        malware_families = data.get('pulse_info', {}) \
            .get('related', {}) \
            .get('alienvault', {}) \
            .get('malware_families', [])

        return {
            "source": "AlienVault",
            "indicator": data.get("indicator"),
            "malware_families": malware_families,
            "pulse_count": data.get("pulse_info", {}).get("count"),
            "country": data.get("country_name")
        }
