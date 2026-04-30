import os
import requests
from dotenv import load_dotenv


class AbuseIPDBClient:
    def __init__(self):
        load_dotenv(override=True)
        self.api_key = os.getenv("AbuseIPDB_Key")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.headers = {
            "accept": "application/json",
            "Key": self.api_key
        }

    def get_raw(self, ip):
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }

        response = requests.get(self.base_url, headers=self.headers, params=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}

    def get_report(self, ip):
        data = self.get_raw(ip).get("data", {})

        return {
            "source": "AbuseIPDB",
            "ip": data.get("ipAddress"),
            "abuse_score": data.get("abuseConfidenceScore"),
            "reports": data.get("totalReports"),
            "country": data.get("countryName"),
            "isp": data.get("isp"),
            "domain": data.get("domain")
        }
