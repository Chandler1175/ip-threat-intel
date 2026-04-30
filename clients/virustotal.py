import os
import requests
from dotenv import load_dotenv


class VirusTotalClient:
    def __init__(self):
        load_dotenv(override=True)
        self.api_key = os.getenv("VT_Key")
        self.base_url = "https://www.virustotal.com/api/v3/ip_addresses"
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
        attributes = self.get_raw(ip).get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "reputation": attributes.get("reputation"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless")
        }
