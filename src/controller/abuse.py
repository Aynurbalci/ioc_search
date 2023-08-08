import httpx
import json
from typing import Optional

from dynaconf import Dynaconf

settings = Dynaconf(settings_file="privacy.toml")


async def fetch_abuseipdb_data(ip: str) -> Optional[bool]:



    params = {"ipAddress": ip, "maxAgeInDays": "200"}

    headers = {"Accept": "application/json", "Key": settings.api_keys.abuseipdb}

    async with httpx.AsyncClient() as client:
        response = await client.get(settings.api_urls.abuse_url, params=params, headers=headers)
        response_data = response.json()

        return json.dumps(response_data, sort_keys=True, indent=4)