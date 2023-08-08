import httpx
import logging
from dynaconf import Dynaconf


logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="privacy.toml")

api_key = settings.api_keys.apininjas


async def fetch_dns_lookup_data(domain: str) -> dict:

    api_url = f"{settings.api_urls.DNS_URL}={domain}"
    headers = {"X-Api-Key": api_key}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(api_url, headers=headers)
            response.raise_for_status()
            return response.json()  # <-- Burada response.json() kullanın
        except httpx.HTTPError as e:
            logging.error("Error: %s", e)
            return None