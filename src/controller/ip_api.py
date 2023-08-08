import httpx
import logging
from dynaconf import Dynaconf

logging.basicConfig(level=logging.INFO)

settings = Dynaconf(settings_file="privacy.toml")

async def fetch_ip_api_data(query: str) -> dict:


    IP_URL =settings.api_urls.IP_URL
    url = IP_URL + query

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
            return data
        except httpx.RequestError as e:
            logging.error("API isteği başarısız: %s", e)
            return None
