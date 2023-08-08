import httpx
from dynaconf import Dynaconf
from src.tasks.type_check import detect_ioc_type
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="privacy.toml")
API_KEY = settings.api_keys.alienvault
ALLIEN_IP = settings.api_urls.ALLIEN_IP
ALLIEN_DOMAIN = settings.api_urls.ALLIEN_DOMAIN
ALLIEN_HASH = settings.api_urls.ALLIEN_HASH
ALLIEN_URL = settings.api_urls.ALLIEN_URL


async def fetch_alien_vault_data(indicator: str) -> Optional[bool]:



    indicator_type = await detect_ioc_type(indicator)

    match indicator_type:
        case "ip":
            base_url = ALLIEN_IP
        case "domain":
            base_url = ALLIEN_DOMAIN
        case "file_hash":
            base_url = ALLIEN_HASH
        case "url":
            base_url = ALLIEN_URL
        case _:
            logging.error("İndikatör hatalı: %s", indicator_type)
            return None

    url = base_url + indicator + "/general"
    headers = {"X-OTX-API-KEY": API_KEY}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as e:
            logging.error("API isteği başarısız: %s", e)
            return None