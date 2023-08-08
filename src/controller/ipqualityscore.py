import httpx
import urllib.parse
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="privacy.toml")
api_key = settings.api_keys.ipqualityscore


async def fetch_ipqualityscore_data(url: str) -> dict:


    url = f"{settings.api_urls.IP_QUO_URL}/{api_key}/{urllib.parse.quote_plus(url)}"
    additional_params = {"strictness": 3}  # Sabit strictness değeri

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=additional_params)
        response.raise_for_status()
        return response.json()