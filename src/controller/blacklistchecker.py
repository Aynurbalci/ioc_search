import httpx
from dynaconf import Dynaconf
from typing import Optional

settings = Dynaconf(settings_file="privacy.toml")

API_KEY = settings.api_keys.blacklist_checker

BLACK_URL = settings.api_urls.BLACK_URL


async def run_blacklist_check(query: str) -> Optional[bool]:

    url = f"{BLACK_URL}{query}"
    async with httpx.AsyncClient(auth=(API_KEY, "")) as client:
        response = await client.get(url)

    if response.status_code != 200:
        return None
    data = response.json()
    detections = data["detections"]

    return True if detections > 0 else False

