import httpx
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="privacy.toml")
key = settings.api_keys.greynoise


async def fetch_greynoise_data(ip: str) -> str:


    url = f"{settings.api_urls.GREY_URL}/{ip}"
    headers = {
        "accept": "application/json",
        "key": key
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)

        return response.text