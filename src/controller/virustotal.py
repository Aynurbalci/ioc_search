import httpx
from src.tasks.type_check import detect_ioc_type
import logging
from dynaconf import Dynaconf

settings = Dynaconf(settings_file="privacy.toml")
logging.basicConfig(level=logging.INFO)
apikey = settings.api_keys.virustotal


async def fetch_virustotal_data(indicator: str) -> dict:


    match indicator_type := await detect_ioc_type(indicator):
        case "file_hash":
            url = f"{settings.api_urls.VIRUS_TOTAL_FILES}/{indicator}"
        case "ip":
            url = f"{settings.api_urls.VIRUS_TOTAL_ADRES}/{indicator}"
        case "domain":
            url = f"{settings.api_urls.VIRUS_TOTAL_DOMAIN}/{indicator}"
        case _:
            logging.error("Geçersiz indicator türü: %s", indicator_type)
            return None

    headers = {"accept": "application/json", "x-apikey": apikey}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data
    except httpx.RequestError as e:
        logging.error("API cagrisi sirasinda bir hata oluştu: %s", e)
        return None