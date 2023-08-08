import httpx
import xml.etree.ElementTree as ET
import logging
from dynaconf import Dynaconf

logging.basicConfig(level=logging.INFO)
settings = Dynaconf(settings_file="privacy.toml")

api_key = settings.api_keys.whoisxmlapi


async def fetch_whois_data(domain_name: str) -> dict:


    WHOIS_URL = f"{settings.api_urls.WHOIS_URL}"
    url = f"{WHOIS_URL}?apiKey={api_key}&domainName={domain_name}"

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            xml_str = response.text
            root = ET.fromstring(xml_str)
            values = []
            for element in root.iter():
                if element.text and not element.text.strip().startswith("#"):
                    values.append(element.text.strip())
            return " ".join(values)
        except httpx.RequestError as e:
            logging.error("API istegi basarisisz oldu: %s", e)
            return None