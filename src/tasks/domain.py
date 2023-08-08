import json
from src.controller.virustotal import fetch_virustotal_data
from src.controller.whois import fetch_whois_data
from src.controller.ip_api import fetch_ip_api_data
from src.controller.blacklistchecker import run_blacklist_check
from src.controller.alienvault import fetch_alien_vault_data
from src.controller.dnslookup import fetch_dns_lookup_data
from src.database.models import DOMAIN

import logging

logging.basicConfig(level=logging.INFO)



async def parse_virustotal_data(data: dict) -> bool:

    # Checking if the IP is marked as malicious
    last_analysis_stats = data["attributes"].get("last_analysis_stats", {})
    is_malicious = last_analysis_stats.get("malicious", 0) > 0

    return True if is_malicious else False



async def parse_geolocation_data(data: dict) -> tuple:


    try:
        ip = data.get("query", None)
        country = data.get("country", None)
        city = data.get("city", None)
        lat = data.get("lat", None)
        lon = data.get("lon", None)
        isp = data.get("isp", None)
        return ip, country, city, lat, lon, isp
    except json.JSONDecodeError:
        logging.error("Invalid JSON data")
        return None, None, None, None, None

async def parse_alien_vault_data(data: dict) -> str:


    tags = set()
    pulse_info = data.get("pulse_info", {})
    if "pulses" in pulse_info:
        for pulse in pulse_info["pulses"]:
            pulse_tags = pulse.get("tags", [])
            tags.update(tag.lower() for tag in pulse_tags)
    tags_str = ", ".join(tags)
    return tags_str


async def create_domain_ioc(domain: str) -> DOMAIN:


    virustotal_json_data = await fetch_virustotal_data(domain)
    is_malicious = await parse_virustotal_data(virustotal_json_data["data"])
    blacklist_result = await run_blacklist_check(domain)
    whois_data = await fetch_whois_data(domain)
    alienvault_data = await fetch_alien_vault_data(domain)
    related_tags = await parse_alien_vault_data(alienvault_data)
    geolocation_data = await fetch_ip_api_data(domain)
    ip, country, city, lat, lon, isp = await parse_geolocation_data(geolocation_data)
    country = country if country is not None else ""
    city = city if city is not None else ""
    country_city = country + "-" + city
    geolocation = str(lat) + "," + str(lon)
    dns_record = await fetch_dns_lookup_data(domain)
    dns_record_data = json.dumps(dns_record)

    domain_ioc = DOMAIN(
        ioc=domain,
        ioc_type="Domain",
        ip=ip,
        dns_record=dns_record_data,
        malicious=is_malicious,
        related_tags=related_tags,
        blacklist=blacklist_result,
        country=country_city,
        geometric_location=geolocation,
        isp=isp,
        whois=whois_data,
    )

    return domain_ioc