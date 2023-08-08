import json
from src.controller.virustotal import fetch_virustotal_data
from src.controller.alienvault import fetch_alien_vault_data
from src.database.models import HASH
import logging

logging.basicConfig(level=logging.INFO)


async def parse_virustotal_data(data: json) -> tuple:


    last_analysis_stats = data["data"]["attributes"].get("last_analysis_stats", {})
    is_malicious = last_analysis_stats.get("malicious", 0) > 0
    file_type = data["data"]["attributes"]["type_description"]
    tlsh = data["data"]["attributes"]["tlsh"]
    vhash = data["data"]["attributes"]["vhash"]
    suggested_threat_label = (
        data["data"]["attributes"]
        .get("popular_threat_classification", {})
        .get("suggested_threat_label", None)
    )
    file_size = data["data"]["attributes"]["size"]  # bytes
    magic = data["data"]["attributes"]["magic"]
    trid = data["data"]["attributes"]["trid"]
    names = data["data"]["attributes"]["names"]

    return (
        is_malicious,
        file_type,
        tlsh,
        vhash,
        suggested_threat_label,
        file_size,
        magic,
        trid,
        names,
    )


async def parse_alien_vault_data(data: json) -> tuple:


    hash_type = data["type_title"]
    # related tags
    tags = set()
    pulse_info = data.get("pulse_info", {})
    if "pulses" in pulse_info:
        for pulse in pulse_info["pulses"]:
            pulse_tags = pulse.get("tags", [])
            tags.update(tag.lower() for tag in pulse_tags)
    tags_str = ", ".join(tags)

    # pulse info
    pulses = data["pulse_info"]["pulses"] if "pulse_info" in data else []
    pulse_details = []
    for pulse in pulses:
        pulse_name = pulse.get("name", None)
        pulse_description = pulse.get("description", None)
        pulse_tags = pulse.get("tags", [])
        pulse_details.append(
            {"Name": pulse_name, "Description": pulse_description, "Tags": pulse_tags}
        )

    return tags_str, pulse_details, hash_type


async def create_hash_ioc(hash_value: str) -> HASH:

    virustotal_json_data = await fetch_virustotal_data(hash_value)
    (
        is_malicious,
        file_type,
        tlsh,
        vhash,
        suggested_threat_label,
        file_size,
        magic,
        trid,
        names,
    ) = await parse_virustotal_data(virustotal_json_data)
    alienvault_data = await fetch_alien_vault_data(hash_value)
    tags_str, pulse_details, hash_type = await parse_alien_vault_data(alienvault_data)

    file_name_str = str(names)
    tr_ID_str = str(trid)
    pulse_info_str = str(pulse_details)

    hash_ioc = HASH(
        ioc=hash_value,
        ioc_type="HASH",
        malicious=is_malicious,
        related_tags=tags_str,
        hash_algorithm=hash_type,
        file_name=file_name_str,
        file_size=file_size,
        file_type=file_type,
        threat_label=suggested_threat_label,
        magic=magic,
        tr_ID=tr_ID_str,
        tlsh=tlsh,
        vhash=vhash,
        pulse_info=pulse_info_str,
    )
    return hash_ioc
