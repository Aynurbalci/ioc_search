import re


async def detect_ioc_type(input_str: str) -> str:


    # IP adresi regex
    ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"  # 255.255.255.255 max fix

    # URL regex
    url_regex = r"^(http|https):\/\/[^\s]+$"

    # Domain regex
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    # File hash regex
    file_hash_regex = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"

    if re.match(ip_regex, input_str):
        return "ip"
    elif re.match(url_regex, input_str):
        return "url"
    elif re.match(domain_regex, input_str):
        return "domain"
    elif re.match(file_hash_regex, input_str):
        return "file_hash"

    return "unknown"