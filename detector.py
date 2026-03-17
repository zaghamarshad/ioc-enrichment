import re

IPV4_REGEX   = r"^(\d{1,3}\.){3}\d{1,3}$"
MD5_REGEX    = r"^[a-fA-F0-9]{32}$"
SHA1_REGEX   = r"^[a-fA-F0-9]{40}$"
SHA256_REGEX = r"^[a-fA-F0-9]{64}$"

def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()

    if re.match(IPV4_REGEX, ioc):
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"

    if re.match(SHA256_REGEX, ioc): return "hash"
    if re.match(SHA1_REGEX, ioc):   return "hash"
    if re.match(MD5_REGEX, ioc):    return "hash"

    return "unknown"