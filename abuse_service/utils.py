from .models import Abuses
from typing import Dict, List


def get_domains() -> List[Dict[str, str]]:

    abuses = Abuses.objects.all().values('ref', 'domains')
    return_data = []
    for row in abuses:
        domains = row['domains'].split(',')
        for domain in domains:
            return_data.append({
                'ref': row['ref'],
                'domain': domain
            })
    return return_data


def get_abuses(status: str, ip: str, domain: str) -> List[Dict[str, str]]:
    abuses = Abuses.objects.all().filter(status=status)
    if ip:
        abuses.filter(ip=ip)
    if domain:
        abuses.filter(domain=domain)
    return_data = []
    for row in abuses:
        domains = row.domains.split(',')
        return_data.append({
            "ref": row.ref,
            "status": row.status,
            "created": row.created,
            "domains": domains,
            "ip": row.ip
        })
    return return_data


