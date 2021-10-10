import requests
import cloudscraper
import validators
import dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime

from .models import Abuses

SBL_LISTING_URL = "https://www.spamhaus.org/sbl/listings/{}"
SBL_QUERY_URL = "https://www.spamhaus.org{}"

SBL_CODES = [
    # by IP https://www.spamhaus.org/faq/section/DNSBL%2520Usage#202
    '127.0.0.2',  # SBL Данные Spamhaus SBL
    '127.0.0.3',  # SBL Данные Spamhaus SBL CSS
    '127.0.0.4',  # XBL Данные CBL
    '127.0.0.9',  # SBL Данные Spamhaus DROP / EDROP (в дополнение к 127.0.0.2, с 1 июня 2016 г.)
    '127.0.0.10', # PBL	ISP поддерживается
    '127.0.0.11', # PBL Spamhaus поддерживается
    # by domain https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
]


def _reverse_address(ip):
    arr = ip.split('.')

    if len(arr) != 4:
        raise Exception("Wrong IPv4 address")

    arr.reverse()
    return '.'.join(arr)


def _parse_domains(link):
    domains = []
    scraper = cloudscraper.create_scraper()
    req = scraper.get(link)

    parsed = BeautifulSoup(req.text, "html.parser")

    for incident in parsed.find_all("table", border="0", cellspacing="20", cellpadding="0"):
        p = incident.findAll("p")

        if len(p) <= 0:
            continue

        text = p[0].find('span').text

        # magic? :|
        text = text.replace('\n', ' ')
        text = text.replace('\t', ' ')
        text = text.replace('/', ' ')

        array = text.split(' ')

        ignore = {'.php', '.html', '.exe', '.js'}

        for word in array:
            word = word.lower().strip()

            if validators.domain(word):
                if word not in domains:
                    add = True

                    for ext in ignore:
                        if ext in word:
                            add = False

                    if add:
                        domains.append(word)

    return domains


def check_listings(domain):
    assert domain

    listings = []

    uri = SBL_LISTING_URL.format(domain)
    request = requests.get(uri)
    parsed = BeautifulSoup(request.text, "html.parser")

    for incident in parsed.find_all("table", border="0", cellpadding="4", cellspacing="0", width="100%"):
        spans = incident.findAll("span")
        abuse_link = SBL_QUERY_URL.format(spans[0].find('a').get('href'))

        ref = spans[0].b.text
        ip = spans[1].b.text
        created = int(datetime.strptime(spans[3].text, "%d-%b-%Y %H:%M %Z").timestamp())
        desc = ' '.join(s.strip() for s in spans[4].text.strip().splitlines())
        domains = _parse_domains(abuse_link)

        listings.append({
            'ref': ref,
            'link': abuse_link,
            'ip_address': ip,
            'timestamp': created,
            'description': desc,
            'domains': domains
        })

        abuse = Abuses.objects.filter(ref=ref).first()
        if abuse:
            abuse.status = 'active'
            abuse.created = created
            abuse.domains = ','.join(domains)
            abuse.ip = ip
            abuse.description = desc
            abuse.save()
        else:
            abuse = Abuses(
                ref=ref,
                status='active',
                created=created,
                domains=','.join(domains),
                ip=ip,
                description=desc,
            )
            abuse.save()

    return listings


def check_addr_in_lists(ip):
    assert ip

    try:
        domain = '{}.zen.spamhaus.org'.format(_reverse_address(ip))
        for rdata in dns.resolver.query(domain, 'A'):
            if str(rdata) in SBL_CODES:
                print("IP {} found in spamhaus [{}]!".format(ip, str(rdata)))
    except dns.resolver.NXDOMAIN:
        print("IP {} not found in spamhaus!".format(ip))

