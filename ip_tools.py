"""IP intelligence: geolocation, allocation (RDAP), reverse DNS, neighbours,
and reputation via public DNS blocklists. All keyless (ipinfo optional)."""
import concurrent.futures
import ipaddress
import socket

import requests
import dns.resolver

from web_tools import get_ip_info, get_rdap_ip, _get_with_retries

_DNSBL = [
    ('Spamhaus ZEN', 'zen.spamhaus.org'),
    ('SpamCop', 'bl.spamcop.net'),
    ('Barracuda', 'b.barracudacentral.org'),
    ('SORBS', 'dnsbl.sorbs.net'),
]


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _reverse_ip_domains(ip, limit=150):
    try:
        resp = _get_with_retries(
            f'https://api.hackertarget.com/reverseiplookup/?q={ip}',
            timeout=12, attempts=2)
        text = resp.text.strip()
        if (not text or 'error' in text.lower()
                or 'API count exceeded' in text or 'No DNS' in text):
            return []
        domains = sorted({line.strip().lower() for line in text.splitlines() if line.strip()})
        return domains[:limit]
    except requests.exceptions.RequestException:
        return []


def _dnsbl_check(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        return [{'name': n, 'listed': None} for n, _ in _DNSBL]

    reversed_ip = '.'.join(reversed(ip.split('.')))
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    results = []
    for name, zone in _DNSBL:
        query = f'{reversed_ip}.{zone}'
        try:
            resolver.resolve(query, 'A')
            results.append({'name': name, 'listed': True})
        except dns.resolver.NXDOMAIN:
            results.append({'name': name, 'listed': False})
        except Exception:
            results.append({'name': name, 'listed': None})
    return results


def analyze_ip(ip):
    ip = (ip or '').strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {'ip': ip, 'valid': False,
                'error': 'Enter a valid IPv4 or IPv6 address.'}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            'geo': ex.submit(get_ip_info, ip),
            'rdap': ex.submit(get_rdap_ip, ip),
            'ptr': ex.submit(_reverse_dns, ip),
            'reverse_domains': ex.submit(_reverse_ip_domains, ip),
            'dnsbl': ex.submit(_dnsbl_check, ip),
        }
        out = {k: f.result() for k, f in futures.items()}

    listed = [b['name'] for b in out['dnsbl'] if b.get('listed')]
    return {
        'ip': ip,
        'valid': True,
        'geo': out['geo'] if isinstance(out['geo'], dict) else {},
        'rdap': out['rdap'],
        'ptr': out['ptr'],
        'reverse_domains': out['reverse_domains'],
        'dnsbl': out['dnsbl'],
        'listed_count': len(listed),
    }
