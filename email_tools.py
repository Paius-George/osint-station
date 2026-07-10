"""Lightweight email OSINT: format, mail servers, SPF/DMARC, Gravatar, links.

All free and keyless. Breach checking is offered as an external link rather
than an API call (HaveIBeenPwned's search now requires a paid key).
"""
import hashlib
import re
import requests
import dns.resolver
from urllib.parse import quote_plus

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted(str(r.exchange).rstrip('.') for r in answers)
    except Exception:
        return []


def _txt_has(name, needle):
    try:
        answers = dns.resolver.resolve(name, 'TXT')
        return any(needle in r.to_text().lower() for r in answers)
    except Exception:
        return False


def check_email(email):
    email = (email or '').strip()
    if not _EMAIL_RE.match(email):
        return {'email': email, 'valid': False,
                'error': 'Enter a valid email address (name@domain.tld).'}

    domain = email.rsplit('@', 1)[1].lower()
    mx = _mx(domain)
    spf = _txt_has(domain, 'v=spf1')
    dmarc = _txt_has('_dmarc.' + domain, 'v=dmarc1')

    digest = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    gravatar_exists = False
    try:
        r = requests.get(f'https://www.gravatar.com/avatar/{digest}?d=404', timeout=8)
        gravatar_exists = r.status_code == 200
    except requests.exceptions.RequestException:
        pass

    links = {
        'HaveIBeenPwned': f'https://haveibeenpwned.com/account/{quote_plus(email)}',
        'Google': 'https://www.google.com/search?q=' + quote_plus(f'"{email}"'),
        'Gravatar profile': f'https://en.gravatar.com/{digest}',
    }

    return {
        'email': email,
        'valid': True,
        'domain': domain,
        'has_mx': bool(mx),
        'mx': mx,
        'spf': spf,
        'dmarc': dmarc,
        'gravatar_exists': gravatar_exists,
        'gravatar_img': f'https://www.gravatar.com/avatar/{digest}?s=160&d=404' if gravatar_exists else None,
        'links': links,
    }
