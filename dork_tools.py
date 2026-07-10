"""Build Google-dork style search queries from a keyword or domain.

No network calls: this only assembles advanced-operator queries and the
matching search-engine URLs. The analyst clicks through to run them.
"""
from urllib.parse import quote_plus
import re


def _is_domain(term):
    t = re.sub(r'^https?://', '', term.strip().lower()).split('/')[0]
    return ' ' not in term.strip() and bool(re.match(r'^[a-z0-9-]+(\.[a-z0-9-]+)+$', t))


def _domain_of(term):
    t = re.sub(r'^https?://', '', term.strip().lower()).split('/')[0]
    if t.startswith('www.'):
        t = t[4:]
    return t


def _search_urls(query):
    q = quote_plus(query)
    return {
        'google': f'https://www.google.com/search?q={q}',
        'ddg': f'https://duckduckgo.com/?q={q}',
        'bing': f'https://www.bing.com/search?q={q}',
    }


def _dork(label, query):
    return {'label': label, 'query': query, 'urls': _search_urls(query)}


def generate_dorks(term):
    term = (term or '').strip()
    if not term:
        return {'term': '', 'is_domain': False, 'domain': None, 'total': 0, 'categories': []}

    is_domain = _is_domain(term)
    domain = _domain_of(term) if is_domain else None
    categories = []

    if is_domain:
        base = f'site:{domain}'
        categories.append({'name': 'Files & documents', 'dorks': [
            _dork('PDF documents', f'{base} filetype:pdf'),
            _dork('Office documents', f'{base} (filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt OR filetype:pptx)'),
            _dork('Text & CSV', f'{base} (filetype:txt OR filetype:csv)'),
            _dork('Backups & databases', f'{base} (filetype:bak OR filetype:old OR filetype:zip OR filetype:tar OR filetype:sql)'),
            _dork('Log files', f'{base} filetype:log'),
            _dork('Config & env files', f'{base} (filetype:env OR filetype:conf OR filetype:ini OR filetype:yml)'),
        ]})
        categories.append({'name': 'Exposed files & directories', 'dorks': [
            _dork('Open directory listings', f'{base} intitle:"index of"'),
            _dork('Index of + backups', f'{base} intitle:"index of" (backup OR bak OR old)'),
            _dork('Exposed .git folder', f'{base} inurl:.git'),
            _dork('Environment files', f'{base} inurl:.env'),
        ]})
        categories.append({'name': 'Login & admin surfaces', 'dorks': [
            _dork('Login pages', f'{base} (inurl:login OR inurl:signin)'),
            _dork('Admin panels', f'{base} (inurl:admin OR intitle:admin)'),
            _dork('Dashboards & portals', f'{base} (inurl:dashboard OR inurl:portal)'),
        ]})
        categories.append({'name': 'Possible secrets', 'dorks': [
            _dork('Password mentions', f'{base} intext:password'),
            _dork('API keys / tokens', f'{base} (intext:"api_key" OR intext:"apikey" OR intext:"secret")'),
            _dork('Credentials & config', f'{base} (inurl:credentials OR inurl:config)'),
        ]})
        categories.append({'name': 'Subdomains & related', 'dorks': [
            _dork('Subdomains', f'site:*.{domain} -www'),
            _dork('Off-site mentions', f'"{domain}" -site:{domain}'),
        ]})
        categories.append({'name': 'Third-party footprint', 'dorks': [
            _dork('GitHub / GitLab', f'(site:github.com OR site:gitlab.com) "{domain}"'),
            _dork('Paste sites', f'(site:pastebin.com OR site:ghostbin.com) "{domain}"'),
            _dork('LinkedIn', f'site:linkedin.com "{domain}"'),
        ]})
    else:
        s = f'"{term}"' if ' ' in term else term
        first = term.split()[0]
        categories.append({'name': 'Files & documents', 'dorks': [
            _dork('PDF documents', f'{s} filetype:pdf'),
            _dork('Office documents', f'{s} (filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx OR filetype:ppt)'),
            _dork('Text & CSV', f'{s} (filetype:txt OR filetype:csv)'),
            _dork('Databases & backups', f'{s} (filetype:sql OR filetype:bak OR filetype:zip)'),
        ]})
        categories.append({'name': 'Where the term appears', 'dorks': [
            _dork('In page titles', f'intitle:{s}'),
            _dork('In URLs', f'inurl:{first}'),
            _dork('In page text', f'intext:{s}'),
        ]})
        categories.append({'name': 'Exposed & login', 'dorks': [
            _dork('Open directory listings', f'intitle:"index of" {s}'),
            _dork('Login & admin pages', f'{s} (inurl:login OR inurl:admin)'),
        ]})
        categories.append({'name': 'Social & code', 'dorks': [
            _dork('LinkedIn', f'site:linkedin.com {s}'),
            _dork('X / Twitter', f'(site:twitter.com OR site:x.com) {s}'),
            _dork('Reddit', f'site:reddit.com {s}'),
            _dork('GitHub', f'site:github.com {s}'),
            _dork('Paste sites', f'site:pastebin.com {s}'),
        ]})

    total = sum(len(c['dorks']) for c in categories)
    return {'term': term, 'is_domain': is_domain, 'domain': domain, 'total': total, 'categories': categories}
