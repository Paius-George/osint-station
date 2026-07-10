import http.cookiejar
import urllib.request
from urllib.parse import urlparse, urljoin
from urllib.request import urlopen
from urllib import parse, robotparser, request, error
import requests
import ipinfo
from dotenv import load_dotenv
import dns.resolver
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import socket
import os
import re
import time


def _get_with_retries(url, timeout, attempts=3, backoff=1.2, headers=None):
    """GET a URL, retrying transient failures (429/5xx and timeouts).

    Many free OSINT sources (crt.sh, archive.org) are frequently overloaded
    and return a fast 502/503 or time out; a couple of retries usually wins.
    """
    last_error = 'request failed'
    for attempt in range(attempts):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code in (429, 500, 502, 503, 504):
                last_error = f'server returned {resp.status_code}'
            else:
                resp.raise_for_status()
                return resp
        except requests.exceptions.Timeout:
            last_error = 'timed out'
        except requests.exceptions.RequestException as e:
            last_error = str(e)
        if attempt < attempts - 1:
            time.sleep(backoff * (attempt + 1))
    raise requests.exceptions.RequestException(last_error)


def is_safe_url(url):
    """Guard against SSRF.

    Resolve the URL's hostname and reject it if any resolved address is
    private, loopback, link-local, reserved, multicast or unspecified.
    Returns a (is_safe, reason) tuple.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return (False, "Invalid URL: no hostname found")
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return (False, "Could not resolve the domain")
    except Exception:
        return (False, "Invalid URL")

    for info in addr_infos:
        ip_str = info[4][0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return (False, "Access to internal or reserved addresses is not allowed")

    return (True, "")

# for screenshot
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import base64


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def findTitle(url, timeout=10):
    try:
        cookiejar = http.cookiejar.CookieJar()

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookiejar))
        urllib.request.install_opener(opener)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        req = urllib.request.Request(url, headers=headers)

        with urllib.request.urlopen(req, timeout=timeout) as response:
            html_content = response.read().decode('utf-8')
            return html_content.split('<title>')[1].split('</title>')[0]
    except (IndexError, urllib.error.HTTPError):
        return ""
    except socket.timeout:
        return ""


def get_favicon(domain):
    return 'https://icon.horse/icon/' + domain


def website_information(website):
    title = findTitle(website)
    parsed_url = urlparse(website)
    domain = parsed_url.netloc
    if domain.startswith("www."):
        domain = domain[4:]

    ip_addresses = [res[4][0] for res in socket.getaddrinfo(domain, 80)]
    # Choosing the first IP address from the list
    ip_address = ip_addresses[0]
    favicon_link = get_favicon(domain)
    return (domain, ip_address, title, favicon_link)


def get_redirects(url, max_redirects=10, timeout=10):
    redirects = []
    for _ in range(max_redirects):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(
                url, allow_redirects=False, timeout=timeout, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return {'Error': f'Failed to fetch URL: {e}'}
        if 300 <= response.status_code < 400:
            redirects.append(url)

            url = response.headers['Location']
        else:
            break

    return {'Redirected From': redirects, 'Final URL': url}


def get_cookies(domain, timeout=5):
    try:
        response = requests.get(domain, timeout=timeout)
        cookies = response.cookies
        cookies_dict = {cookie.name: cookie.value for cookie in cookies}
        return cookies_dict

    except requests.exceptions.Timeout as e:
        return {'Error': f'Timeout error: {e}'}
    except requests.exceptions.RequestException as e:
        return {'Error': f'Failed to fetch URL: {e}'}


def get_headers(domain, timeout=5):
    try:
        response = requests.get(domain, timeout=timeout)
        headers = response.headers
        headers_dict = {header: value for header, value in headers.items()}
        return headers_dict
    except requests.exceptions.Timeout as e:
        return {'Error': f'Timeout error: {e}'}
    except requests.exceptions.RequestException as e:
        return {'Error': f'Failed to fetch URL: {e}'}


load_dotenv()
ipinfo_api_key = os.getenv('IPINFO_API_KEY')


def get_ip_info(ip_address):
    try:
        handler = ipinfo.getHandler(ipinfo_api_key)

        details = handler.getDetails(ip_address)
        return (details.all)
    except ValueError as e:
        return {'Error': f'{e}'}


def get_records(domain):
    results = {}
    # The common, useful record types. Querying every possible type was slow
    # (dozens of sequential lookups that mostly time out).
    record_types = ['A', 'AAAA', 'NS', 'CNAME', 'SOA', 'MX', 'TXT', 'CAA', 'SRV', 'PTR']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            continue

    return results


def get_ssl(hostname, port=443):
    context = ssl.create_default_context()
    with context.wrap_socket(socket.socket(
            socket.AF_INET, socket.SOCK_STREAM), server_hostname=hostname) as conn:
        conn.connect((hostname, port))
        certs = conn.getpeercert(True)

    certificate = x509.load_der_x509_certificate(certs, default_backend())
    subject = next((attr.value for attr in certificate.subject if attr.oid ==
                   x509.NameOID.COMMON_NAME), None)
    issuer = next((attr.value for attr in certificate.issuer if attr.oid ==
                  x509.NameOID.ORGANIZATION_NAME), None)
    # Prefer the timezone-aware properties (cryptography >= 42), fall back to
    # the deprecated naive ones on older versions.
    not_before = getattr(certificate, 'not_valid_before_utc', None) or certificate.not_valid_before
    not_after = getattr(certificate, 'not_valid_after_utc', None) or certificate.not_valid_after
    certificate_info = {
        "subject": subject,
        "issuer": issuer,
        "serial_number": certificate.serial_number,
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat()
    }
    return certificate_info


def get_sitemaps(website, timeout=5):
    robotstxturl = parse.urljoin(website, "robots.txt")
    sitemaps = []
    try:
        socket.setdefaulttimeout(timeout)
        rp = robotparser.RobotFileParser()
        rp.set_url(robotstxturl)
        rp.read()
        sitemaps = rp.site_maps()
    except error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            print(f"Timeout Error: {e}")
        else:
            print(f"URLError: {e}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        socket.setdefaulttimeout(None)

    return sitemaps


def sitemap_parser(sitemap):
    try:
        r = request.urlopen(sitemap)
        xml = r.read().decode('utf8')
        elements = re.findall(r'<loc>(.*?)<\/loc>', xml, re.DOTALL)

        urls = []

        for element in elements:
            try:
                if element.endswith('.xml'):
                    # Recursively call sitemap_parser
                    urls.extend(sitemap_parser(element))
                else:
                    urls.append(element)
            except Exception as e:
                print(f"Error parsing sub-sitemap '{element}': {str(e)}")

        return urls
    except Exception as e:
        print(f"Error accessing sitemap '{sitemap}': {str(e)}")
        return []


def site_maps(url):
    sitemaps = get_sitemaps(url)
    if sitemaps is None:
        return {"Pages": []}
    all_urls = []

    for sitemap in sitemaps:
        all_urls.extend(sitemap_parser(sitemap))

    urls_dict = {"Pages": all_urls}

    return (urls_dict)


def find_open_port(hostname, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((hostname, port))
    sock.close()

    return result == 0


def check_ports(url):
    ports_to_check = [21, 22, 23, 25, 53, 80, 110,
                      143, 443, 465, 587, 993, 995, 3306, 3389, 8080]
    open_ports = []
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: (
            port, find_open_port(url, port)), ports_to_check))

    for port, is_open in results:
        if is_open:
            open_ports.append(port)
    return {"Open Ports": open_ports}


def whois_info(domain):
    valid_tld = ['cc', 'com', 'edu', 'name', 'net']
    try:
        parts = domain.split('.')
        if len(parts) < 2:
            return {'error': 'Invalid domain name.'}
        # Use the last two labels so subdomains (e.g. www.example.com) work.
        sd, tld = parts[-2], parts[-1]
        if (tld not in valid_tld):
            return {'error': 'The Whois database only accepts these top level domains: .cc .com .edu .name .net '}
        url = f"https://webwhois.verisign.com/webwhois-ui/rest/whois?q={sd}&tld={tld}&type=domain"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            text = data["message"]
            lines = text.split('\n')
            domain_data = {}

            for i in range(17):
                key, value = lines[i].split(':', 1)
                # Remove leading/trailing whitespaces
                domain_data[key] = value.strip()

            return domain_data
        else:
            return {"error": f"Unable to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": f"An error occurred: {e}"}


def get_screenshot(url):
    chrome_options = Options()
    # Run Chrome in headless mode (no GUI)
    chrome_options.add_argument('--headless')

    driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get(url)

        # Wait for some time to let the page load (adjust this according to your needs)
        driver.implicitly_wait(10)

        # Capture a screenshot and convert it to base64
        screenshot_base64 = driver.get_screenshot_as_base64()

        return {"screenshot": screenshot_base64}

    except Exception as e:
        print(f'Error: {e}')

    finally:
        # Close the WebDriver
        driver.quit()


def get_internal_external_links(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        base_url = urlparse(url).scheme + '://' + urlparse(url).hostname
        links = re.findall(r'href=["\'](https?://[^\s"\'<>]+)', response.text)
        internal_links = []
        external_links = []

        for link in links:
            absolute_link = urljoin(base_url, link)
            if urlparse(absolute_link).hostname == urlparse(url).hostname:
                internal_links.append(absolute_link)
            else:
                external_links.append(absolute_link)

        return {'Internal Links': internal_links, 'External Links': external_links}

    except requests.exceptions.RequestException as e:
        return {'error': f'Request error during request to {e}', 'message': 'Some sites might prohibit automated requests.'}


def get_emails(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()

        emails = re.findall(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
        return {'Emails': emails}

    except requests.exceptions.RequestException as e:
        return {'error': f'Request error during request to {e}', 'message': 'Some sites might prohibit automated requests.'}


def get_phone_numbers(url, timeout=5):
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        text_content = re.sub('<.*?>', ' ', response.text)
        phone_numbers = re.findall(
            r'\b1\s?\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b', text_content)
        return {'Phone Numbers': phone_numbers}

    except requests.exceptions.RequestException as e:
        return {'error': f'Request error during request to {e}', 'message': 'Some sites might prohibit automated requests.'}


def _subdomains_crtsh(domain, timeout):
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    # One attempt: crt.sh either answers promptly or is down; HackerTarget is
    # the fallback, so fail fast rather than retry a struggling endpoint.
    resp = _get_with_retries(url, timeout=timeout, attempts=1,
                             headers={'User-Agent': 'Mozilla/5.0'})
    subs = set()
    for entry in resp.json():
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower().lstrip('*.')
            if '@' in name or ' ' in name:
                continue
            if name.endswith('.' + domain):
                subs.add(name)
    return subs


def _subdomains_hackertarget(domain, timeout):
    url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
    resp = _get_with_retries(url, timeout=timeout, attempts=2)
    text = resp.text.strip()
    # HackerTarget signals errors/quota as plain text with a 200 status.
    if (not text or ',' not in text or 'error' in text.lower()
            or 'API count exceeded' in text):
        raise requests.exceptions.RequestException('HackerTarget unavailable')
    subs = set()
    for line in text.splitlines():
        host = line.split(',')[0].strip().lower()
        if host.endswith('.' + domain):
            subs.add(host)
    return subs


def get_subdomains(domain, timeout=12, limit=250):
    """Enumerate subdomains, with a fallback source when the primary is down.

    Primary: crt.sh (Certificate Transparency). Fallback: HackerTarget — used
    when crt.sh is overloaded (frequent 502s) or returns nothing.
    """
    subs = set()
    source = None

    try:
        subs = _subdomains_crtsh(domain, timeout)
        source = 'crt.sh'
    except (ValueError, requests.exceptions.RequestException):
        pass

    if not subs:
        try:
            subs = _subdomains_hackertarget(domain, timeout)
            source = 'HackerTarget'
        except (ValueError, requests.exceptions.RequestException):
            pass

    if source is None:
        return {'error': 'Subdomain sources (crt.sh and HackerTarget) are both temporarily unavailable. Try again shortly.'}

    ordered = sorted(subs)
    result = {'Count': len(ordered), 'Source': source, 'Subdomains': ordered[:limit]}
    if len(ordered) > limit:
        result['Note'] = f'Showing first {limit} of {len(ordered)}'
    return result


def get_wayback(url, timeout=8, count_cap=10000):
    """Summarise a URL's history in the Internet Archive (Wayback Machine)."""
    base = ('http://web.archive.org/cdx/search/cdx?url='
            + parse.quote(url, safe='') + '&output=json&fl=timestamp')

    def fmt(ts):
        try:
            return datetime.strptime(ts[:8], '%Y%m%d').strftime('%Y-%m-%d')
        except ValueError:
            return ts

    # Primary: CDX API — gives first capture, last capture and a total count.
    # Single attempt: when CDX is down it is slow (5s 503s), so fail fast to
    # the availability fallback rather than retrying a struggling endpoint.
    try:
        oldest = _get_with_retries(base + '&limit=1', timeout=timeout, attempts=1).json()
        if len(oldest) < 2:
            return {'Snapshots': 0, 'Note': 'No archived snapshots found'}
        newest = _get_with_retries(base + '&limit=-1', timeout=timeout, attempts=1).json()

        first_ts = oldest[1][0]
        last_ts = newest[1][0]
        result = {
            'First capture': fmt(first_ts),
            'Last capture': fmt(last_ts),
            'Latest snapshot': f'https://web.archive.org/web/{last_ts}/{url}',
        }
        try:
            cap = requests.get(base + f'&limit={count_cap + 1}', timeout=8).json()
            n = max(len(cap) - 1, 0)
            result['Snapshots'] = f'{count_cap}+' if n > count_cap else str(n)
        except Exception:
            pass
        return result
    except (ValueError, requests.exceptions.RequestException):
        pass

    # Fallback: the lighter availability API is often up when CDX is 5xx.
    try:
        avail_url = 'http://archive.org/wayback/available?url=' + parse.quote(url, safe='')
        snap = (_get_with_retries(avail_url, timeout=timeout, attempts=2).json()
                .get('archived_snapshots', {}).get('closest'))
        if snap and snap.get('available'):
            return {
                'Last capture': fmt(snap.get('timestamp', '')),
                'Latest snapshot': snap.get('url'),
                'Note': 'Full history is unavailable right now; showing the latest snapshot only.',
            }
        return {'Snapshots': 0, 'Note': 'No archived snapshots found'}
    except (ValueError, requests.exceptions.RequestException):
        return {'error': 'The Internet Archive (Wayback) did not respond in time. Try again shortly.'}


def _header_ci(headers, name):
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _domain_age_days(whois):
    if not isinstance(whois, dict):
        return None
    # whois keys can carry stray whitespace/casing, so match loosely.
    created = None
    for key, value in whois.items():
        if 'creation' in key.strip().lower() or key.strip().lower() in ('created', 'created date'):
            created = value
            break
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.strip().replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, AttributeError):
        return None


def _dmarc_present(domain):
    try:
        answers = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
        return any('v=dmarc1' in r.to_text().lower() for r in answers)
    except Exception:
        return False


def assess_credibility(data, domain):
    """Synthesise the collected signals into a trust score and findings list.

    Reads only data already gathered by the other tools (plus one DMARC
    lookup), so it must run after they complete.
    """
    checks = []

    def add(label, status, detail, weight):
        # status: good / warn / bad / na
        checks.append({'label': label, 'status': status, 'detail': detail,
                       'weight': weight})

    # TLS certificate
    ssl_info = data.get('ssl_info') or {}
    not_after = ssl_info.get('not_valid_after')
    if not_after:
        try:
            exp = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp > datetime.now(timezone.utc):
                issuer = ssl_info.get('issuer') or 'unknown issuer'
                add('TLS certificate', 'good', f'Valid, issued by {issuer}', 20)
            else:
                add('TLS certificate', 'bad', 'Certificate has expired', 20)
        except ValueError:
            add('TLS certificate', 'warn', 'Certificate present, dates unclear', 20)
    else:
        add('TLS certificate', 'bad', 'No valid HTTPS certificate found', 20)

    # Domain age
    age = _domain_age_days(data.get('whois_info'))
    if age is None:
        add('Domain age', 'na', 'Registration date unavailable', 0)
    elif age >= 365:
        add('Domain age', 'good', f'Registered {age // 365} year(s) ago', 15)
    elif age >= 90:
        add('Domain age', 'warn', f'Registered {age} days ago', 15)
    else:
        add('Domain age', 'bad', f'Very new — registered {age} days ago', 15)

    # SPF
    txt = data.get('dns_records', {}).get('TXT', [])
    spf = isinstance(txt, list) and any('v=spf1' in t.lower() for t in txt)
    add('SPF record', 'good' if spf else 'warn',
        'Present' if spf else 'No SPF record found', 8)

    # DMARC
    dmarc = _dmarc_present(domain)
    add('DMARC record', 'good' if dmarc else 'warn',
        'Present' if dmarc else 'No DMARC policy found', 8)

    # Security headers
    headers = data.get('headers') or {}
    wanted = ['Strict-Transport-Security', 'Content-Security-Policy',
              'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']
    present = [h for h in wanted if _header_ci(headers, h)]
    ratio = len(present) / len(wanted)
    status = 'good' if ratio >= 0.6 else ('warn' if ratio > 0 else 'bad')
    add('Security headers', status,
        f'{len(present)} of {len(wanted)} present', 20)

    # Sensitive open ports
    open_ports = data.get('port_info', {}).get('Open Ports', [])
    risky = sorted(set(open_ports) & {21, 23, 3389, 3306, 5432})
    if risky:
        add('Exposed services', 'bad',
            'Sensitive ports open: ' + ', '.join(map(str, risky)), 15)
    else:
        add('Exposed services', 'good', 'No sensitive ports exposed', 15)

    # Redirect sanity
    redirects = data.get('redirects') or {}
    hops = redirects.get('Redirected From')
    final = redirects.get('Final URL')
    if isinstance(hops, list):
        final_host = urlparse(final).hostname if final else None
        if final_host and domain not in (final_host or ''):
            add('Redirects', 'warn',
                f'Ends on a different host: {final_host}', 10)
        elif len(hops) > 3:
            add('Redirects', 'warn', f'{len(hops)} redirect hops', 10)
        else:
            add('Redirects', 'good',
                'Direct' if not hops else f'{len(hops)} hop(s), same host', 10)
    else:
        add('Redirects', 'na', 'Could not evaluate redirects', 0)

    # Score
    points = {'good': 1.0, 'warn': 0.5, 'bad': 0.0}
    scored = [c for c in checks if c['status'] != 'na']
    total_weight = sum(c['weight'] for c in scored) or 1
    earned = sum(points[c['status']] * c['weight'] for c in scored)
    score = round(earned / total_weight * 100)
    band = 'High' if score >= 75 else ('Moderate' if score >= 45 else 'Low')

    return {'score': score, 'band': band, 'checks': checks}


def _vcard_fn(entity):
    """Pull the display name (fn) out of an RDAP entity's vCard array."""
    try:
        for item in entity.get('vcardArray', [None, []])[1]:
            if item[0] == 'fn':
                return item[3]
    except (KeyError, IndexError, TypeError):
        pass
    return None


def get_rdap(domain):
    """Domain registration via RDAP (rdap.org bootstrap).

    Replaces the old Verisign whois that only handled 5 TLDs — RDAP covers
    almost every TLD, no key required.
    """
    try:
        resp = _get_with_retries('https://rdap.org/domain/' + domain,
                                 timeout=10, attempts=2,
                                 headers={'Accept': 'application/rdap+json'})
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return {'error': 'RDAP registration lookup is unavailable for this domain.'}

    events = {e.get('eventAction'): e.get('eventDate')
              for e in data.get('events', []) if e.get('eventAction')}
    registrar = None
    for ent in data.get('entities', []):
        if 'registrar' in (ent.get('roles') or []):
            registrar = _vcard_fn(ent)
            break
    nameservers = sorted(n.get('ldhName') for n in data.get('nameservers', [])
                         if n.get('ldhName'))

    result = {}
    if registrar:
        result['Registrar'] = registrar
    if events.get('registration'):
        result['Creation Date'] = events['registration']
    if events.get('expiration'):
        result['Expiration Date'] = events['expiration']
    if events.get('last changed'):
        result['Last Changed'] = events['last changed']
    if data.get('status'):
        result['Status'] = data['status']
    if nameservers:
        result['Name Servers'] = nameservers
    if not result:
        return {'error': 'RDAP returned no registration details for this domain.'}
    return result


def get_rdap_ip(ip):
    """IP allocation details via RDAP (owning org, range, country)."""
    try:
        resp = _get_with_retries('https://rdap.org/ip/' + ip,
                                 timeout=10, attempts=2,
                                 headers={'Accept': 'application/rdap+json'})
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return {'error': 'RDAP IP lookup is unavailable.'}

    result = {}
    if data.get('name'):
        result['Network'] = data['name']
    if data.get('handle'):
        result['Handle'] = data['handle']
    if data.get('startAddress') and data.get('endAddress'):
        result['Range'] = f"{data['startAddress']} – {data['endAddress']}"
    if data.get('country'):
        result['Country'] = data['country']
    if data.get('type'):
        result['Type'] = data['type']
    for ent in data.get('entities', []):
        name = _vcard_fn(ent)
        if name:
            result['Owner'] = name
            break
    return result or {'error': 'RDAP returned no allocation details for this IP.'}
