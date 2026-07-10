"""Check whether a username exists across many public sites.

Best-effort: uses HTTP status codes (and a couple of body markers) to guess
whether a profile exists. Some sites soft-404 or block bots, so results are a
starting point for an analyst, not proof.
"""
import concurrent.futures
import re
import requests

_UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                     'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'}

# check modes:
#   'status'  -> 200 = found, 404/410 = not found, else unknown.
#   'absent'  -> 200 without the marker = found (site 200s for missing pages).
#   'present' -> 200 with the marker = found.
# 'caution': True marks platforms that aggressively block bots — their result
# is unreliable from a server (often 'unknown', sometimes a false positive).
_SITES = [
    # Developer / general — reliable status codes
    {'name': 'GitHub', 'url': 'https://github.com/{}', 'check': 'status'},
    {'name': 'GitLab', 'url': 'https://gitlab.com/{}', 'check': 'status'},
    {'name': 'Reddit', 'url': 'https://www.reddit.com/user/{}/about.json', 'check': 'status'},
    {'name': 'Chess.com', 'url': 'https://api.chess.com/pub/player/{}', 'check': 'status'},
    {'name': 'Dev.to', 'url': 'https://dev.to/{}', 'check': 'status'},
    {'name': 'Medium', 'url': 'https://medium.com/@{}', 'check': 'status'},
    {'name': 'Keybase', 'url': 'https://keybase.io/{}', 'check': 'status'},
    {'name': 'Replit', 'url': 'https://replit.com/@{}', 'check': 'status'},
    {'name': 'Gravatar', 'url': 'https://en.gravatar.com/{}', 'check': 'status'},
    {'name': 'Pinterest', 'url': 'https://www.pinterest.com/{}/', 'check': 'status'},
    {'name': 'SoundCloud', 'url': 'https://soundcloud.com/{}', 'check': 'status'},
    {'name': 'Vimeo', 'url': 'https://vimeo.com/{}', 'check': 'status'},
    {'name': 'Patreon', 'url': 'https://www.patreon.com/{}', 'check': 'status'},
    {'name': 'Behance', 'url': 'https://www.behance.net/{}', 'check': 'status'},
    {'name': 'Steam', 'url': 'https://steamcommunity.com/id/{}',
     'check': 'absent', 'marker': 'The specified profile could not be found'},
    {'name': 'Hacker News', 'url': 'https://news.ycombinator.com/user?id={}',
     'check': 'absent', 'marker': 'No such user.'},
    # Media / social — usually workable
    {'name': 'YouTube', 'url': 'https://www.youtube.com/@{}', 'check': 'status'},
    {'name': 'Snapchat', 'url': 'https://www.snapchat.com/add/{}', 'check': 'status'},
    {'name': 'Spotify', 'url': 'https://open.spotify.com/user/{}', 'check': 'status'},
    {'name': 'Linktree', 'url': 'https://linktr.ee/{}', 'check': 'status'},
    {'name': 'Flickr', 'url': 'https://www.flickr.com/people/{}', 'check': 'status'},
    {'name': 'Telegram', 'url': 'https://t.me/{}', 'check': 'present', 'marker': 'tgme_page_title'},
    # Big platforms — aggressive bot-blocking, best-effort only
    {'name': 'Instagram', 'url': 'https://www.instagram.com/{}/',
     'check': 'absent', 'marker': "Sorry, this page isn't available", 'caution': True},
    {'name': 'Facebook', 'url': 'https://www.facebook.com/{}',
     'check': 'absent', 'marker': "isn't available", 'caution': True},
    {'name': 'TikTok', 'url': 'https://www.tiktok.com/@{}',
     'check': 'absent', 'marker': "Couldn't find this account", 'caution': True},
    {'name': 'X (Twitter)', 'url': 'https://x.com/{}',
     'check': 'absent', 'marker': "This account doesn’t exist", 'caution': True},
]


def _check_site(site, username):
    url = site['url'].format(username)
    result = {'name': site['name'], 'url': url, 'caution': site.get('caution', False)}
    try:
        r = requests.get(url, headers=_UA, timeout=8, allow_redirects=True)
        code = r.status_code
        mode = site['check']
        if mode == 'absent':
            if code == 200:
                result['status'] = 'notfound' if site['marker'].lower() in r.text.lower() else 'found'
            elif code in (404, 410):
                result['status'] = 'notfound'
            else:
                result['status'] = 'unknown'
        elif mode == 'present':
            if code == 200:
                result['status'] = 'found' if site['marker'].lower() in r.text.lower() else 'notfound'
            elif code in (404, 410):
                result['status'] = 'notfound'
            else:
                result['status'] = 'unknown'
        else:  # status
            if code == 200:
                result['status'] = 'found'
            elif code in (404, 410):
                result['status'] = 'notfound'
            else:
                result['status'] = 'unknown'
    except requests.exceptions.RequestException:
        result['status'] = 'error'
    return result


def check_username(username):
    username = (username or '').strip()
    if not re.match(r'^[A-Za-z0-9._-]{1,40}$', username):
        return {'username': username, 'found_count': 0, 'total': 0, 'results': [],
                'error': 'Enter a valid username (letters, digits, dot, dash, underscore).'}

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        results = list(ex.map(lambda s: _check_site(s, username), _SITES))

    order = {'found': 0, 'unknown': 1, 'notfound': 2, 'error': 3}
    results.sort(key=lambda r: (order.get(r['status'], 4), r['name'].lower()))
    found = sum(1 for r in results if r['status'] == 'found')
    return {'username': username, 'found_count': found, 'total': len(results), 'results': results}
