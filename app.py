import concurrent.futures
import json
import os
import re

from flask import Flask, render_template, request as flask_request, jsonify
from dotenv import load_dotenv

from web_tools import (
    website_information, get_redirects, get_cookies, get_headers,
    get_ip_info, get_records, get_ssl, site_maps, check_ports,
    whois_info, get_screenshot, get_internal_external_links,
    get_emails, get_phone_numbers, is_safe_url,
    get_subdomains, get_wayback, assess_credibility,
    get_rdap,
)
from ip_tools import analyze_ip
from file_tools import get_exif
from pid_tools import get_phone_info
from dork_tools import generate_dorks
from user_tools import check_username
from email_tools import check_email


app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Reject uploads larger than 20 MB (matches the client-side check).
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

load_dotenv()
secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    # Fall back to an ephemeral key so the app still runs in development.
    print("Warning: SECRET_KEY not set; using a temporary key for this run.")
    secret_key = os.urandom(32)
app.secret_key = secret_key


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/web_tool', methods=["GET", "POST"])
def web_tool():
    user_url = flask_request.values.get('web_input')
    if not user_url:
        return jsonify({"error": "Please provide a valid URL"}), 400

    url_pattern = re.compile(
        r'^http(s)://(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+(?:/[^/\s]*)?$')
    if not url_pattern.match(user_url):
        return jsonify({"error": "Please provide a valid HTTPS URL"}), 400
    unallowed_domains = ["osintdashboard.info","https://osintdashboard.azurewebsites.net/"]

    if user_url in unallowed_domains or user_url.startswith("https://osintdashboard.azurewebsites.net/"):
        return jsonify({"error": "Access to this domain is not allowed"}), 400

    # Block SSRF: refuse URLs that resolve to private/reserved addresses
    # before making any outbound request to them.
    safe, reason = is_safe_url(user_url)
    if not safe:
        return jsonify({"error": reason}), 400

    domain, ip_str, title, favicon = website_information(user_url)
    large_json = {
        "ip_info": {},
        "cookies": {},
        "headers": {},
        "dns_records": {},
        "ssl_info": {},
        'redirects': {},
        'sitemap': {},
        'port_info': {},
        'whois_info': {},
        'screenshot': {},
        'link_info': {},
        'email_info': {},
        'phone_info': {},
        'subdomain_info': {},
        'wayback_info': {}
    }

    # The fast tools run synchronously here. The slow/flaky ones (subdomains,
    # wayback, screenshot) are loaded afterwards by the page over AJAX via
    # /web_tool_data, so one slow source no longer blocks the whole report.
    with concurrent.futures.ThreadPoolExecutor() as executor:
        redirect_future = executor.submit(get_redirects, user_url)
        cookies_future = executor.submit(get_cookies, user_url)
        headers_future = executor.submit(get_headers, user_url)
        ip_info_future = executor.submit(get_ip_info, ip_str)
        dns_rec_future = executor.submit(get_records, domain)
        ssl_cer_future = executor.submit(get_ssl, domain)
        sitemap_future = executor.submit(site_maps, user_url)
        port_info_future = executor.submit(check_ports, domain)
        whois_info_future = executor.submit(get_rdap, domain)
        link_info_future = executor.submit(
            get_internal_external_links, user_url)
        email_info_future = executor.submit(get_emails, user_url)
        phone_info_future = executor.submit(get_phone_numbers, user_url)

        future_mapping = {
            redirect_future: "redirects",
            cookies_future: "cookies",
            headers_future: "headers",
            ip_info_future: "ip_info",
            dns_rec_future: "dns_records",
            ssl_cer_future: "ssl_info",
            sitemap_future: "sitemap",
            port_info_future: "port_info",
            whois_info_future: "whois_info",
            link_info_future: "link_info",
            email_info_future: "email_info",
            phone_info_future: "phone_info"
        }

        for future in concurrent.futures.as_completed(future_mapping):
            try:
                large_json[future_mapping[future]] = future.result()
            except Exception as e:
                print(f"Error: {e}")

    # Derive the credibility panel from everything collected above.
    large_json['credibility'] = assess_credibility(large_json, domain)

    return render_template('web_tools.html', user_url=domain, full_url=user_url, ip_info=ip_str, title=title, favicon=favicon, web_info=json.dumps(large_json), credibility=large_json['credibility'])


@app.route('/web_tool_data')
def web_tool_data():
    """Serve one slow tool's result as JSON for progressive (lazy) loading."""
    tool = flask_request.args.get('tool')
    if tool == 'subdomains':
        return jsonify({'result': get_subdomains(flask_request.args.get('domain', ''))})
    if tool == 'wayback':
        return jsonify({'result': get_wayback(flask_request.args.get('url', ''))})
    if tool == 'screenshot':
        url = flask_request.args.get('url', '')
        safe, reason = is_safe_url(url)
        if not safe:
            return jsonify({'result': {'error': reason}})
        return jsonify({'result': get_screenshot(url) or {'error': 'Screenshot failed'}})
    return jsonify({'error': 'unknown tool'}), 400


@app.route('/pid_tool', methods=["POST"])
def pid_tool():
    number = flask_request.form.get('phone_input')
    number_info = get_phone_info(number)
    return render_template('pid_tools.html', number=number, number_info=json.dumps(number_info))


@app.route('/dork_tool', methods=["POST"])
def dork_tool():
    term = flask_request.form.get('dork_input', '').strip()
    if not term:
        return render_template('index.html')
    dorks = generate_dorks(term)
    return render_template('dork_tools.html', dorks=dorks)


@app.route('/user_tool', methods=["POST"])
def user_tool():
    username = flask_request.form.get('user_input', '').strip()
    if not username:
        return render_template('index.html')
    return render_template('user_tools.html', data=check_username(username))


@app.route('/email_tool', methods=["GET", "POST"])
def email_tool():
    email = flask_request.values.get('email_input', '').strip()
    if not email:
        return render_template('index.html')
    return render_template('email_tools.html', data=check_email(email))


@app.route('/ip_tool', methods=["GET", "POST"])
def ip_tool():
    ip = flask_request.values.get('ip_input', '').strip()
    if not ip:
        return render_template('index.html')
    return render_template('ip_tools.html', data=analyze_ip(ip))


@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = flask_request.files.get('fileToUpload')
    if uploaded_file is None or uploaded_file.filename == '':
        return render_template('index.html')

    try:
        result = get_exif(uploaded_file)
    except Exception as e:
        print(f"Error reading image: {e}")
        return render_template(
            "report.html",
            PillowDict={"Error": ["Could not read the uploaded file as an image.",
                                  "The file may be corrupted or in an unsupported format."]},
        )

    # get_exif returns just PillowDict when there is no EXIF data,
    # or the full tuple when EXIF is present.
    if isinstance(result, dict):
        return render_template("report.html", PillowDict=result)

    PillowDict, coords, exifreadVersion, tags, presentTags, ExifDict = result
    return render_template("report.html", PillowDict=PillowDict, coords=coords, exifreadVersion=exifreadVersion, tags=tags, presentTags=presentTags, ExifDict=ExifDict)


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, port=5001)
