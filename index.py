import os
import re
import uuid
import time
import requests
import imaplib
import email
from email.header import decode_header
import random
import logging
import asyncio
import aiohttp
import string
import glob
from xml.etree import ElementTree as ET
from flask import Flask, request, jsonify
from flask_cors import CORS
try:
    from pywidevine.pssh import PSSH
    from pywidevine.cdm import Cdm
    from pywidevine.device import Device
    PYWIDEVINE_AVAILABLE = True
except ImportError:
    PYWIDEVINE_AVAILABLE = False
    logging.warning("Pywidevine not installed — DRM decryption will fail")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# === CONFIG FROM ENV ===
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "YOUR GMAIL ID")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD", "16 DIGIT GMAIL APP PASSWORD")

# === GLOBALS ===
token_cache = {"tokens": [], "user_usage": {}}
token_count = 0
MAX_USES_PER_TOKEN = 150
recent_logs = []
MAX_RECENT_LOGS = 100
server_start_time = time.time()
CURRENT_DEVICE_ID = uuid.uuid4().hex  # Fixed device ID for all requests
CURRENT_FINGERPRINT_ID = uuid.uuid4().hex  # Fixed fingerprint ID

# === CONSTANTS ===
API_URL = "https://api.classplusapp.com"
REGION = "IN"
API_VERSION = "52"
NAMES = ["Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan", "Krishna", "Ishaan", "Atharv"]
ORG_CODES = ["zevobw"]
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)"]

# === HELPERS ===
def random_user_agent(): return random.choice(USER_AGENTS)
def random_name(): return random.choice(NAMES)
def random_mobile(): return random.choice(["9", "8", "7", "6"]) + ''.join(random.choices(string.digits, k=9))
def random_org_code(): return random.choice(ORG_CODES)

def get_headers(device_id=CURRENT_DEVICE_ID):  # Use fixed device ID
    return {
        "Accept": "application/json, text/plain, */*",
        "accept-language": "en",
        "Content-Type": "application/json;charset=utf-8",
        "Api-Version": API_VERSION,
        "device-id": device_id,
        "region": REGION,
        "User-Agent": random_user_agent()
    }

# === GMAIL OTP FETCH ===
def get_otp_from_gmail(account, timeout=40):
    email_addr = account.get("email", EMAIL_ADDRESS)
    password = account.get("password", EMAIL_APP_PASSWORD)
    if not email_addr or not password:
        logger.error("Gmail credentials not configured.")
        return None, None
    logger.info(f"Waiting for OTP in {email_addr}...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(email_addr, password)
            mail.select("inbox")
            _, data = mail.search(None, '(UNSEEN FROM "email@ce.classplus.co")')
            for email_id in data[0].split()[::-1]:
                _, msg_data = mail.fetch(email_id, "(RFC822)")
                msg = email.message_from_bytes(msg_data[0][1])
                subject = decode_header(msg["Subject"])[0][0]
                if isinstance(subject, bytes):
                    subject = subject.decode()
                subject_match = re.search(r'\b(\d{4})\b', subject)
                if subject_match:
                    return subject_match.group(1), msg.get("Message-ID", "")
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode(errors="ignore")
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode(errors="ignore")
                for pattern in [r'(\d{4})\s+is\s+your\s+OTP', r'OTP:\s*(\d{4})', r'OTP\s+is\s+(\d{4})', r'\bverify\s+with\s+(\d{4})\b', r'\b(\d{4})\b']:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        return match.group(1), msg.get("Message-ID", "")
        except Exception as e:
            logger.error(f"OTP fetch error: {e}")
            break
        time.sleep(5)
    logger.warning(f"Timeout: No OTP in {email_addr}")
    return None, None

# === TOKEN GENERATION LOGIC ===
async def generate_token_logic():
    org_code = random_org_code()
    org_id, org_name = await validate_org(org_code)
    name, mobile = random_name(), random_mobile()
    for attempt in range(5):
        email_addr = f"{EMAIL_ADDRESS.split('@')[0]}+{random.randint(1000,9999)}@{EMAIL_ADDRESS.split('@')[1]}"
        logger.info(f"[{attempt+1}/5] Trying: {email_addr}")
        try:
            session_start_time = time.time()
            session_id = await generate_otp(email_addr, org_id, org_code, CURRENT_DEVICE_ID)
            otp, msg_id = get_otp_from_gmail({"email": EMAIL_ADDRESS, "password": EMAIL_APP_PASSWORD})
            if not otp:
                logger.warning("OTP not received, next email...")
                continue
            if msg_id:
                logger.info(f"Email ID: {msg_id}")
            elapsed = time.time() - session_start_time
            if elapsed < 15:
                logger.info(f"Waiting for OTP to stabilize ({elapsed:.1f}s)")
                await asyncio.sleep(5)
            try:
                await verify_otp(otp, session_id, org_id, email_addr, CURRENT_DEVICE_ID)
                token = await register_user(name, email_addr, mobile, org_id, org_name, session_id, otp, CURRENT_DEVICE_ID)
                logger.info("Token generated successfully.")
                return token
            except Exception as e:
                if "Invalid OTP" in str(e) or "otpInvalid" in str(e).lower():
                    logger.warning("Invalid OTP, regenerating...")
                    session_id = await generate_otp(email_addr, org_id, org_code, CURRENT_DEVICE_ID)
                    otp, msg_id = get_otp_from_gmail({"email": EMAIL_ADDRESS, "password": EMAIL_APP_PASSWORD})
                    if not otp:
                        logger.error("No OTP after regeneration")
                        continue
                    await verify_otp(otp, session_id, org_id, email_addr, CURRENT_DEVICE_ID)
                    token = await register_user(name, email_addr, mobile, org_id, org_name, session_id, otp, CURRENT_DEVICE_ID)
                    logger.info("Token generated after OTP regeneration.")
                    return token
            logger.error(f"Verification/Registration failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Attempt {attempt+1} failed: {e}")
            await asyncio.sleep(2)
    raise Exception("All attempts failed.")

async def validate_org(org_code, device_id=CURRENT_DEVICE_ID):
    headers = get_headers(device_id)
    logger.info(f"Validating org: {org_code}")
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_URL}/v2/orgs/{org_code}", headers=headers, timeout=10) as r:
            if r.status != 200:
                raise Exception(f"Invalid org: {org_code}")
            d = (await r.json())["data"]
            logger.info(f"Org valid: {d['orgName']}")
            return d["orgId"], d["orgName"]

async def generate_otp(email, org_id, org_code, device_id=CURRENT_DEVICE_ID):
    headers = get_headers(device_id)
    payload = {"countryExt": "91", "orgCode": org_code, "viaSms": 0, "viaEmail": 1, "retry": 0, "orgId": org_id, "otpCount": 0, "email": email}
    logger.info(f"Sending OTP to: {email}")
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}/v2/otp/generate", json=payload, headers=headers, timeout=10) as r:
            if r.status != 200:
                raise Exception(f"OTP gen failed: {await r.text()}")
            logger.info("OTP sent")
            return (await r.json())["data"]["sessionId"]

async def verify_otp(otp, session_id, org_id, email, device_id=CURRENT_DEVICE_ID):
    headers = get_headers(device_id)
    payload = {"otp": otp, "countryExt": "91", "sessionId": session_id, "orgId": org_id, "fingerprintId": CURRENT_FINGERPRINT_ID, "email": email}  # Use fixed fingerprint
    logger.info(f"Verifying OTP {otp}")
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}/v2/users/verify", json=payload, headers=headers, timeout=10) as r:
            if r.status not in (200, 201):
                error_msg = await r.text()
                if "otpInvalid" in error_msg:
                    raise Exception("Invalid OTP")
                raise Exception(f"Verification failed: {error_msg}")
            logger.info("OTP verified")

async def register_user(name, email, mobile, org_id, org_name, session_id, otp, device_id=CURRENT_DEVICE_ID):
    headers = get_headers(device_id)
    payload = {"contact": {"email": email, "countryExt": "91", "mobile": mobile}, "type": 1, "name": name, "orgId": org_id, "orgName": org_name, "sessionId": session_id, "otp": otp, "fingerprintId": CURRENT_FINGERPRINT_ID, "viaSms": 0, "viaEmail": 1}  # Use fixed fingerprint
    logger.info(f"Registering user: {name}")
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{API_URL}/v2/users/register", json=payload, headers=headers, timeout=10) as r:
            if r.status != 200:
                raise Exception(f"Registration failed: {await r.text()}")
            logger.info("Registration successful")
            response_data = await r.json()
            return response_data["data"]["token"] if "data" in response_data and "token" in response_data["data"] else None

# === TOKEN CACHE ===
def get_cached_token_internal():
    current_time = time.time()
    token_cache["tokens"] = [t for t in token_cache["tokens"] if current_time < t.get("expires_at", float('inf'))]
    user_id_str = "unknown"
    for i in range(len(token_cache["tokens"]) - 1, -1, -1):
        token_obj = token_cache["tokens"][i]
        token_value = token_obj["token"]
        if token_value not in token_cache["user_usage"]:
            token_cache["user_usage"][token_value] = {}
        current_uses = token_cache["user_usage"][token_value].get(user_id_str, 0)
        if current_uses < MAX_USES_PER_TOKEN:
            token_cache["user_usage"][token_value][user_id_str] = current_uses + 1
            return token_value
    return None

def add_token_to_cache_internal(token):
    expires_at = time.time() + 24 * 3600
    token_cache["tokens"].append({"token": token, "created_at": time.time(), "expires_at": expires_at})
    token_cache["user_usage"][token] = {}
    logger.info("New token cached.")

def generate_single_token_internal():
    global token_count
    try:
        token = asyncio.run(generate_token_logic())
        if token:
            token_count += 1
            return {"success": True, "token": token, "token_count": token_count}
        return {"success": False, "error": "Token generation returned None"}
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        return {"success": False, "error": f"Exception: {str(e)}"}

def get_or_generate_token_internal():
    token = get_cached_token_internal()
    if token:
        return token
    result = generate_single_token_internal()
    if result.get('success'):
        add_token_to_cache_internal(result['token'])
        return result['token']
    logger.error(f"Failed to generate token: {result.get('error')}")
    return None

# === WVD LOADER ===
def find_wvd_file():
    possible_paths = [
        'WVDs/*.wvd',
        './WVDs/*.wvd',
        'WVDs/device.wvd',
        './WVDs/device.wvd'
    ]
    for pattern in possible_paths:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    raise FileNotFoundError("No .wvd file found in WVDs/ folder")

# === SIGN URL (WITH DRM SUPPORT) ===
def sign_url_internal(url, token):
    try:
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip',
            'accept-language': 'EN',
            'api-version': '35',
            'app-version': '1.4.73.2',
            'build-number': '35',
            'connection': 'Keep-Alive',
            'content-type': 'application/json',
            'device-details': 'Xiaomi_Redmi 7_SDK-32',
            'device-id': CURRENT_DEVICE_ID,  # Use fixed device ID
            'host': 'api.classplusapp.com',
            'region': 'IN',
            'user-agent': 'Mobile-Android',
            'webengage-luid': '00000187-6fe4-5d41-a530-26186858be4c'
        }
        if token:
            headers['x-access-token'] = token

        # Bypass Nepal block by using proxy or alternative endpoint if needed
        # (Currently Classplus API may block Nepal IPs — consider using proxy if this fails)
        signed_resp = requests.get(
            f'https://api.classplusapp.com/cams/uploader/video/jw-signed-url?url={url}',
            headers=headers,
            timeout=15
        )
        try:
            response = signed_resp.json()
        except ValueError:
            return {"error": "Failed to parse JSON from Classplus API"}

        # Non-DRM case
        if response.get('status') == 'ok' and response.get('url'):            return {"url": response['url']}

        # Token invalid
        if response.get('error') == 'Invalid token' or response.get('status') == 'failure':
            return {"error": "Token expired or invalid"}

        # DRM case
        drm_urls = response.get('drmUrls')
        if not drm_urls:
            return {"error": "Unexpected response: no DRM and no direct URL"}

        mpd_url = drm_urls.get('manifestUrl')
        lic_url = drm_urls.get('licenseUrl')
        if not mpd_url or not lic_url:
            return {"error": "Missing DRM manifest or license URL"}

        # Fetch MPD
        mpd_resp = requests.get(mpd_url, timeout=10)
        if mpd_resp.status_code != 200:
            return {"error": f"MPD fetch failed: HTTP {mpd_resp.status_code}"}

        # Parse PSSH robustly
        pssh_b64 = None
        try:
            root = ET.fromstring(mpd_resp.content)
        except ET.ParseError:
            return {"error": "Invalid MPD XML"}

        namespaces = {'cenc': 'urn:mpeg:cenc:2013'}
        for elem in root.iter():
            if 'ContentProtection' in elem.tag:
                scheme = elem.get('schemeIdUri', '').lower()
                if 'edef8ba9-79d6-4ace-a3c8-27dcd51d21ed' in scheme:
                    # Try multiple strategies
                    pssh_elem = elem.find('.//{urn:mpeg:cenc:2013}pssh')
                    if pssh_elem is None:
                        pssh_elem = elem.find('.//cenc:pssh', namespaces)
                    if pssh_elem is None:
                        for child in elem:
                            if 'pssh' in child.tag.lower():
                                pssh_elem = child
                                break
                    if pssh_elem is not None and pssh_elem.text:
                        pssh_b64 = pssh_elem.text.strip()
                        break

        if not pssh_b64:
            return {"error": "PSSH not found in MPD"}

        # Load WVD
        try:
            wvd_path = find_wvd_file()
        except Exception as e:
            return {"error": f"WVD error: {str(e)}"}

        if not PYWIDEVINE_AVAILABLE:
            return {"error": "Pywidevine not installed — cannot decrypt DRM"}

        # Decrypt
        try:
            ipssh = PSSH(pssh_b64)
            device = Device.load(wvd_path)
            cdm = Cdm.from_device(device)
            session_id = cdm.open()
            challenge = cdm.get_license_challenge(session_id, ipssh)
            lic_headers = {
                'user-agent': 'okhttp/4.9.3',
                'content-type': 'application/octet-stream'
            }
            lic_resp = requests.post(lic_url, data=challenge, headers=lic_headers, timeout=15)
            if lic_resp.status_code != 200:
                cdm.close(session_id)
                return {"error": f"License request failed: {lic_resp.status_code}"}
            cdm.parse_license(session_id, lic_resp.content)
            keys = []
            for key in cdm.get_keys(session_id):
                if key.type == 'CONTENT':
                    keys.append(f"{key.kid.hex}:{key.key.hex()}")
            cdm.close(session_id)
            if not keys:
                return {"error": "No decryption keys extracted"}
            return {
                "MPD": mpd_url,
                "KEYS": keys,            }
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return {"error": f"DRM decryption failed: {str(e)}"}
    except Exception as e:
        logger.error(f"sign_url_internal error: {e}")
        return {"error": f"Processing failed: {str(e)}"}

# === TELEGRAM & LOGGING ===
def log_request(url):
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
    }
    recent_logs.append(log_entry)
    if len(recent_logs) > MAX_RECENT_LOGS:
        recent_logs.pop(0)

# === FLASK ROUTES ===
@app.route('/favicon.ico')
def favicon():
    return "", 204

@app.route('/favicon.png')
def favicon_png():
    return "", 204

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome",
        "example": f"{request.url_root}ITsGOLU_OFFICIAL?url={{url}}"
    })

@app.route('/ITsGOLU_OFFICIAL', methods=['GET'])
def ITsGOLU_OFFICIAL():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    actual_url = url
    logger.info(f"Processing: {actual_url[:50]}...")
    token = get_or_generate_token_internal()
    if not token:
        return jsonify({"success": False, "error": "Token generation failed"}), 500
    result = sign_url_internal(actual_url, token)
    if "error" in result and "Invalid token" in str(result.get("error", "")):
        token = get_or_generate_token_internal()
        if not token:
            return jsonify({"success": False, "error": "Token generation failed"}), 500
        result = sign_url_internal(actual_url, token)
    if "error" not in result:
        log_request(actual_url)
        return jsonify({"success": True, **result})
    return jsonify({"success": False, "error": result["error"]}), 500

@app.route('/admin', methods=['GET'])
def admin_dashboard():
    total_tokens = len(token_cache["tokens"])
    uptime_seconds = int(time.time() - server_start_time)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"
    return jsonify({
        "dashboard": "Admin Panel",
        "uptime": uptime_str,
        "stats": {
            "total_tokens_generated": token_count,
            "active_tokens": total_tokens,
            "max_uses_per_token": MAX_USES_PER_TOKEN
        }
    })

@app.route('/generate_token', methods=['GET'])
def manual_token_generate():
    result = generate_single_token_internal()
    if result.get('success'):
        add_token_to_cache_internal(result['token'])
        return jsonify({"success": True, "token": result['token']})
    return jsonify({"success": False, "error": result.get('error', 'Unknown error')}), 500

# === RUN ===
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
