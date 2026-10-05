# -*- coding: utf-8 -*-
"""
Link2Go Backend — النسخة المحسّنة (أمان + ذكاء)

متغيرات البيئة المطلوبة (التطبيق مش هيشتغل من غيرها):
    ADMIN_USERNAME        اسم الأدمن
    ADMIN_PASSWORD_HASH   (مفضّل) هاش الباسورد:
                          python -c "from werkzeug.security import generate_password_hash as g; print(g('كلمتك'))"
    ADMIN_PASSWORD        (بديل لو مفيش هاش) 10 حروف على الأقل
    JWT_SECRET            32+ حرف عشوائي:  python -c "import secrets; print(secrets.token_urlsafe(48))"

اختيارية:
    ALLOWED_ORIGINS       دومينات الفرونت مفصولة بفاصلة (الافتراضي *)
    TRUST_PROXY=1         لو ورا Nginx/Cloudflare
    TRUSTED_PROXY_HOPS    عدد البروكسيات الموثوقة (الافتراضي 1)
    WHATSAPP_API_URL / WHATSAPP_API_KEY

ملاحظة: الحالة (OTP, rate limit, الضيوف) في الذاكرة → شغّل worker واحد
(gunicorn -w 1 --threads 8) أو انقلها لـ Redis لو هتكبّر.
"""
import os
import re
import sys
import json
import hmac
import time
import uuid
import hashlib
import secrets
import shutil
import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

import jwt
import requests
import yt_dlp
from yt_dlp.utils import match_filter_func
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
logger = logging.getLogger('link2go')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOAD_DIR = os.path.join(BASE_DIR, 'downloads')
USERS_DIR = os.path.join(BASE_DIR, 'users_data')
HISTORY_DIR = os.path.join(BASE_DIR, 'history_data')
for _d in (DOWNLOAD_DIR, USERS_DIR, HISTORY_DIR):
    os.makedirs(_d, exist_ok=True)


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ============== إعدادات عامة ==============
FILE_TTL_MINUTES = 10
LARGE_FILE_TTL_MINUTES = 60
LARGE_FILE_THRESHOLD_SECONDS = 3600
CLEANUP_INTERVAL = 60
ADMIN_TOKEN_HOURS = 8
SESSION_DAYS = 30
MAX_REQUEST_SIZE_MB = 1
HISTORY_MAX_ENTRIES = 500

# حدود التحميل
MAX_FILE_MB = _env_int('MAX_FILE_MB', 500)
MAX_DURATION_SECONDS = _env_int('MAX_DURATION_SECONDS', 4 * 3600)
MAX_VIDEO_HEIGHT = _env_int('MAX_VIDEO_HEIGHT', 1080)
MAX_CONCURRENT_DOWNLOADS = _env_int('MAX_CONCURRENT_DOWNLOADS', 3)
MAX_CONCURRENT_PER_USER = 2
MIN_FREE_DISK_GB = 1

# OTP
OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN = 60
OTP_PER_PHONE_HOURLY = 5

# Rate limiting
RATE_LIMIT_GLOBAL = 240
RATE_LIMIT_AUTH = 10
RATE_LIMIT_LOGIN = 5
RATE_LIMIT_DOWNLOAD = 20
RATE_LIMIT_SEARCH = 30

# ============== الأسرار (من البيئة فقط) ==============
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', '').strip()
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '').strip()
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
JWT_SECRET = os.environ.get('JWT_SECRET', '')

TRUST_PROXY = os.environ.get('TRUST_PROXY', '0') == '1'
TRUSTED_PROXY_HOPS = max(1, _env_int('TRUSTED_PROXY_HOPS', 1))
WHATSAPP_API_URL = os.environ.get('WHATSAPP_API_URL', 'http://127.0.0.1:4000/send')
WHATSAPP_API_KEY = os.environ.get('WHATSAPP_API_KEY', '')
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '*').split(',') if o.strip()]


def _require_config():
    problems = []
    if not ADMIN_USERNAME:
        problems.append('ADMIN_USERNAME')
    if not ADMIN_PASSWORD_HASH and len(ADMIN_PASSWORD) < 10:
        problems.append('ADMIN_PASSWORD_HASH (أو ADMIN_PASSWORD بطول 10+)')
    if len(JWT_SECRET) < 32:
        problems.append('JWT_SECRET (32+ حرف)')
    if problems:
        sys.stderr.write('❌ إعدادات ناقصة/ضعيفة: ' + ', '.join(problems) + '\n')
        raise RuntimeError('Missing or weak security configuration')
    if ALLOWED_ORIGINS == ['*']:
        logger.warning('CORS مفتوح لكل الدومينات — حدّد ALLOWED_ORIGINS في الإنتاج')


_require_config()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_SIZE_MB * 1024 * 1024
app.json.ensure_ascii = False
CORS(app, supports_credentials=False, resources={r"/*": {"origins": ALLOWED_ORIGINS}})

LINKS_HISTORY_FILE = os.path.join(HISTORY_DIR, 'links_history.json')
OTP_HISTORY_FILE = os.path.join(HISTORY_DIR, 'otp_history.json')
LOGIN_HISTORY_FILE = os.path.join(HISTORY_DIR, 'login_history.json')

# ==========================================
# 0. أدوات أساسية: أقفال + كتابة ذرّية
# ==========================================
_locks = defaultdict(threading.RLock)
_locks_guard = threading.Lock()


def lock_for(key):
    with _locks_guard:
        return _locks[key]


def now_utc():
    return datetime.now(timezone.utc)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def current_month_str():
    return datetime.now().strftime("%Y-%m")


def current_day_str():
    return datetime.now().strftime("%Y-%m-%d")


def read_json(path, default=None):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except (OSError, ValueError):
        logger.warning('read_json failed: %s', os.path.basename(path))
    return default


def atomic_write_json(path, data):
    """كتابة ذرّية: ملف مؤقت ثم استبدال — مفيش ملف نص مكتوب لو السيرفر وقع"""
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def err(msg, code=400, **extra):
    body = {'success': False, 'error': msg}
    body.update(extra)
    return jsonify(body), code


def get_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def safe_int(value, default, lo, hi):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


# ==========================================
# 1. السجلات (History)
# ==========================================
HISTORY_LOCK = threading.Lock()


def load_history(filepath):
    data = read_json(filepath, [])
    return data if isinstance(data, list) else []


def save_history(filepath, data):
    try:
        if len(data) > HISTORY_MAX_ENTRIES:
            data = data[-HISTORY_MAX_ENTRIES:]
        atomic_write_json(filepath, data)
    except OSError:
        logger.exception('History save error')


def log_event(filepath, event):
    event['timestamp'] = now_str()
    with HISTORY_LOCK:
        data = load_history(filepath)
        data.append(event)
        save_history(filepath, data)


def log_link_event(phone, username, url, action, status, error=None, ip=None):
    log_event(LINKS_HISTORY_FILE, {
        'phone': phone or 'guest', 'username': username or 'زائر',
        'url': (url or '')[:500], 'action': action, 'status': status,
        'error': error, 'ip': ip
    })


def log_otp_event(phone, action, status, error=None, ip=None):
    log_event(OTP_HISTORY_FILE, {
        'phone': phone, 'action': action, 'status': status, 'error': error, 'ip': ip
    })


def log_login_event(phone, username, action, status, error=None, ip=None):
    log_event(LOGIN_HISTORY_FILE, {
        'phone': phone or 'unknown', 'username': username or 'unknown',
        'action': action, 'status': status, 'error': error, 'ip': ip
    })


def audit(action, target=''):
    label = f"{action}:{target}" if target else action
    log_login_event('admin', ADMIN_USERNAME, label, 'success', None, rate_limiter.get_client_ip(request))


# ==========================================
# 2. الباقات
# ==========================================
PLANS = {
    'guest': {'name': 'زائر (مجهول)', 'platforms': ['tiktok', 'soundcloud'], 'limit': 2,
              'duration_days': 0, 'listens_limit': 0, 'listens_period': 'monthly',
              'price': 0, 'duration_label': 'مجاناً'},
    'free': {'name': 'الباقة المجانية', 'platforms': ['tiktok', 'soundcloud'], 'limit': 10,
             'duration_days': 0, 'listens_limit': 50, 'listens_period': 'monthly',
             'price': 0, 'duration_label': 'مجاناً'},
    'weekly': {'name': 'الباقة الأسبوعية',
               'platforms': ['tiktok', 'soundcloud', 'facebook', 'instagram'], 'limit': 20,
               'duration_days': 7, 'listens_limit': -1, 'listens_period': 'monthly',
               'price': 10, 'duration_label': 'أسبوع'},
    'monthly': {'name': 'الباقة الشهرية',
                'platforms': ['tiktok', 'soundcloud', 'facebook', 'instagram',
                              'youtube', 'x', 'shahid', 'anghami'], 'limit': -1,
                'duration_days': 30, 'listens_limit': -1, 'listens_period': 'monthly',
                'price': 50, 'duration_label': 'شهر'}
}

PLATFORM_DOMAINS = {
    'tiktok': ['tiktok.com'],
    'soundcloud': ['soundcloud.com'],
    'facebook': ['facebook.com', 'fb.watch', 'fb.com'],
    'instagram': ['instagram.com'],
    'youtube': ['youtube.com', 'youtu.be'],
    'x': ['twitter.com', 'x.com'],
    'shahid': ['shahid.mbc.net'],
    'anghami': ['anghami.com'],
}


# ==========================================
# 3. Rate Limiter + IP Blacklist
# ==========================================
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def is_allowed(self, key, limit, window_seconds):
        now = time.time()
        with self.lock:
            q = self.requests[key]
            while q and q[0] < now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False, len(q)
            q.append(now)
            return True, len(q)

    def purge(self, max_age=3700):
        now = time.time()
        with self.lock:
            for key in list(self.requests.keys()):
                q = self.requests[key]
                while q and q[0] < now - max_age:
                    q.popleft()
                if not q:
                    del self.requests[key]

    def get_client_ip(self, req):
        """مش بنثق في X-Forwarded-For إلا لو TRUST_PROXY=1 (وبناخد الخانة اللي ضافها البروكسي بتاعنا)"""
        if TRUST_PROXY:
            forwarded = req.headers.get('X-Forwarded-For', '')
            parts = [p.strip() for p in forwarded.split(',') if p.strip()]
            if len(parts) >= TRUSTED_PROXY_HOPS:
                return parts[-TRUSTED_PROXY_HOPS]
        return req.remote_addr or 'unknown'


rate_limiter = RateLimiter()


class IPBlacklist:
    THRESHOLD = 10      # مخالفات
    WINDOW = 600        # خلال 10 دقايق
    BAN_SECONDS = 3600

    def __init__(self):
        self.blacklist = {}
        self.events = defaultdict(deque)
        self.lock = threading.Lock()

    def add_suspicious(self, ip, reason):
        now = time.time()
        with self.lock:
            q = self.events[ip]
            q.append(now)
            while q and q[0] < now - self.WINDOW:
                q.popleft()
            if len(q) >= self.THRESHOLD:
                self.blacklist[ip] = now + self.BAN_SECONDS
                q.clear()
                logger.warning('IP banned: %s (%s)', ip, reason)

    def is_blacklisted(self, ip):
        with self.lock:
            exp = self.blacklist.get(ip)
            if not exp:
                return False
            if exp < time.time():
                del self.blacklist[ip]
                return False
            return True

    def cleanup(self):
        now = time.time()
        with self.lock:
            for ip in list(self.blacklist.keys()):
                if self.blacklist[ip] < now:
                    del self.blacklist[ip]
            for ip in list(self.events.keys()):
                q = self.events[ip]
                while q and q[0] < now - self.WINDOW:
                    q.popleft()
                if not q:
                    del self.events[ip]


ip_blacklist = IPBlacklist()


def rate_limit(limit=RATE_LIMIT_GLOBAL, window=60, key_suffix=''):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = rate_limiter.get_client_ip(request)
            key = f"{ip}:{key_suffix or request.endpoint}"
            allowed, _ = rate_limiter.is_allowed(key, limit, window)
            if not allowed:
                ip_blacklist.add_suspicious(ip, f"Rate limit: {request.endpoint}")
                return err(f'عدد كبير من الطلبات. حاول بعد {window} ثانية', 429)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ==========================================
# 4. التوكنات (أدمن + تسجيل جديد + جلسات المستخدمين)
# ==========================================
REVOKED_JTIS = {}            # jti -> exp (timestamp)
USED_SIGNUP_JTIS = {}
_jti_lock = threading.Lock()


def _jwt_encode(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def _jwt_decode(token):
    return jwt.decode(token, JWT_SECRET, algorithms=['HS256'],
                      options={'require': ['exp', 'iat', 'jti']})


def generate_admin_token():
    now = now_utc()
    return _jwt_encode({
        'username': ADMIN_USERNAME, 'role': 'admin', 'jti': uuid.uuid4().hex,
        'iat': now, 'exp': now + timedelta(hours=ADMIN_TOKEN_HOURS)
    })


def verify_admin_token(req):
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return False, 'التوكن غير موجود', None
    token = auth.split(' ', 1)[1].strip()
    try:
        payload = _jwt_decode(token)
    except jwt.ExpiredSignatureError:
        return False, 'انتهت صلاحية الجلسة', None
    except jwt.InvalidTokenError:
        return False, 'توكن غير صالح', None
    if payload.get('role') != 'admin':
        return False, 'صلاحيات غير كافية', None
    with _jti_lock:
        if payload.get('jti') in REVOKED_JTIS:
            return False, 'تم إنهاء الجلسة', None
    return True, None, payload


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ok, msg, _ = verify_admin_token(request)
        if not ok:
            return err(msg, 401)
        return f(*args, **kwargs)
    return wrapper


def create_signup_token(phone):
    now = now_utc()
    return _jwt_encode({
        'role': 'signup', 'phone': phone, 'jti': uuid.uuid4().hex,
        'iat': now, 'exp': now + timedelta(minutes=15)
    })


def consume_signup_token(token, phone):
    """تذكرة تسجيل لمرة واحدة، مربوطة برقم التليفون اللي اتحقق منه بالـ OTP"""
    try:
        payload = _jwt_decode(str(token))
    except jwt.InvalidTokenError:
        return False
    if payload.get('role') != 'signup' or payload.get('phone') != phone:
        return False
    with _jti_lock:
        if payload['jti'] in USED_SIGNUP_JTIS:
            return False
        USED_SIGNUP_JTIS[payload['jti']] = payload['exp']
    return True


def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def issue_session_token(user_data):
    """بنخزّن الهاش بس — لو الملفات اتسربت التوكنات متنفعش"""
    token = secrets.token_urlsafe(32)
    user_data['token_hash'] = hash_token(token)
    user_data['token_expires'] = (now_utc() + timedelta(days=SESSION_DAYS)).isoformat()
    user_data.pop('token', None)
    return token


# ==========================================
# 5. Before / After Request
# ==========================================
BLOCKED_UA = ('sqlmap', 'nikto', 'nmap', 'masscan', 'acunetix', 'nessus', 'dirbuster', 'wpscan')


@app.before_request
def guard_request():
    ip = rate_limiter.get_client_ip(request)
    if ip_blacklist.is_blacklisted(ip):
        return err('تم حظر عنوان IP مؤقتاً', 429)

    ua = request.headers.get('User-Agent', '').lower()
    if any(b in ua for b in BLOCKED_UA):
        ip_blacklist.add_suspicious(ip, f"Scanner UA: {ua[:50]}")
        return err('مرفوض', 403)

    if len(request.url) > 2000:
        ip_blacklist.add_suspicious(ip, "URL too long")
        return err('طلب غير صالح', 414)

    allowed, _ = rate_limiter.is_allowed(f"{ip}:global", RATE_LIMIT_GLOBAL, 60)
    if not allowed:
        return err('عدد كبير من الطلبات', 429)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    if request.is_secure or TRUST_PROXY:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if response.mimetype == 'application/json':
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Content-Security-Policy'] = "default-src 'none'"
    return response


ERROR_MESSAGES = {
    404: 'غير موجود', 405: 'الطريقة غير مسموحة', 413: 'حجم الطلب كبير جداً',
    414: 'طلب غير صالح', 429: 'عدد كبير من الطلبات'
}


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return err(ERROR_MESSAGES.get(e.code, 'طلب غير صالح'), e.code or 400)
    logger.exception('Unhandled error')
    return err('حصل خطأ داخلي', 500)


# ==========================================
# 6. دوال مساعدة
# ==========================================
FILE_ID_RE = re.compile(r'^[a-f0-9]{64}$')
PARTIAL_SUFFIXES = ('.meta', '.part', '.ytdl', '.tmp')


def safe_phone(phone):
    if not phone:
        return ''
    return re.sub(r'[^0-9]', '', str(phone))[:15]


def valid_phone(phone):
    return 10 <= len(phone) <= 15


def safe_username(username):
    if not username:
        return ''
    username = re.sub(r'[\x00-\x1f\x7f<>\'"`;{}&\\]', '', str(username))
    return re.sub(r'\s+', ' ', username).strip()[:50]


def clean_query(q):
    q = re.sub(r'[\x00-\x1f\x7f]', ' ', str(q or ''))
    return q.strip()[:200]


def get_platform_from_url(url):
    try:
        host = (urlparse(url).hostname or '').lower().rstrip('.')
    except ValueError:
        return 'other'
    for platform, domains in PLATFORM_DOMAINS.items():
        for d in domains:
            if host == d or host.endswith('.' + d):
                return platform
    return 'other'


def validate_url(url):
    """قايمة بيضاء بالدومينات المدعومة فقط (بتمنع SSRF وملفات محلية وخدع زي evil.com/?tiktok.com)"""
    if not isinstance(url, str) or not url or len(url) > 2000:
        return False
    try:
        p = urlparse(url.strip())
        port = p.port
    except ValueError:
        return False
    if p.scheme.lower() not in ('http', 'https'):
        return False
    if not p.hostname or p.username or p.password:
        return False
    if port not in (None, 80, 443):
        return False
    return get_platform_from_url(url) != 'other'


def format_duration(seconds):
    try:
        seconds = int(seconds)
        h, m, s = seconds // 3600, (seconds % 3600) // 60, seconds % 60
        return f"{h}:{m:02d}:{s:02d}" if h > 0 else f"{m}:{s:02d}"
    except (TypeError, ValueError):
        return '—'


def calculate_renewal_date(plan_id):
    duration = PLANS.get(plan_id, {}).get('duration_days', 0)
    if duration <= 0:
        return ''
    return (datetime.now() + timedelta(days=duration)).strftime("%Y-%m-%d")


def get_effective_listen_limit(user_data, plan_info):
    if user_data.get('listens_limit') is not None:
        try:
            return int(user_data['listens_limit'])
        except (ValueError, TypeError):
            pass
    return plan_info.get('listens_limit', 0)


def effective_plan_id(user_data):
    plan_id = user_data.get('plan', 'free')
    if plan_id not in PLANS:
        return 'free'
    if PLANS[plan_id]['duration_days'] > 0:
        rd = user_data.get('renewal_date', '')
        if rd and rd < current_day_str():
            return 'free'
    return plan_id


def normalize_user(data):
    """يصفّر العدادات اليومية/الشهرية وينزّل الباقة المنتهية تلقائياً. يرجع True لو اتغير حاجة"""
    changed = False
    today, month = current_day_str(), current_month_str()
    if data.get('last_download_date') != today:
        data['daily_downloads'] = 0
        data['last_download_date'] = today
        changed = True
    if data.get('last_listen_month') != month:
        data['monthly_listens'] = 0
        data['last_listen_month'] = month
        changed = True
    plan_id = data.get('plan', 'free')
    if plan_id in PLANS and PLANS[plan_id]['duration_days'] > 0:
        rd = data.get('renewal_date', '')
        if rd and rd < today:
            data['expired_plan'] = plan_id
            data['plan'] = 'free'
            data['renewal_date'] = ''
            data['is_cancelled'] = False
            changed = True
    return changed


def user_path(phone):
    return os.path.join(USERS_DIR, f"{phone}.json")


def new_user_record(phone, username, ip):
    return {
        'username': username, 'phone': phone, 'plan': 'free',
        'daily_downloads': 0, 'last_download_date': current_day_str(),
        'monthly_listens': 0, 'last_listen_month': current_month_str(),
        'last_ip_address': ip, 'created_at': now_str(), 'last_login': now_str(),
        'renewal_date': '', 'is_cancelled': False
    }


# ----- ملفات التحميل -----
def find_media_file(file_id):
    if not FILE_ID_RE.match(file_id or ''):
        return None
    prefix = file_id + '.'
    for f in os.listdir(DOWNLOAD_DIR):
        if f.startswith(prefix) and not f.endswith(PARTIAL_SUFFIXES):
            return f
    return None


def meta_path_for(file_id):
    return os.path.join(DOWNLOAD_DIR, f"{file_id}.meta")


def save_file_meta(file_id, meta):
    try:
        atomic_write_json(meta_path_for(file_id), meta)
    except OSError:
        logger.exception('Meta save error')


def load_file_meta(file_id):
    return read_json(meta_path_for(file_id), {}) or {}


def file_ttl_seconds(file_id):
    duration = load_file_meta(file_id).get('duration', 0) or 0
    minutes = LARGE_FILE_TTL_MINUTES if duration > LARGE_FILE_THRESHOLD_SECONDS else FILE_TTL_MINUTES
    return minutes * 60


def remove_files_for(file_id):
    for f in os.listdir(DOWNLOAD_DIR):
        if f.startswith(file_id):
            try:
                os.remove(os.path.join(DOWNLOAD_DIR, f))
            except OSError:
                pass


def pretty_filename(title, ext):
    base = re.sub(r'[\\/:*?"<>|\r\n\t]', '', str(title or '')).strip()[:80]
    return f"{base}.{ext}" if base else None


# ----- كاش ذكي: نفس الرابط + النوع = نفس الملف طالما لسه موجود -----
DOWNLOAD_CACHE = {}
_cache_lock = threading.Lock()


def cache_get(key):
    with _cache_lock:
        file_id = DOWNLOAD_CACHE.get(key)
    if file_id and find_media_file(file_id):
        return file_id
    with _cache_lock:
        DOWNLOAD_CACHE.pop(key, None)
    return None


def cache_put(key, file_id):
    with _cache_lock:
        if len(DOWNLOAD_CACHE) > 2000:
            DOWNLOAD_CACHE.clear()
        DOWNLOAD_CACHE[key] = file_id


# ----- كاش البحث (5 دقايق) -----
SEARCH_CACHE = {}
SEARCH_CACHE_TTL = 300
_search_lock = threading.Lock()


# ----- تحكم في التحميلات المتزامنة -----
DOWNLOAD_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
ACTIVE_BY_USER = defaultdict(int)
_active_lock = threading.Lock()


def acquire_user_slot(key):
    with _active_lock:
        if ACTIVE_BY_USER[key] >= MAX_CONCURRENT_PER_USER:
            return False
        ACTIVE_BY_USER[key] += 1
        return True


def release_user_slot(key):
    with _active_lock:
        ACTIVE_BY_USER[key] -= 1
        if ACTIVE_BY_USER[key] <= 0:
            del ACTIVE_BY_USER[key]


def cleanup_loop():
    while True:
        try:
            now = time.time()
            for f in os.listdir(DOWNLOAD_DIR):
                fp = os.path.join(DOWNLOAD_DIR, f)
                if not os.path.isfile(fp):
                    continue
                file_id = f.split('.')[0]
                age = now - os.path.getmtime(fp)
                if f.endswith('.meta'):
                    if find_media_file(file_id) is None and age > 300:
                        os.remove(fp)
                elif f.endswith(PARTIAL_SUFFIXES):
                    if age > 3600:
                        os.remove(fp)
                elif age > file_ttl_seconds(file_id):
                    remove_files_for(file_id)

            ip_blacklist.cleanup()
            rate_limiter.purge()

            with OTP_LOCK:
                for phone in [p for p, e in PENDING_OTPS.items() if e['expires'] < now]:
                    del PENDING_OTPS[phone]
            with _jti_lock:
                for store in (REVOKED_JTIS, USED_SIGNUP_JTIS):
                    for jti in [j for j, exp in store.items() if exp < now]:
                        del store[jti]
            today = current_day_str()
            for ip in [i for i, g in list(GUESTS.items()) if g.get('last_download_date') != today]:
                GUESTS.pop(ip, None)
            with _search_lock:
                for k in [k for k, (ts, _) in SEARCH_CACHE.items() if now - ts > SEARCH_CACHE_TTL]:
                    del SEARCH_CACHE[k]
        except Exception:
            logger.exception('cleanup error')
        time.sleep(CLEANUP_INTERVAL)


# ==========================================
# 7. الضيوف + الحصص (ذرّية)
# ==========================================
GUESTS = {}   # ip -> بيانات الضيف (قبل كده كانت بتتصفّر كل طلب = تحميل لا نهائي!)


def new_guest():
    return {'plan': 'guest', 'daily_downloads': 0, 'last_download_date': current_day_str(),
            'monthly_listens': 0, 'last_listen_month': current_month_str()}


def authenticate_user(req_data, req_headers, client_ip):
    """يرجع (ok, user_data, file_path, error)"""
    user_type = req_data.get('user_type', 'guest')

    if user_type == 'guest':
        with lock_for(f'guest:{client_ip}'):
            if len(GUESTS) > 50000:
                GUESTS.clear()
            g = GUESTS.setdefault(client_ip, new_guest())
            normalize_user(g)
            return True, dict(g), None, None

    auth_header = req_headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return False, None, None, 'غير مصرح لك.'
    token = auth_header.split(' ', 1)[1].strip()

    phone = safe_phone(req_data.get('phone', ''))
    if not valid_phone(phone):
        return False, None, None, 'بيانات الحساب غير مكتملة.'

    path = user_path(phone)
    user_data = read_json(path)
    if not isinstance(user_data, dict):
        return False, None, None, 'غير مصرح لك.'

    stored = user_data.get('token_hash')
    if not stored or not hmac.compare_digest(stored, hash_token(token)):
        return False, None, None, 'انتهت صلاحية الجلسة.'

    expires = user_data.get('token_expires')
    if expires:
        try:
            if now_utc() > datetime.fromisoformat(expires):
                return False, None, None, 'انتهت صلاحية الجلسة.'
        except ValueError:
            return False, None, None, 'انتهت صلاحية الجلسة.'

    return True, user_data, path, None


def _apply_quota(data, kind, platform):
    normalize_user(data)
    plan = PLANS[effective_plan_id(data)]

    if platform and platform != 'all' and platform not in plan['platforms']:
        verb = 'الاستماع' if kind == 'stream' else 'التحميل'
        return False, f"باقتك ({plan['name']}) لا تدعم {verb} من هذا الموقع."

    if kind == 'stream':
        limit = get_effective_listen_limit(data, plan)
        if limit == 0:
            return False, "الاستماع متاح فقط للحسابات المسجلة."
        if limit != -1 and data.get('monthly_listens', 0) >= limit:
            return False, f"لقد استنفدت الحد الأقصى ({limit} استماع) لباقتك."
        data['monthly_listens'] = data.get('monthly_listens', 0) + 1
    else:
        limit = plan['limit']
        if limit != -1 and data.get('daily_downloads', 0) >= limit:
            return False, f"لقد استنفدت الحد الأقصى ({limit} تحميلات) لباقتك اليوم."
        data['daily_downloads'] = data.get('daily_downloads', 0) + 1
    return True, None


def reserve_quota(path, ip, kind, platform):
    """يتحقق ويحجز الحصة في خطوة واحدة تحت قفل — بيمنع تخطي الحد بطلبات متوازية"""
    if path is None:
        with lock_for(f'guest:{ip}'):
            g = GUESTS.setdefault(ip, new_guest())
            return _apply_quota(g, kind, platform)
    with lock_for(path):
        data = read_json(path)
        if not isinstance(data, dict):
            return False, 'الحساب غير موجود.'
        ok, msg = _apply_quota(data, kind, platform)
        atomic_write_json(path, data)
        return ok, msg


def refund_quota(path, ip, kind):
    """لو التحميل فشل منخصمش من رصيد المستخدم"""
    field = 'monthly_listens' if kind == 'stream' else 'daily_downloads'
    if path is None:
        with lock_for(f'guest:{ip}'):
            g = GUESTS.get(ip)
            if g:
                g[field] = max(0, g.get(field, 0) - 1)
        return
    with lock_for(path):
        data = read_json(path)
        if isinstance(data, dict):
            data[field] = max(0, data.get(field, 0) - 1)
            atomic_write_json(path, data)


# ==========================================
# 8. OTP / تسجيل الدخول
# ==========================================
PENDING_OTPS = {}
OTP_LOCK = threading.Lock()


def hash_otp(phone, otp):
    return hmac.new(JWT_SECRET.encode(), f"{phone}:{otp}".encode(), hashlib.sha256).hexdigest()


def send_whatsapp_message(phone_number, text_message):
    try:
        headers = {'X-API-Key': WHATSAPP_API_KEY} if WHATSAPP_API_KEY else {}
        r = requests.post(WHATSAPP_API_URL, json={"number": phone_number, "message": text_message},
                          headers=headers, timeout=10)
        return r.status_code == 200 and r.json().get('success')
    except (requests.RequestException, ValueError):
        logger.warning('WhatsApp gateway error')
        return False


@app.route('/send-otp', methods=['POST'])
@rate_limit(limit=RATE_LIMIT_AUTH, window=60, key_suffix='otp')
def send_otp():
    ip = rate_limiter.get_client_ip(request)
    phone = safe_phone(get_body().get('phone'))
    if not valid_phone(phone):
        log_otp_event(phone or 'unknown', 'send', 'failed', 'رقم غير صحيح', ip)
        return err('رقم التليفون غير صحيح', 400)

    # حد لكل رقم (بيمنع إغراق رقم حد برسايل واتساب من IPs مختلفة)
    allowed, _ = rate_limiter.is_allowed(f"otp_phone:{phone}", OTP_PER_PHONE_HOURLY, 3600)
    if not allowed:
        log_otp_event(phone, 'send', 'failed', 'تجاوز الحد الساعي', ip)
        return err('تجاوزت عدد المحاولات المسموح. حاول بعد ساعة', 429)

    with OTP_LOCK:
        existing = PENDING_OTPS.get(phone)
        if existing:
            wait = OTP_RESEND_COOLDOWN - (time.time() - existing['sent_at'])
            if wait > 0:
                return err(f'استنى {int(wait) + 1} ثانية قبل إعادة الإرسال', 429)

    otp_code = str(secrets.randbelow(900000) + 100000)
    msg = f"أهلاً بك في Link2Go،\nكود التحقق الخاص بك هو: *{otp_code}*\nصالح لمدة 5 دقائق."
    if not send_whatsapp_message(phone, msg):
        log_otp_event(phone, 'send', 'failed', 'فشل إرسال واتساب', ip)
        return err('فشل إرسال الكود', 502)

    with OTP_LOCK:
        PENDING_OTPS[phone] = {
            'hash': hash_otp(phone, otp_code), 'ip': ip,
            'sent_at': time.time(), 'expires': time.time() + OTP_TTL_SECONDS, 'attempts': 0
        }
    log_otp_event(phone, 'send', 'success', None, ip)
    return jsonify({'success': True, 'message': 'تم إرسال الكود', 'expires_in': OTP_TTL_SECONDS})


@app.route('/verify-otp', methods=['POST'])
@rate_limit(limit=RATE_LIMIT_AUTH, window=60, key_suffix='otp_verify')
def verify_otp():
    ip = rate_limiter.get_client_ip(request)
    data = get_body()
    phone = safe_phone(data.get('phone'))
    otp_input = str(data.get('otp', '')).strip()

    if not valid_phone(phone) or not re.fullmatch(r'\d{6}', otp_input):
        log_otp_event(phone or 'unknown', 'verify', 'failed', 'بيانات غير صحيحة', ip)
        return err('البيانات غير صحيحة', 400)

    with OTP_LOCK:
        entry = PENDING_OTPS.get(phone)
        if not entry or entry['expires'] < time.time():
            PENDING_OTPS.pop(phone, None)
            log_otp_event(phone, 'verify', 'failed', 'جلسة منتهية', ip)
            return err('انتهت صلاحية الكود. اطلب كود جديد', 404)

        entry['attempts'] += 1
        matched = hmac.compare_digest(entry['hash'], hash_otp(phone, otp_input))
        if matched:
            del PENDING_OTPS[phone]
        elif entry['attempts'] >= OTP_MAX_ATTEMPTS:
            del PENDING_OTPS[phone]
            log_otp_event(phone, 'verify', 'failed', 'تجاوز محاولات التحقق', ip)
            ip_blacklist.add_suspicious(ip, 'OTP brute force')
            return err('تجاوزت عدد المحاولات. اطلب كود جديد', 429)

    if not matched:
        log_otp_event(phone, 'verify', 'failed', 'كود غلط', ip)
        return err('الرمز غير صحيح', 400)

    path = user_path(phone)
    with lock_for(path):
        saved = read_json(path)
        if isinstance(saved, dict):
            saved['last_login'] = now_str()
            saved['last_ip_address'] = ip
            token = issue_session_token(saved)
            atomic_write_json(path, saved)
            log_otp_event(phone, 'verify', 'success', None, ip)
            log_login_event(phone, saved.get('username', ''), 'otp_login', 'success', None, ip)
            return jsonify({'success': True, 'is_new': False,
                            'username': saved.get('username', 'مستخدم'),
                            'phone': phone, 'token': token})

    log_otp_event(phone, 'verify', 'success', 'مستخدم جديد', ip)
    return jsonify({'success': True, 'is_new': True, 'phone': phone,
                    'signup_token': create_signup_token(phone)})


@app.route('/update-username', methods=['POST'])
@rate_limit(limit=10, window=60, key_suffix='update_user')
def update_username():
    """
    - مستخدم جديد: لازم signup_token طالع من verify-otp (قبل كده أي حد كان يقدر ياخد حساب أي رقم!)
    - مستخدم موجود: لازم Bearer token بتاعه
    """
    ip = rate_limiter.get_client_ip(request)
    data = get_body()
    phone = safe_phone(data.get('phone'))
    username = safe_username(data.get('username'))

    if not valid_phone(phone) or len(username) < 2:
        return err('البيانات غير صحيحة', 400)

    path = user_path(phone)
    signup_token = data.get('signup_token')

    if signup_token:
        if not consume_signup_token(signup_token, phone):
            return err('انتهت صلاحية التسجيل. أعد التحقق من الرقم', 401)
        with lock_for(path):
            if os.path.exists(path):
                return err('الحساب موجود بالفعل، سجّل دخول', 409)
            user_data = new_user_record(phone, username, ip)
            token = issue_session_token(user_data)
            atomic_write_json(path, user_data)
        log_login_event(phone, username, 'signup', 'success', None, ip)
    else:
        ok, _, _, msg = authenticate_user({'user_type': 'user', 'phone': phone}, request.headers, ip)
        if not ok:
            return err(msg, 401)
        with lock_for(path):
            user_data = read_json(path)
            if not isinstance(user_data, dict):
                return err('الحساب غير موجود', 404)
            user_data['username'] = username
            user_data['last_ip_address'] = ip
            token = issue_session_token(user_data)
            atomic_write_json(path, user_data)

    return jsonify({'success': True, 'username': username, 'phone': phone, 'token': token})


@app.route('/logout', methods=['POST'])
@rate_limit(limit=20, window=60, key_suffix='logout')
def logout():
    ip = rate_limiter.get_client_ip(request)
    ok, user, path, msg = authenticate_user(get_body(), request.headers, ip)
    if not ok or not path:
        return err(msg or 'غير مصرح', 401)
    with lock_for(path):
        data = read_json(path)
        if isinstance(data, dict):
            data.pop('token_hash', None)
            data.pop('token_expires', None)
            atomic_write_json(path, data)
    log_login_event(user.get('phone'), user.get('username'), 'logout', 'success', None, ip)
    return jsonify({'success': True})


# ==========================================
# 9. Admin Login
# ==========================================
def check_admin_credentials(username, password):
    u_ok = hmac.compare_digest(username.encode('utf-8'), ADMIN_USERNAME.encode('utf-8'))
    if ADMIN_PASSWORD_HASH:
        p_ok = check_password_hash(ADMIN_PASSWORD_HASH, password)
    else:
        p_ok = hmac.compare_digest(password.encode('utf-8'), ADMIN_PASSWORD.encode('utf-8'))
    return u_ok and p_ok


@app.route('/admin-login', methods=['POST'])
@rate_limit(limit=RATE_LIMIT_LOGIN, window=300, key_suffix='admin_login')
def admin_login():
    ip = rate_limiter.get_client_ip(request)
    data = get_body()
    username = str(data.get('username', ''))[:100]
    password = str(data.get('password', ''))[:200]

    if not username or not password:
        return err('البيانات ناقصة', 400)

    if not check_admin_credentials(username, password):
        ip_blacklist.add_suspicious(ip, 'Failed admin login')
        log_login_event('admin', safe_username(username), 'admin_login', 'failed', 'بيانات غلط', ip)
        return err('بيانات الدخول غير صحيحة', 401)

    log_login_event('admin', username, 'admin_login', 'success', None, ip)
    return jsonify({'success': True, 'token': generate_admin_token(),
                    'username': ADMIN_USERNAME, 'expires_in_hours': ADMIN_TOKEN_HOURS})


@app.route('/admin-logout', methods=['POST'])
@admin_required
def admin_logout():
    _, _, payload = verify_admin_token(request)
    with _jti_lock:
        REVOKED_JTIS[payload['jti']] = payload['exp']
    return jsonify({'success': True})


@app.route('/admin-verify', methods=['POST'])
@admin_required
def admin_verify():
    return jsonify({'success': True, 'username': ADMIN_USERNAME})


# ==========================================
# 10. بروفايل المستخدم والباقات
# ==========================================
@app.route('/get-profile', methods=['POST'])
@rate_limit(limit=60, window=60, key_suffix='profile')
def get_profile():
    ip = rate_limiter.get_client_ip(request)
    ok, user_data, path, msg = authenticate_user(get_body(), request.headers, ip)
    if not ok:
        return err(msg, 401)

    if path:
        with lock_for(path):
            fresh = read_json(path)
            if not isinstance(fresh, dict):
                return err('الحساب غير موجود', 401)
            changed = normalize_user(fresh)
            info = PLANS[effective_plan_id(fresh)]
            if not fresh.get('renewal_date') and info['duration_days'] > 0:
                fresh['renewal_date'] = calculate_renewal_date(fresh.get('plan'))
                changed = True
            if changed:
                atomic_write_json(path, fresh)
            user_data = fresh

    plan_id = effective_plan_id(user_data)
    plan_info = PLANS[plan_id]
    return jsonify({
        'success': True,
        'user': {
            'username': user_data.get('username', 'زائر'),
            'phone': user_data.get('phone', ''),
            'plan_id': plan_id,
            'plan_name': plan_info['name'],
            'platforms': plan_info['platforms'],
            'daily_downloads': user_data.get('daily_downloads', 0),
            'limit': plan_info['limit'],
            'monthly_listens': user_data.get('monthly_listens', 0),
            'listens_limit': get_effective_listen_limit(user_data, plan_info),
            'listens_period': plan_info.get('listens_period', 'monthly'),
            'renewal_date': user_data.get('renewal_date', ''),
            'is_cancelled': user_data.get('is_cancelled', False),
            'expired_plan': user_data.get('expired_plan', '')
        }
    })


@app.route('/get-plans', methods=['GET'])
@rate_limit(limit=30, window=60, key_suffix='get_plans')
def get_plans():
    result = {}
    for plan_id, info in PLANS.items():
        if plan_id == 'guest':
            continue
        result[plan_id] = {
            'id': plan_id, 'name': info['name'], 'platforms': info['platforms'],
            'limit': info['limit'], 'listens_limit': info.get('listens_limit', 0),
            'duration_days': info.get('duration_days', 0), 'price': info.get('price', 0),
            'duration_label': info.get('duration_label', '')
        }
    return jsonify({'success': True, 'plans': result})


@app.route('/request-upgrade', methods=['POST'])
@rate_limit(limit=10, window=300, key_suffix='upgrade')
def request_upgrade():
    ip = rate_limiter.get_client_ip(request)
    data = get_body()
    ok, _, path, msg = authenticate_user(data, request.headers, ip)
    if not ok or not path:
        return err(msg or 'سجّل دخول الأول', 401)

    requested = data.get('plan', '')
    if requested not in PLANS or requested in ('guest', 'free'):
        return err('باقة غير معروفة', 400)

    with lock_for(path):
        user_data = read_json(path)
        if not isinstance(user_data, dict):
            return err('الحساب غير موجود', 404)
        user_data['upgrade_requested'] = requested
        user_data['upgrade_request_date'] = now_str()
        atomic_write_json(path, user_data)
    return jsonify({'success': True})


@app.route('/cancel-plan', methods=['POST'])
@rate_limit(limit=5, window=300, key_suffix='cancel')
def cancel_plan():
    ip = rate_limiter.get_client_ip(request)
    ok, _, path, msg = authenticate_user(get_body(), request.headers, ip)
    if not ok or not path:
        return err(msg or 'سجّل دخول الأول', 401)

    with lock_for(path):
        user_data = read_json(path)
        if not isinstance(user_data, dict):
            return err('الحساب غير موجود', 404)
        user_data['is_cancelled'] = True
        user_data['cancelled_at'] = now_str()
        atomic_write_json(path, user_data)
    return jsonify({'success': True})


# ==========================================
# 11. إدارة المستخدمين (أدمن)
# ==========================================
def _admin_user_view(data, phone_fallback=''):
    plan_id = data.get('plan', 'free')
    plan_info = PLANS.get(plan_id, PLANS['free'])
    return {
        'phone': data.get('phone', phone_fallback), 'username': data.get('username', ''),
        'plan_id': plan_id, 'plan_name': plan_info.get('name', plan_id),
        'platforms': plan_info.get('platforms', []),
        'limit': plan_info.get('limit', 0), 'listens_limit': plan_info.get('listens_limit', 0),
        'daily_downloads': data.get('daily_downloads', 0),
        'monthly_listens': data.get('monthly_listens', 0),
        'renewal_date': data.get('renewal_date', ''),
        'is_cancelled': data.get('is_cancelled', False),
        'upgrade_requested': data.get('upgrade_requested', ''),
        'created_at': data.get('created_at', ''), 'last_login': data.get('last_login', '')
    }


@app.route('/users-list', methods=['GET'])
@admin_required
def users_list():
    users = []
    for filename in os.listdir(USERS_DIR):
        if not filename.endswith('.json'):
            continue
        data = read_json(os.path.join(USERS_DIR, filename))
        if isinstance(data, dict):
            users.append(_admin_user_view(data, filename[:-5]))
    return jsonify({'success': True, 'count': len(users), 'users': users})


@app.route('/user/<phone>', methods=['GET'])
@admin_required
def get_user(phone):
    phone = safe_phone(phone)
    data = read_json(user_path(phone)) if phone else None
    if not isinstance(data, dict):
        return err('المستخدم غير موجود', 404)
    return jsonify({'success': True, 'user': _admin_user_view(data, phone)})


@app.route('/user/<phone>', methods=['DELETE'])
@admin_required
def delete_user(phone):
    phone = safe_phone(phone)
    if not valid_phone(phone):
        return err('رقم غير صالح', 400)
    path = user_path(phone)
    with lock_for(path):
        if not os.path.exists(path):
            return err('المستخدم غير موجود', 404)
        os.remove(path)
    audit('delete_user', phone)
    return jsonify({'success': True, 'message': f'تم حذف المستخدم {phone}'})


@app.route('/user/<phone>/set-plan', methods=['POST'])
@admin_required
def set_user_plan(phone):
    new_plan = get_body().get('plan')
    if new_plan not in PLANS or new_plan == 'guest':
        return err('باقة غير معروفة', 400)

    phone = safe_phone(phone)
    path = user_path(phone)
    with lock_for(path):
        user_data = read_json(path)
        if not isinstance(user_data, dict):
            return err('المستخدم غير موجود', 404)
        user_data['plan'] = new_plan
        user_data['is_cancelled'] = False
        user_data['renewal_date'] = calculate_renewal_date(new_plan)
        user_data.pop('expired_plan', None)
        user_data.pop('upgrade_requested', None)
        user_data['updated_at'] = now_str()
        atomic_write_json(path, user_data)

    audit('set_plan', f'{phone}->{new_plan}')
    return jsonify({'success': True, 'message': f'تم تغيير الباقة إلى {PLANS[new_plan]["name"]}',
                    'plan_id': new_plan, 'plan_name': PLANS[new_plan]['name'],
                    'renewal_date': user_data['renewal_date']})


def _parse_counter(value):
    try:
        return max(0, min(10_000_000, int(value)))
    except (TypeError, ValueError):
        return None


@app.route('/user/<phone>/set-counters', methods=['POST'])
@admin_required
def set_user_counters(phone):
    data = get_body()
    phone = safe_phone(phone)
    path = user_path(phone)

    updates = {}
    for field in ('daily_downloads', 'monthly_listens'):
        if data.get(field) is not None:
            val = _parse_counter(data[field])
            if val is None:
                return err('قيمة غير صحيحة', 400)
            updates[field] = val

    if 'renewal_date' in data:
        val = str(data['renewal_date'] or '').strip()
        if val:
            try:
                datetime.strptime(val, '%Y-%m-%d')
            except ValueError:
                return err('صيغة التاريخ YYYY-MM-DD', 400)
        updates['renewal_date'] = val

    clear_listens = False
    if 'listens_limit' in data:
        val = data['listens_limit']
        if val is None or val == '':
            clear_listens = True
        else:
            try:
                updates['listens_limit'] = max(-1, min(10_000_000, int(val)))
            except (ValueError, TypeError):
                return err('قيمة غير صحيحة', 400)

    with lock_for(path):
        user_data = read_json(path)
        if not isinstance(user_data, dict):
            return err('المستخدم غير موجود', 404)
        user_data.update(updates)
        if clear_listens:
            user_data.pop('listens_limit', None)
            updates['listens_limit'] = None
        user_data['updated_at'] = now_str()
        atomic_write_json(path, user_data)

    audit('set_counters', phone)
    return jsonify({'success': True, 'message': 'تم التحديث', 'changes': updates})


@app.route('/admin-set-listen-limit', methods=['POST'])
@admin_required
def admin_set_listen_limit():
    data = get_body()
    phone = safe_phone(data.get('phone'))
    if not valid_phone(phone):
        return err('رقم الهاتف مطلوب', 400)

    limit = data.get('listens_limit')
    if limit is not None:
        try:
            limit = max(-1, min(10_000_000, int(limit)))
        except (ValueError, TypeError):
            return err('قيمة غير صحيحة', 400)

    path = user_path(phone)
    with lock_for(path):
        user_data = read_json(path)
        if not isinstance(user_data, dict):
            return err('المستخدم غير موجود', 404)
        if limit is None:
            user_data.pop('listens_limit', None)
            msg = 'تم مسح الحد المخصص'
        else:
            user_data['listens_limit'] = limit
            msg = f'تم تحديد الحد = {limit}'
        atomic_write_json(path, user_data)

    audit('set_listen_limit', phone)
    return jsonify({'success': True, 'message': msg,
                    'listens_limit': user_data.get('listens_limit', 'default')})


# ==========================================
# 12. السجلات (أدمن)
# ==========================================
@app.route('/history', methods=['GET'])
@admin_required
def get_history():
    history_type = request.args.get('type', 'all')
    limit = safe_int(request.args.get('limit'), 200, 1, 500)
    sources = {'links': LINKS_HISTORY_FILE, 'otp': OTP_HISTORY_FILE, 'login': LOGIN_HISTORY_FILE}

    result = {}
    for name, path in sources.items():
        if history_type in ('all', name):
            items = load_history(path)
            result[name] = list(reversed(items))[:limit]
            result[f'{name}_count'] = len(items)
    return jsonify({'success': True, 'max_entries': HISTORY_MAX_ENTRIES, 'data': result})


@app.route('/history/clear', methods=['POST'])
@admin_required
def clear_history():
    history_type = get_body().get('type', 'all')
    sources = {'links': LINKS_HISTORY_FILE, 'otp': OTP_HISTORY_FILE, 'login': LOGIN_HISTORY_FILE}
    cleared = []
    with HISTORY_LOCK:
        for name, path in sources.items():
            if history_type in ('all', name):
                save_history(path, [])
                cleared.append(name)
    audit('clear_history', ','.join(cleared))
    return jsonify({'success': True, 'cleared': cleared, 'message': 'تم مسح السجل'})


# ==========================================
# 13. الملفات
# ==========================================
@app.route('/files-list', methods=['GET'])
@admin_required   # كانت مفتوحة للكل وبتكشف أرقام وأسماء المستخدمين!
def files_list():
    files = []
    for filename in os.listdir(DOWNLOAD_DIR):
        if filename.endswith(PARTIAL_SUFFIXES):
            continue
        filepath = os.path.join(DOWNLOAD_DIR, filename)
        if not os.path.isfile(filepath):
            continue
        stat = os.stat(filepath)
        file_id = filename.split('.')[0]
        meta = load_file_meta(file_id)
        duration = meta.get('duration', 0) or 0
        is_large = duration > LARGE_FILE_THRESHOLD_SECONDS
        files.append({
            'file_id': file_id, 'filename': filename, 'title': meta.get('title', ''),
            'download_url': f'/file/{file_id}', 'inline_url': f'/file/{file_id}?inline=true',
            'size_bytes': stat.st_size, 'size_mb': round(stat.st_size / (1024 * 1024), 2),
            'created_at': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            'duration_seconds': duration,
            'duration_label': format_duration(duration) if duration else '—',
            'is_large': is_large,
            'ttl_minutes': LARGE_FILE_TTL_MINUTES if is_large else FILE_TTL_MINUTES,
            'requested_by': {'username': meta.get('username', 'مجهول'),
                             'phone': meta.get('phone', '—'), 'type': meta.get('type', 'audio')}
        })
    files.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({'success': True, 'count': len(files), 'files': files})


@app.route('/file/<file_id>/delete', methods=['DELETE'])
@admin_required
def delete_file(file_id):
    if not FILE_ID_RE.match(file_id or ''):
        return err('معرف غير صالح', 400)
    if not find_media_file(file_id):
        return err('الملف غير موجود', 404)
    remove_files_for(file_id)
    with _cache_lock:
        for k in [k for k, v in DOWNLOAD_CACHE.items() if v == file_id]:
            del DOWNLOAD_CACHE[k]
    audit('delete_file', file_id[:12])
    return jsonify({'success': True, 'message': 'تم الحذف'})


MIMETYPES = {'mp4': 'video/mp4', 'mp3': 'audio/mpeg', 'webm': 'video/webm',
             'm4a': 'audio/mp4', 'wav': 'audio/wav', 'ogg': 'audio/ogg', 'mkv': 'video/x-matroska'}


@app.route('/file/<file_id>', methods=['GET'])
@rate_limit(limit=120, window=60, key_suffix='get_file')
def get_file(file_id):
    filename = find_media_file(file_id)   # مطابقة صارمة: 64 hex بالظبط
    if not filename:
        return err('الملف غير موجود', 404)

    inline = request.args.get('inline', 'false').lower() == 'true'
    ext = filename.rsplit('.', 1)[-1].lower()
    meta = load_file_meta(file_id)
    download_name = pretty_filename(meta.get('title'), ext) or filename

    # conditional=True بيفعّل Range requests (التقديم والتأخير في المشغّل)
    response = send_file(os.path.join(DOWNLOAD_DIR, filename), as_attachment=not inline,
                         download_name=download_name,
                         mimetype=MIMETYPES.get(ext, 'application/octet-stream'),
                         conditional=True, max_age=0)
    response.headers['Cache-Control'] = 'private, max-age=300'
    return response


# ==========================================
# 14. البحث والتحميل
# ==========================================
def _search_platform(search_query, source_name):
    now = time.time()
    with _search_lock:
        cached = SEARCH_CACHE.get(search_query)
        if cached and now - cached[0] < SEARCH_CACHE_TTL:
            return list(cached[1])

    ydl_opts = {'quiet': True, 'no_warnings': True, 'extract_flat': True,
                'skip_download': True, 'socket_timeout': 15}
    results = []
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(search_query, download=False)
        for entry in (info.get('entries', []) if info else []):
            if not entry:
                continue
            url = entry.get('url') or entry.get('webpage_url')
            if not url and entry.get('id') and source_name == 'youtube':
                url = f"https://www.youtube.com/watch?v={entry['id']}"
            if not url or not validate_url(url):
                continue
            duration = entry.get('duration')
            results.append({
                'title': str(entry.get('title') or 'بدون عنوان')[:200], 'url': url,
                'duration': format_duration(duration) if duration else '—',
                'thumbnail': entry.get('thumbnail') or '',
                'uploader': str(entry.get('uploader') or entry.get('channel') or '')[:100],
                'source': source_name,
            })
    except Exception:
        logger.warning('search failed for %s', source_name)
        return []

    with _search_lock:
        if len(SEARCH_CACHE) > 500:
            SEARCH_CACHE.clear()
        SEARCH_CACHE[search_query] = (now, results)
    return list(results)


def _run_search(query, source, plan, limit):
    results = []
    if source in ('all', 'soundcloud'):
        results.extend(_search_platform(f"scsearch{limit}:{query}", 'soundcloud'))
    if source in ('all', 'youtube') and 'youtube' in plan['platforms']:
        results.extend(_search_platform(f"ytsearch{limit}:{query}", 'youtube'))
    return results


@app.route('/search', methods=['POST'])
@rate_limit(limit=RATE_LIMIT_SEARCH, window=60, key_suffix='search')
def search_media():
    data = get_body()
    ip = rate_limiter.get_client_ip(request)
    ok, user_data, _, msg = authenticate_user(data, request.headers, ip)
    if not ok:
        return err(msg, 401)

    query = clean_query(data.get('query'))
    if not query:
        return err('اكتب كلمة البحث', 400)

    source = data.get('source', 'all')
    if source not in ('all', 'soundcloud', 'youtube'):
        return err('مصدر غير مدعوم', 400)

    plan = PLANS[effective_plan_id(user_data)]
    if source == 'youtube' and 'youtube' not in plan['platforms']:
        return err('البحث في يوتيوب متاح للباقة الشهرية فقط.', 403)

    results = _run_search(query, source, plan, safe_int(data.get('limit'), 5, 1, 20))
    if not results:
        return err('مفيش نتائج', 404)
    return jsonify({'success': True, 'query': query, 'count': len(results), 'results': results})


def _file_response(file_id, filename, download_type, action, duration):
    return jsonify({
        'success': True, 'file_id': file_id, 'filename': filename,
        'download_url': f'/file/{file_id}', 'inline_url': f'/file/{file_id}?inline=true',
        'type': download_type, 'action': action, 'duration': duration,
        'is_large': duration > LARGE_FILE_THRESHOLD_SECONDS
    })


@app.route('/download', methods=['POST'])
@rate_limit(limit=RATE_LIMIT_DOWNLOAD, window=60, key_suffix='download')
def download_video():
    data = get_body()
    ip = rate_limiter.get_client_ip(request)

    ok, user_data, path, msg = authenticate_user(data, request.headers, ip)
    if not ok:
        return err(msg, 401)

    url = data.get('url')
    url = url.strip() if isinstance(url, str) else None
    query = clean_query(data.get('query'))
    if not url and not query:
        return err('الرابط مطلوب', 400)
    if url and not validate_url(url):
        return err('الرابط غير صالح أو الموقع غير مدعوم', 400)

    action = str(data.get('action', 'download')).lower()
    if action not in ('stream', 'download'):
        action = 'download'
    download_type = data.get('type', 'video')
    if download_type not in ('audio', 'video'):
        download_type = 'video'

    log_phone = user_data.get('phone', 'guest')
    log_username = user_data.get('username', 'زائر')
    plan = PLANS[effective_plan_id(user_data)]

    # البحث بالاسم
    if not url:
        source = data.get('source', 'soundcloud')
        if source not in ('all', 'soundcloud', 'youtube'):
            return err('مصدر غير مدعوم', 400)
        if source == 'youtube' and 'youtube' not in plan['platforms']:
            return err('يوتيوب متاح للباقة الشهرية فقط.', 403)
        results = _run_search(query, source, plan, 1)
        if not results:
            log_link_event(log_phone, log_username, query, action, 'failed', 'مفيش نتائج', ip)
            return err('مفيش نتائج', 404)
        url = results[0]['url']

    # حجز الحصة بشكل ذرّي (بعد معرفة المنصة الفعلية للرابط)
    platform = get_platform_from_url(url)
    allowed, quota_err = reserve_quota(path, ip, action, platform)
    if not allowed:
        log_link_event(log_phone, log_username, url, action, 'quota', quota_err, ip)
        return err(quota_err, 403, quota_type='listens' if action == 'stream' else 'downloads')

    # كاش: نفس الرابط اتحمّل قبل كده ولسه موجود → مفيش تحميل تاني
    cache_key = hashlib.sha256(f"{url}|{download_type}".encode()).hexdigest()
    cached_id = cache_get(cache_key)
    if cached_id:
        fname = find_media_file(cached_id)
        if fname:
            meta = load_file_meta(cached_id)
            log_link_event(log_phone, log_username, url, action, 'success', 'cache', ip)
            return _file_response(cached_id, fname, download_type, action, meta.get('duration', 0) or 0)

    # حماية الموارد
    slot_key = log_phone if path else f"ip:{ip}"
    if shutil.disk_usage(DOWNLOAD_DIR).free < MIN_FREE_DISK_GB * 1024 ** 3:
        refund_quota(path, ip, action)
        logger.error('Low disk space')
        return err('الخدمة مشغولة حالياً، حاول بعد شوية', 503)
    if not acquire_user_slot(slot_key):
        refund_quota(path, ip, action)
        return err('عندك تحميلات شغالة بالفعل، استنى لما تخلص', 429)
    if not DOWNLOAD_SLOTS.acquire(timeout=20):
        release_user_slot(slot_key)
        refund_quota(path, ip, action)
        return err('السيرفر مشغول، حاول بعد لحظات', 503)

    file_id = uuid.uuid4().hex + uuid.uuid4().hex
    ydl_opts = {
        'outtmpl': os.path.join(DOWNLOAD_DIR, f'{file_id}.%(ext)s'),
        'quiet': True, 'no_warnings': True, 'restrictfilenames': True,
        'socket_timeout': 30, 'retries': 3, 'noplaylist': True,
        'max_filesize': MAX_FILE_MB * 1024 * 1024,
        'match_filter': match_filter_func(f"duration <=? {MAX_DURATION_SECONDS} & !is_live"),
    }
    if download_type == 'audio':
        ydl_opts['format'] = 'bestaudio/best'
        ydl_opts['postprocessors'] = [{'key': 'FFmpegExtractAudio',
                                       'preferredcodec': 'mp3', 'preferredquality': '192'}]
    else:
        h = MAX_VIDEO_HEIGHT
        ydl_opts['format'] = f'bestvideo[height<={h}]+bestaudio/best[height<={h}]/best'
        ydl_opts['merge_output_format'] = 'mp4'

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=True)

        filename = find_media_file(file_id)
        if not info or not filename:
            raise ValueError('no output file (too long / too large / blocked)')

        duration = int(info.get('duration') or 0)
        save_file_meta(file_id, {
            'duration': duration, 'title': str(info.get('title') or '')[:200],
            'username': log_username, 'phone': log_phone,
            'type': download_type, 'action': action, 'created_at': now_str()
        })
        cache_put(cache_key, file_id)
        log_link_event(log_phone, log_username, url, action, 'success', None, ip)
        return _file_response(file_id, filename, download_type, action, duration)

    except Exception as e:
        logger.warning('download failed: %s', str(e)[:300])
        remove_files_for(file_id)
        refund_quota(path, ip, action)
        log_link_event(log_phone, log_username, url, action, 'failed', str(e)[:200], ip)
        return err('تعذّر تحميل الرابط. تأكد إنه عام وغير محمي وإن مدته/حجمه ضمن الحد المسموح', 502)
    finally:
        DOWNLOAD_SLOTS.release()
        release_user_slot(slot_key)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


# ==========================================
# 15. التشغيل
# ==========================================
_bg_started = False


def start_background_tasks():
    """بتشتغل مرة واحدة حتى لو التطبيق اتشغّل بـ gunicorn"""
    global _bg_started
    if not _bg_started:
        _bg_started = True
        threading.Thread(target=cleanup_loop, daemon=True, name='cleanup').start()


start_background_tasks()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=3000, debug=False)
