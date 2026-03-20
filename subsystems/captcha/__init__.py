import random
import string
import threading
import time
from urllib.parse import urlparse, urljoin

from capjs_server import CapServer
from flask import request, session

characters = string.ascii_letters + string.digits

SESSION_MAX_AGE_SEC = 43200
RATE_LIMIT_THRESHOLD = 30
RATE_LIMIT_WINDOW = 60
TOKEN_EXPIRY_SEC = 600

cap = CapServer(
    secret_key=''.join(random.choices(characters, k=64)),
    challenge_difficulty=5,
    challenge_count=32,
    challenge_size=32,
)

used_tokens = {}
token_lock = threading.Lock()
rate_limit_data = {}
rate_lock = threading.Lock()


def cleanup_task():
    while True:
        time.sleep(60)
        now = time.time()

        with token_lock:
            expired = [t for t, ts in used_tokens.items() if now - ts > TOKEN_EXPIRY_SEC]
            for t in expired:
                del used_tokens[t]

        with rate_lock:
            for ip in list(rate_limit_data.keys()):
                rate_limit_data[ip] = [t for t in rate_limit_data[ip] if now - t <= RATE_LIMIT_WINDOW]
                if not rate_limit_data[ip]:
                    del rate_limit_data[ip]


def start_cleanup_task():
    thread = threading.Thread(target=cleanup_task, daemon=True)
    thread.start()


def is_safe_url(target):
    host_url = request.host_url
    test_url = urljoin(host_url, target)
    return urlparse(test_url).scheme in ("http", "https") and urlparse(host_url).netloc == urlparse(test_url).netloc


def add_rate_event(user_ip):
    now = time.time()
    with rate_lock:
        if user_ip not in rate_limit_data:
            rate_limit_data[user_ip] = []
        rate_limit_data[user_ip].append(now)
        rate_limit_data[user_ip] = [t for t in rate_limit_data[user_ip] if now - t <= RATE_LIMIT_WINDOW]
        return len(rate_limit_data[user_ip]) > RATE_LIMIT_THRESHOLD


def reset_rate_limit(user_ip):
    with rate_lock:
        rate_limit_data.pop(user_ip, None)


def is_session_verified():
    verified_at = session.get('verified_at')
    if not verified_at:
        return False
    return time.time() - verified_at <= SESSION_MAX_AGE_SEC


def should_checkpoint():
    user_ip = request.remote_addr
    is_ip_flagged = add_rate_event(user_ip)
    return is_ip_flagged or not is_session_verified()


def validate_and_use_token(cap_token):
    with token_lock:
        if cap_token in used_tokens:
            return False, "CAPTCHA already used."
        if not cap.validate(cap_token):
            return False, "Validation failed!"
        used_tokens[cap_token] = time.time()
    return True, None
