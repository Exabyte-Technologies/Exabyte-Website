import os
import random
import string
import time
from urllib.parse import urlparse, urljoin

from capjs_server import CapServer
from flask import request, session
from redis import Redis

redis_client = Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0)),
)

SESSION_MAX_AGE_SEC = 43200
RATE_LIMIT_THRESHOLD = 30
RATE_LIMIT_WINDOW = 60
TOKEN_EXPIRY_SEC = 600

cap_secret = os.getenv("CAP_SECRET_KEY", "dev_cap_secret")
cap = CapServer(
    secret_key=cap_secret,
    challenge_difficulty=5,
    challenge_count=32,
    challenge_size=32,
)

if cap_secret == "dev_cap_secret":
    print("WARNING: CAP_SECRET_KEY not set; use stable secret in production")


def start_cleanup_task():
    return


def is_safe_url(target):
    host_url = request.host_url
    test_url = urljoin(host_url, target)
    return urlparse(test_url).scheme in ("http", "https") and urlparse(host_url).netloc == urlparse(test_url).netloc


def add_rate_event(user_ip):
    now = time.time()
    key = f"rate-limit:{user_ip}"
    member = f"{now}:{os.urandom(4).hex()}"

    redis_client.zadd(key, {member: now})
    redis_client.zremrangebyscore(key, 0, now - RATE_LIMIT_WINDOW)
    count = redis_client.zcount(key, now - RATE_LIMIT_WINDOW, now)
    redis_client.expire(key, RATE_LIMIT_WINDOW + 2)

    return count > RATE_LIMIT_THRESHOLD


def reset_rate_limit(user_ip):
    redis_client.delete(f"rate-limit:{user_ip}")


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
    key = f"captcha-token:{cap_token}"
    if redis_client.exists(key):
        return False, "CAPTCHA already used."
    if not cap.validate(cap_token):
        return False, "Validation failed!"
    redis_client.set(key, "used", ex=TOKEN_EXPIRY_SEC)
    return True, None
