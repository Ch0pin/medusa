import json
import time
import uuid
import re
import requests
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Iterable

REQUEST_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36"
SEPARATOR = "-" * 60
# Keep write probes opt-in (matches your bash scanner having explicit write tests + cleanup)
ALLOW_WRITES_DEFAULT = False

COMMON_RTDB_PATHS = [
    "users", "accounts", "profiles", "members", "customers", "clients",
    "orders", "transactions", "payments", "invoices", "billing",
    "messages", "chats", "conversations", "notifications",
    "settings", "config", "admin", "secrets", "tokens", "api_keys",
    "sessions", "credentials", "passwords", "logs", "audit",
]

# Bash scanner uses a very large list; keep yours but you can expand safely.
COMMON_FUNCTION_NAMES = [
    "addMessage", "sendMessage", "createUser", "deleteUser", "updateUser", "getUser", "getUsers",
    "login", "logout", "register", "signup", "signUp", "authenticate", "verify", "verifyEmail",
    "resetPassword", "changePassword", "sendNotification", "sendEmail", "processPayment",
    "createOrder", "getOrders", "updateOrder", "deleteOrder", "uploadFile", "getFile",
    "generateToken", "validateToken", "refreshToken", "getData", "setData", "syncData",
    "backup", "restore", "export", "import", "webhook", "callback", "api", "admin",
    "debug", "test", "healthcheck", "status",
]

# Bash mostly uses us-central1; keep multi-region optional.
FUNCTION_REGIONS = [
    "us-central1", "us-east1", "us-east4", "us-west1",
    "europe-west1", "europe-west2", "europe-west3",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-south1",
]

COMMON_FIRESTORE_COLLECTIONS = [
    "users", "user", "accounts", "account", "profiles", "profile", "members",
    "customers", "clients", "orders", "transactions", "payments",
    "messages", "chats", "conversations", "posts", "comments",
    "settings", "config", "admin", "admins", "tokens", "sessions",
    "credentials", "logs", "events", "analytics", "notifications",
    "emails", "files", "documents", "images", "media", "uploads",
]

@contextmanager
def spinner(message: str, enabled: bool = True, interval: float = 0.12):
    """
    Console spinner that shows a 'working' message while a probe runs.
    Uses plain ASCII so it works everywhere.
    """
    if not enabled:
        yield
        return

    stop = threading.Event()

    def _run():
        frames = ["|", "/", "-", "\\"]
        i = 0
        while not stop.is_set():
            sys.stdout.write(f"\r⏳ {message} {frames[i % len(frames)]}")
            sys.stdout.flush()
            i += 1
            time.sleep(interval)
        # clear line
        sys.stdout.write("\r" + (" " * (len(message) + 8)) + "\r")
        sys.stdout.flush()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()
        t.join()

# --------------------------- Utilities ---------------------------

def _safe_json(resp: requests.Response):
    try:
        return resp.json()
    except ValueError:
        return {"_non_json": resp.text}

def _looks_like_firebase_web_key(k: str) -> bool:
    return bool(k and re.fullmatch(r"AIza[A-Za-z0-9_\-]{35}", k))

def _identity_error(body: Any) -> Optional[str]:
    if isinstance(body, dict):
        msg = body.get("error", {}).get("message")
        return msg if isinstance(msg, str) and msg else None
    return None

def _permission_denied(body: Any, status: int) -> bool:
    if status in (401, 403):
        return True
    txt = json.dumps(body).lower() if isinstance(body, (dict, list)) else str(body).lower()
    return ("permission denied" in txt) or ("permission_denied" in txt)

def _api_disabled(body: Any) -> bool:
    txt = json.dumps(body).lower() if isinstance(body, (dict, list)) else str(body).lower()
    return ("access not configured" in txt) or ("api has not been used" in txt) or ("api is not enabled" in txt)

def _bucket_not_found(body: Any, status: int) -> bool:
    if status == 404:
        return True
    txt = json.dumps(body).lower() if isinstance(body, (dict, list)) else str(body).lower()
    return ("bucket" in txt and ("not found" in txt or "does not exist" in txt))

def _requires_oauth(body: Any, status: int) -> bool:
    if status not in (401, 403):
        return False
    txt = json.dumps(body).lower() if isinstance(body, (dict, list)) else str(body).lower()
    return ("oauth" in txt) or ("credentials" in txt) or ("unauthenticated" in txt)

def _norm_https_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    return u.rstrip("/")

def _norm_bucket(bucket: str) -> str:
    b = (bucket or "").strip()
    if not b:
        return b
    b = b.replace("gs://", "").rstrip("/")
    if b.endswith(".appspot.com"):
        return b
    return f"{b}.appspot.com"

def _uniq(seq: Iterable[str]) -> List[str]:
    out, seen = [], set()
    for s in seq:
        s = (s or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# --------------------------- Table rendering ---------------------------

@dataclass
class Row:
    test: str
    result: str
    status: str

def print_security_report_lines(
    rows: List["Row"],
    api_key: Optional[str] = None,
    project_id: Optional[str] = None,
    firebase_db_url: Optional[str] = None,
    bucket: Optional[str] = None,
    region: str = "us-central1",
) -> None:
    """
    Clean, readable report with separators between tests.
    """

    def needs_attention(status: str) -> bool:
        s = (status or "").lower()
        return any(k in s for k in ("review", "critical", "high", "medium", "low"))

    def status_badge(status: str) -> str:
        s = status or ""
        sl = s.lower()
        if "secure" in sl:
            return "✅ Secure"
        if "n/a" in sl:
            return "✅ N/A"
        if "critical" in sl:
            return "❌ Critical"
        if "high" in sl:
            return "⚠️ High"
        if "medium" in sl:
            return "⚠️ Medium"
        if "low" in sl:
            return "⚠️ Low"
        if "review" in sl:
            return "⚠️ Review"
        return s

    def curl_for(test_name: str) -> Optional[str]:
        t = (test_name or "").lower()

        if "open signup" in t and api_key:
            return (
                "curl -X POST -H \"Content-Type: application/json\" "
                "-d '{\"email\":\"attacker@evil.com\",\"password\":\"Password123!\",\"returnSecureToken\":true}' "
                f"\"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}\""
            )
        if "anonymous auth" in t and api_key:
            return (
                "curl -X POST -H \"Content-Type: application/json\" "
                "-d '{\"returnSecureToken\":true}' "
                f"\"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}\""
            )
        if "email enumeration" in t and api_key:
            return (
                "curl -X POST -H \"Content-Type: application/json\" "
                "-d '{\"identifier\":\"victim@company.com\",\"continueUri\":\"https://localhost\"}' "
                f"\"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={api_key}\""
            )
        if "realtime db read" in t and firebase_db_url:
            base = firebase_db_url.rstrip("/")
            return f"curl \"{base}/.json\" && echo && curl \"{base}/.json?shallow=true\""
        if "realtime db write" in t and firebase_db_url:
            base = firebase_db_url.rstrip("/")
            return (
                "curl -X PUT -H \"Content-Type: application/json\" "
                "-d '{\"attacker\":\"was_here\",\"timestamp\":1234567890}' "
                f"\"{base}/_security_test.json\""
            )
        if "rtdb auth bypass" in t and firebase_db_url:
            base = firebase_db_url.rstrip("/")
            return f"curl \"{base}/.json?auth=<ID_TOKEN>\""
        if "firestore read" in t and project_id:
            return f"curl \"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents\""
        if "firestore write" in t and project_id:
            return (
                "curl -X POST -H \"Content-Type: application/json\" "
                "-d '{\"fields\":{\"security_test\":{\"stringValue\":\"firebase_scanner\"}}}' "
                f"\"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/_security_test\""
            )
        if "firestore collections" in t and project_id:
            return f"curl \"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/users\""
        if "storage bucket" in t and bucket:
            b = bucket if bucket.endswith(".appspot.com") else f"{bucket}.appspot.com"
            return f"curl \"https://firebasestorage.googleapis.com/v0/b/{b}/o\""
        if "storage upload" in t and bucket:
            b = bucket if bucket.endswith(".appspot.com") else f"{bucket}.appspot.com"
            return (
                "curl -X POST -H \"Content-Type: text/plain\" "
                "--data-binary \"test\" "
                f"\"https://firebasestorage.googleapis.com/v0/b/{b}/o?uploadType=media&name=pwned.txt\""
            )
        if "remote config" in t and api_key and project_id:
            return (
                f"curl -H \"x-goog-api-key: {api_key}\" "
                f"\"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/remoteConfig\""
            )
        if "cloud functions" in t and project_id:
            return f"curl \"https://{region}-{project_id}.cloudfunctions.net/<functionName>\""

        return None
    print(SEPARATOR)
    for idx, r in enumerate(rows):
        badge = status_badge(r.status)
        print(f"{badge}  {r.test} — {r.result}")

        if needs_attention(r.status):
            cmd = curl_for(r.test)
            if cmd:
                print("  Next step:")
                print(f"    {cmd}")

        # Print separator between entries (not after the last one)
        if idx != len(rows) - 1:
            print(SEPARATOR)
# --------------------------- Probes ---------------------------

# AUTH

def probe_open_signup(api_key: str) -> Row:
    if not api_key:
        return Row("Open Signup", "Missing API key", "✅ N/A")
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
    payload = {
        "email": f"scanner_{uuid.uuid4().hex[:8]}@test-domain-nonexistent.com",
        "password": "TestPassword123!",
        "returnSecureToken": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        if resp.status_code == 200 and isinstance(body, dict) and body.get("idToken"):
            return Row("Open Signup", "idToken returned", "❌ Critical")

        err = _identity_error(body)
        if err in ("OPERATION_NOT_ALLOWED", "ADMIN_ONLY_OPERATION"):
            return Row("Open Signup", err, "✅ Secure")
        if err and "API_KEY_INVALID" in err:
            return Row("Open Signup", "Invalid API key", "⚠️ Review")

        return Row("Open Signup", err or f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Open Signup", f"Error: {e}", "⚠️ Review")

def probe_anonymous_auth(api_key: str) -> Tuple[Row, Optional[str]]:
    if not api_key:
        return Row("Anonymous Auth", "Missing API key", "✅ N/A"), None
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}"
    payload = {"returnSecureToken": True}
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        if resp.status_code == 200 and isinstance(body, dict) and body.get("idToken"):
            return Row("Anonymous Auth", "idToken returned", "❌ High"), body.get("idToken")

        err = _identity_error(body)
        if err in ("OPERATION_NOT_ALLOWED", "ADMIN_ONLY_OPERATION"):
            return Row("Anonymous Auth", err, "✅ Secure"), None

        return Row("Anonymous Auth", err or f"HTTP {resp.status_code}", "⚠️ Review"), None
    except Exception as e:
        return Row("Anonymous Auth", f"Error: {e}", "⚠️ Review"), None

def probe_email_enumeration(api_key: str) -> Row:
    if not api_key:
        return Row("Email Enumeration", "Missing API key", "✅ N/A")
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={api_key}"
    try:
        fake_email = f"definitely_not_exists_{uuid.uuid4().hex[:8]}@nonexistent-domain-test.com"
        resp = requests.post(
            url,
            json={"identifier": fake_email, "continueUri": "https://localhost"},
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        body = _safe_json(resp)
        if isinstance(body, dict) and "registered" in body:
            return Row("Email Enumeration", "Returns registered field", "⚠️ Low")
        return Row("Email Enumeration", "No registered field", "✅ Secure")
    except Exception as e:
        return Row("Email Enumeration", f"Error: {e}", "⚠️ Review")


# RTDB

def probe_rtdb_read(firebase_db_url: str) -> Row:
    if not firebase_db_url:
        return Row("Realtime DB Read", "Missing DB URL", "✅ N/A")

    base = _norm_https_url(firebase_db_url)

    try:
        # 1) Root read
        url_root = f"{base}/.json"
        r_root = requests.get(url_root, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        b_root = _safe_json(r_root)

        if r_root.status_code == 200 and b_root not in (None, "null") and not (isinstance(b_root, dict) and b_root.get("error")):
            return Row("Realtime DB Read", "Public root read (/.json)", "❌ Critical")

        # 2) Shallow structure read
        url_shallow = f"{base}/.json?shallow=true"
        r_shallow = requests.get(url_shallow, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        b_shallow = _safe_json(r_shallow)

        if r_shallow.status_code == 200 and b_shallow not in (None, "null") and not (isinstance(b_shallow, dict) and b_shallow.get("error")):
            return Row("Realtime DB Read", "Shallow structure exposed", "⚠️ High")

        # 3) Common paths
        open_paths: List[str] = []
        for p in COMMON_RTDB_PATHS:
            url_path = f"{base}/{p}.json"
            try:
                rr = requests.get(url_path, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
                bb = _safe_json(rr)
                if rr.status_code == 200 and bb not in (None, "null") and not (isinstance(bb, dict) and bb.get("error")):
                    open_paths.append(p)
                    if len(open_paths) >= 3:
                        break
            except Exception:
                continue

        if open_paths:
            return Row("Realtime DB Read", f"Public paths: {', '.join(open_paths)}", "⚠️ High")

        if _permission_denied(b_root, r_root.status_code) or _permission_denied(b_shallow, r_shallow.status_code):
            return Row("Realtime DB Read", "Permission denied", "✅ Secure")

        return Row("Realtime DB Read", f"HTTP {r_root.status_code}/{r_shallow.status_code}", "⚠️ Review")

    except Exception as e:
        return Row("Realtime DB Read", f"Error: {e}", "⚠️ Review")

def probe_rtdb_write(firebase_db_url: str, allow_writes: bool) -> Row:
    if not firebase_db_url:
        return Row("Realtime DB Write", "Missing DB URL", "✅ N/A")
    if not allow_writes:
        return Row("Realtime DB Write", "Not tested (write probes off)", "✅ N/A")

    base = _norm_https_url(firebase_db_url)
    test_path = f"_firebase_security_test_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    url = f"{base}/{test_path}.json"
    payload = {"security_test": "firebase_scanner", "timestamp": int(time.time())}

    try:
        resp = requests.put(url, json=payload, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        writable = False
        if resp.status_code in (200, 201) and not (isinstance(body, dict) and body.get("error")):
            # In RTDB a successful write usually echoes the JSON back
            txt = json.dumps(body)
            writable = "security_test" in txt

        # Cleanup
        try:
            requests.delete(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        except Exception:
            pass

        if writable:
            return Row("Realtime DB Write", "Write succeeded", "❌ Critical")
        if _permission_denied(body, resp.status_code):
            return Row("Realtime DB Write", "Permission denied", "✅ Secure")

        return Row("Realtime DB Write", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Realtime DB Write", f"Error: {e}", "⚠️ Review")

def probe_rtdb_authenticated(firebase_db_url: str, id_token: str) -> Row:
    if not firebase_db_url:
        return Row("RTDB Auth Bypass", "Missing DB URL", "✅ N/A")
    if not id_token:
        return Row("RTDB Auth Bypass", "No token available", "✅ N/A")

    base = _norm_https_url(firebase_db_url)
    url = f"{base}/.json?auth={id_token}"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        if resp.status_code == 200 and body not in (None, "null") and not _permission_denied(body, resp.status_code):
            return Row("RTDB Auth Bypass", "Accessible with anon token", "⚠️ High")

        if _permission_denied(body, resp.status_code):
            return Row("RTDB Auth Bypass", "Permission denied", "✅ Secure")

        return Row("RTDB Auth Bypass", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("RTDB Auth Bypass", f"Error: {e}", "⚠️ Review")


# FIRESTORE

def probe_firestore_read(project_id: str) -> Row:
    if not project_id:
        return Row("Firestore Read", "Missing project_id", "✅ N/A")

    base_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"

    try:
        resp = requests.get(base_url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        if isinstance(body, dict) and "documents" in body:
            return Row("Firestore Read", "Documents accessible", "❌ Critical")
        if _api_disabled(body):
            return Row("Firestore Read", "API disabled", "✅ N/A")
        if _permission_denied(body, resp.status_code):
            return Row("Firestore Read", "Permission denied", "✅ Secure")

        return Row("Firestore Read", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Firestore Read", f"Error: {e}", "⚠️ Review")

def probe_firestore_write(project_id: str, allow_writes: bool) -> Row:
    if not project_id:
        return Row("Firestore Write", "Missing project_id", "✅ N/A")
    if not allow_writes:
        return Row("Firestore Write", "Not tested (write probes off)", "✅ N/A")

    base_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
    collection = f"_firebase_security_test_{int(time.time())}"
    url = f"{base_url}/{collection}"
    payload = {"fields": {"security_test": {"stringValue": "firebase_scanner"}}}

    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        writable = isinstance(body, dict) and ("name" in body) and ("fields" in body)
        doc_name = body.get("name") if isinstance(body, dict) else None

        # Cleanup if created
        if writable and doc_name:
            try:
                requests.delete(f"https://firestore.googleapis.com/v1/{doc_name}", timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
            except Exception:
                pass

        if writable:
            return Row("Firestore Write", "Write succeeded", "❌ Critical")
        if _permission_denied(body, resp.status_code):
            return Row("Firestore Write", "Permission denied", "✅ Secure")
        if _api_disabled(body):
            return Row("Firestore Write", "API disabled", "✅ N/A")

        return Row("Firestore Write", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Firestore Write", f"Error: {e}", "⚠️ Review")

def probe_firestore_collections(project_id: str) -> Row:
    if not project_id:
        return Row("Firestore Collections", "Missing project_id", "✅ N/A")

    base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
    exposed: List[str] = []

    try:
        for col in COMMON_FIRESTORE_COLLECTIONS:
            url = f"{base}/{col}"
            try:
                resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
                body = _safe_json(resp)
                if isinstance(body, dict) and "documents" in body:
                    exposed.append(col)
                    if len(exposed) >= 5:
                        break
            except Exception:
                continue

        if exposed:
            return Row("Firestore Collections", f"Exposed: {', '.join(exposed)}", "⚠️ High")

        return Row("Firestore Collections", "No exposed collections found", "✅ Secure")
    except Exception as e:
        return Row("Firestore Collections", f"Error: {e}", "⚠️ Review")


# STORAGE

def probe_storage_bucket(bucket: str) -> Row:
    if not bucket:
        return Row("Storage Bucket", "Missing bucket", "✅ N/A")

    bkt = _norm_bucket(bucket)
    url = f"https://firebasestorage.googleapis.com/v0/b/{bkt}/o"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        body = _safe_json(resp)

        if resp.status_code == 200 and isinstance(body, dict) and "items" in body:
            return Row("Storage Bucket", "Listing enabled", "❌ High")
        if _bucket_not_found(body, resp.status_code):
            return Row("Storage Bucket", "Does not exist", "✅ N/A")
        if _permission_denied(body, resp.status_code):
            return Row("Storage Bucket", "Permission denied", "✅ Secure")

        return Row("Storage Bucket", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Storage Bucket", f"Error: {e}", "⚠️ Review")

def probe_storage_write(bucket: str, allow_writes: bool) -> Row:
    if not bucket:
        return Row("Storage Upload", "Missing bucket", "✅ N/A")
    if not allow_writes:
        return Row("Storage Upload", "Not tested (write probes off)", "✅ N/A")

    bkt = _norm_bucket(bucket)
    api_url = f"https://firebasestorage.googleapis.com/v0/b/{bkt}/o"
    test_path = f"_firebase_security_test_{int(time.time())}.txt"

    try:
        resp = requests.post(
            f"{api_url}?uploadType=media&name={requests.utils.quote(test_path, safe='')}",
            data=b"firebase_security_scanner_test",
            headers={"Content-Type": "text/plain", "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        body = _safe_json(resp)

        writable = (resp.status_code in (200, 201)) and isinstance(body, dict) and body.get("name")
        # Cleanup
        try:
            requests.delete(f"{api_url}/{requests.utils.quote(test_path, safe='')}", timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        except Exception:
            pass

        if writable:
            return Row("Storage Upload", "Upload succeeded", "❌ Critical")
        if _permission_denied(body, resp.status_code):
            return Row("Storage Upload", "Permission denied", "✅ Secure")
        if _bucket_not_found(body, resp.status_code):
            return Row("Storage Upload", "Bucket does not exist", "✅ N/A")

        return Row("Storage Upload", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Storage Upload", f"Error: {e}", "⚠️ Review")


# CLOUD FUNCTIONS

def probe_cloud_functions(project_id: str, known_functions: Optional[List[str]] = None, region: str = "us-central1") -> Row:
    if not project_id:
        return Row("Cloud Functions", "Missing project_id", "✅ N/A")

    known_functions = _uniq(known_functions or [])
    common = _uniq(COMMON_FUNCTION_NAMES)
    all_funcs = _uniq(known_functions + common)

    found_non404 = 0
    found_200 = 0
    callable_no_auth = 0

    # Enumerate endpoints (bash: mainly us-central1; keep region param)
    for fn in all_funcs:
        url = f"https://{region}-{project_id}.cloudfunctions.net/{fn}"
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, headers={"User-Agent": USER_AGENT})
            if r.status_code != 404:
                found_non404 += 1
                if r.status_code == 200:
                    found_200 += 1
        except Exception:
            pass

    # Callable tests only for known (extracted) names, like bash
    for fn in known_functions:
        url = f"https://{region}-{project_id}.cloudfunctions.net/{fn}"
        try:
            r = requests.post(
                url,
                json={"data": {}},
                timeout=REQUEST_TIMEOUT,
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                allow_redirects=False,
            )
            txt = r.text or ""
            if r.status_code == 200 and ('"result"' in txt or '"data"' in txt):
                callable_no_auth += 1
            # If it says UNAUTHENTICATED, that’s protected; no count.
        except Exception:
            pass

    if callable_no_auth > 0:
        return Row("Cloud Functions", f"Callable no-auth: {callable_no_auth}", "⚠️ Medium")
    if found_non404 == 0:
        return Row("Cloud Functions", "No endpoints found", "✅ N/A")
    if found_200 > 0:
        return Row("Cloud Functions", f"Unauth endpoints (200): {found_200}", "⚠️ Medium")
    return Row("Cloud Functions", f"Endpoints exist (non-404): {found_non404}", "✅ N/A")


# REMOTE CONFIG

def probe_remote_config(project_id: str, api_key: str) -> Row:
    if not (project_id and api_key):
        return Row("Remote Config", "Missing project_id/api_key", "✅ N/A")

    url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/remoteConfig"
    try:
        resp = requests.get(url, headers={"x-goog-api-key": api_key, "User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
        body = _safe_json(resp)

        if resp.status_code == 200 and isinstance(body, dict) and ("parameters" in body or "conditions" in body):
            return Row("Remote Config", "Parameters exposed", "⚠️ Medium")
        if _requires_oauth(body, resp.status_code):
            return Row("Remote Config", "Requires OAuth", "✅ Secure")
        if _permission_denied(body, resp.status_code):
            return Row("Remote Config", "Permission denied", "✅ Secure")
        return Row("Remote Config", f"HTTP {resp.status_code}", "⚠️ Review")
    except Exception as e:
        return Row("Remote Config", f"Error: {e}", "⚠️ Review")

