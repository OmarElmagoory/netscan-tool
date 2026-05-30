import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "WebScanPro/2.0 Security Scanner"}
session = requests.Session()
session.headers.update(HEADERS)

# ========== CRAWLER ==========
def crawl(base_url, max_pages=20):
    visited = set()
    to_visit = [base_url]
    found = []
    parsed_base = urlparse(base_url)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        try:
            r = session.get(url, timeout=8, verify=False)
            visited.add(url)
            found.append(url)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action")
                if href:
                    full = urljoin(url, href)
                    parsed = urlparse(full)
                    if parsed.netloc == parsed_base.netloc and full not in visited:
                        to_visit.append(full)
        except:
            pass
    return found

# ========== HEADERS ==========
def check_headers(url):
    results = []
    try:
        r = session.get(url, timeout=10, verify=False)
        headers = r.headers
        security_headers = {
            "Content-Security-Policy": {"fix": "Add: Content-Security-Policy: default-src 'self'", "severity": "critical"},
            "X-Frame-Options": {"fix": "Add: X-Frame-Options: DENY", "severity": "medium"},
            "X-Content-Type-Options": {"fix": "Add: X-Content-Type-Options: nosniff", "severity": "medium"},
            "Strict-Transport-Security": {"fix": "Add: Strict-Transport-Security: max-age=31536000", "severity": "medium"},
            "Referrer-Policy": {"fix": "Add: Referrer-Policy: no-referrer-when-downgrade", "severity": "low"},
            "Permissions-Policy": {"fix": "Add: Permissions-Policy: geolocation=()", "severity": "low"},
        }
        for h, info in security_headers.items():
            if h not in headers:
                results.append({"name_ar": f"رأس {h} مفقود", "name_en": f"Missing Header: {h}", "desc_ar": f"الموقع لا يرسل رأس {h}.", "desc_en": f"Server does not send {h} header.", "fix": info["fix"], "severity": info["severity"], "url": url})
            else:
                results.append({"name_ar": f"✓ {h} موجود", "name_en": f"✓ {h} present", "desc_ar": f"القيمة: {headers[h][:80]}", "desc_en": f"Value: {headers[h][:80]}", "fix": "", "severity": "safe", "url": url})
        if "Server" in headers:
            results.append({"name_ar": f"كشف معلومات السيرفر: {headers['Server']}", "name_en": f"Server Disclosed: {headers['Server']}", "desc_ar": "الخادم يكشف نوعه.", "desc_en": "Server reveals its type.", "fix": "Remove or obscure the Server header.", "severity": "low", "url": url})
    except Exception as e:
        results.append({"name_ar": f"خطأ: {str(e)}", "name_en": f"Error: {str(e)}", "desc_ar": "تعذر الاتصال.", "desc_en": "Could not connect.", "fix": "", "severity": "critical", "url": url})
    return results

# ========== SSL ==========
def check_ssl(url):
    results = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return results
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                expire_str = cert.get("notAfter", "")
                if expire_str:
                    expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire_date - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        sev, msg_ar, msg_en = "critical", f"انتهت منذ {abs(days_left)} يوم", f"Expired {abs(days_left)} days ago"
                    elif days_left < 30:
                        sev, msg_ar, msg_en = "medium", f"تنتهي خلال {days_left} يوم", f"Expires in {days_left} days"
                    else:
                        sev, msg_ar, msg_en = "safe", f"سارية ({days_left} يوم)", f"Valid ({days_left} days left)"
                    results.append({"name_ar": f"شهادة SSL: {msg_ar}", "name_en": f"SSL Certificate: {msg_en}", "desc_ar": f"تنتهي: {expire_date.strftime('%Y-%m-%d')}", "desc_en": f"Expires: {expire_date.strftime('%Y-%m-%d')}", "fix": "Renew via Let's Encrypt." if sev != "safe" else "", "severity": sev, "url": url})
                weak = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
                if protocol in weak:
                    results.append({"name_ar": f"بروتوكول ضعيف: {protocol}", "name_en": f"Weak Protocol: {protocol}", "desc_ar": "بروتوكول قديم.", "desc_en": "Deprecated protocol.", "fix": "Enable only TLS 1.2 and TLS 1.3.", "severity": "critical", "url": url})
                else:
                    results.append({"name_ar": f"✓ بروتوكول آمن: {protocol}", "name_en": f"✓ Secure Protocol: {protocol}", "desc_ar": "بروتوكول حديث.", "desc_en": "Modern protocol.", "fix": "", "severity": "safe", "url": url})
                if cipher:
                    cn = cipher[0]
                    weak_c = ["RC4","DES","3DES","MD5","NULL","EXPORT"]
                    if any(w in cn.upper() for w in weak_c):
                        results.append({"name_ar": f"خوارزمية ضعيفة: {cn}", "name_en": f"Weak Cipher: {cn}", "desc_ar": "خوارزمية قديمة.", "desc_en": "Outdated cipher.", "fix": "Use AES-256-GCM.", "severity": "critical", "url": url})
                    else:
                        results.append({"name_ar": f"✓ خوارزمية قوية: {cn}", "name_en": f"✓ Strong Cipher: {cn}", "desc_ar": "خوارزمية قوية.", "desc_en": "Strong cipher.", "fix": "", "severity": "safe", "url": url})
    except Exception as e:
        results.append({"name_ar": "لا يوجد SSL", "name_en": "No SSL", "desc_ar": "الموقع لا يدعم HTTPS.", "desc_en": "No HTTPS support.", "fix": "Install SSL certificate.", "severity": "critical", "url": url})
    return results

# ========== SQL INJECTION ==========
def check_sql(url):
    results = []
    payloads = ["'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "1' ORDER BY 1--", "' UNION SELECT NULL--", "admin'--"]
    error_sigs = ["sql syntax", "mysql_fetch", "ora-", "syntax error", "mysql error", "unclosed quotation", "postgresql", "sqlite", "odbc", "sqlexception", "sql server", "warning: mysql", "error in your sql", "incorrect syntax"]
    try:
        base = session.get(url, timeout=10, verify=False)
        base_len = len(base.text)
        for payload in payloads:
            test_url = url + ("&id=" if "?" in url else "?id=") + requests.utils.quote(payload)
            try:
                r = session.get(test_url, timeout=8, verify=False)
                if any(sig in r.text.lower() for sig in error_sigs):
                    results.append({"name_ar": "🚨 ثغرة SQL Injection مكتشفة!", "name_en": "🚨 SQL Injection Found!", "desc_ar": f"الموقع عرضة لـ SQL Injection عبر payload: {payload}", "desc_en": f"SQL Injection via payload: {payload}", "fix": "Use prepared statements. Never concatenate user input into SQL.", "severity": "critical", "url": url})
                    return results
                if abs(len(r.text) - base_len) > 500:
                    results.append({"name_ar": "⚠️ SQL Injection محتمل", "name_en": "⚠️ Possible SQL Injection", "desc_ar": "تغير في حجم الرد بعد الـ payload.", "desc_en": "Response size changed after payload injection.", "fix": "Use prepared statements.", "severity": "medium", "url": url})
                    return results
            except:
                pass
    except:
        pass
    results.append({"name_ar": "✓ لم تُكتشف ثغرة SQL Injection", "name_en": "✓ No SQL Injection detected", "desc_ar": "الاختبار لم يكشف ثغرات SQL ظاهرة.", "desc_en": "Basic SQL tests passed.", "fix": "", "severity": "safe", "url": url})
    return results

# ========== XSS ==========
def check_xss(url):
    results = []
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "'\"><script>alert('XSS')</script>", "<svg onload=alert('XSS')>", "javascript:alert('XSS')"]
    try:
        for payload in payloads:
            test_url = url + ("&q=" if "?" in url else "?q=") + requests.utils.quote(payload)
            try:
                r = session.get(test_url, timeout=8, verify=False)
                if payload in r.text:
                    results.append({"name_ar": "🚨 ثغرة XSS مكتشفة!", "name_en": "🚨 XSS Vulnerability Found!", "desc_ar": "الموقع يعكس JavaScript بدون تعقيم.", "desc_en": f"XSS payload reflected without sanitization.", "fix": "Sanitize inputs. Use CSP. Encode output.", "severity": "critical", "url": url})
                    return results
            except:
                pass
    except:
        pass
    results.append({"name_ar": "✓ لم تُكتشف ثغرة XSS", "name_en": "✓ No XSS detected", "desc_ar": "اختبار XSS الأساسي نجح.", "desc_en": "Basic XSS tests passed.", "fix": "", "severity": "safe", "url": url})
    return results

# ========== DIRECTORIES ==========
def check_directories(url):
    results = []
    base = url.rstrip('/')
    paths = ["/admin", "/admin/", "/.env", "/.git", "/.git/config", "/backup", "/backup.sql", "/phpinfo.php", "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config", "/api", "/login", "/phpmyadmin", "/uploads", "/tmp", "/logs", "/server-status", "/.DS_Store", "/config.php", "/wp-admin", "/wp-login.php"]
    for path in paths:
        try:
            r = session.get(base + path, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 200:
                sev = "critical" if any(p in path for p in ['.env', '.git', 'config', 'backup', 'sql', 'phpinfo', 'phpmyadmin']) else "medium" if any(p in path for p in ['admin', 'login', 'server-status']) else "low"
                results.append({"name_ar": f"مسار حساس مكشوف: {path}", "name_en": f"Sensitive Path Exposed: {path}", "desc_ar": f"تم العثور على {path} (HTTP 200).", "desc_en": f"Found {path} (HTTP 200).", "fix": f"Restrict access to {path}.", "severity": sev, "url": base + path})
            elif r.status_code == 403:
                results.append({"name_ar": f"مسار محمي: {path} (403)", "name_en": f"Protected Path: {path} (403)", "desc_ar": f"المسار موجود لكن محمي.", "desc_en": f"Path exists but protected.", "fix": f"Verify {path} is properly secured.", "severity": "low", "url": base + path})
        except:
            pass
    if not results:
        results.append({"name_ar": "✓ لم تُكتشف مسارات حساسة", "name_en": "✓ No sensitive paths found", "desc_ar": "لم يتم العثور على مسارات حساسة.", "desc_en": "No exposed sensitive paths.", "fix": "", "severity": "safe", "url": url})
    return results

# ========== PORTS ==========
def check_ports(hostname):
    results = []
    ports = {21:("FTP","critical"), 22:("SSH","low"), 23:("Telnet","critical"), 80:("HTTP","low"), 443:("HTTPS","safe"), 3306:("MySQL","critical"), 5432:("PostgreSQL","critical"), 6379:("Redis","critical"), 27017:("MongoDB","critical"), 8080:("HTTP-Alt","medium")}
    for port, (service, sev) in ports.items():
        try:
            s = socket.socket()
            s.settimeout(1.5)
            r = s.connect_ex((hostname, port))
            s.close()
            if r == 0:
                if sev == "safe":
                    results.append({"name_ar": f"✓ منفذ {port} ({service})", "name_en": f"✓ Port {port} ({service})", "desc_ar": "طبيعي.", "desc_en": "Expected.", "fix": "", "severity": "safe", "url": hostname})
                elif sev == "critical":
                    results.append({"name_ar": f"منفذ خطير: {port} ({service})", "name_en": f"Dangerous Port: {port} ({service})", "desc_ar": f"منفذ {service} مكشوف.", "desc_en": f"{service} port exposed.", "fix": f"Close port {port} via firewall.", "severity": "critical", "url": hostname})
                else:
                    results.append({"name_ar": f"منفذ مفتوح: {port} ({service})", "name_en": f"Open Port: {port} ({service})", "desc_ar": "تحقق إن كان ضرورياً.", "desc_en": "Verify if needed.", "fix": f"Close if not needed.", "severity": "medium", "url": hostname})
        except:
            pass
    return results

# ========== CSRF ==========
def check_csrf(url):
    results = []
    try:
        r = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            has_csrf = any(i.get("name","").lower() in ["csrf","csrf_token","_token","token","authenticity_token"] for i in inputs)
            if not has_csrf and form.get("method","get").lower() == "post":
                results.append({"name_ar": "🚨 نموذج بدون حماية CSRF", "name_en": "🚨 Form Without CSRF Protection", "desc_ar": "نموذج POST بدون CSRF token — عرضة لهجمات CSRF.", "desc_en": "POST form without CSRF token — vulnerable to CSRF attacks.", "fix": "Add CSRF token to all POST forms.", "severity": "critical", "url": url})
                return results
    except:
        pass
    results.append({"name_ar": "✓ لم تُكتشف ثغرة CSRF", "name_en": "✓ No CSRF detected", "desc_ar": "النماذج تبدو محمية.", "desc_en": "Forms appear protected.", "fix": "", "severity": "safe", "url": url})
    return results

# ========== FULL SCAN ==========
def full_scan(url, scan_type):
    parsed = urlparse(url)
    hostname = parsed.hostname
    all_results = []

    if scan_type in ["vuln", "both"]:
        # فحص الصفحة الرئيسية
        all_results.extend(check_headers(url))
        all_results.extend(check_sql(url))
        all_results.extend(check_xss(url))
        all_results.extend(check_csrf(url))
        all_results.extend(check_directories(url))

        # Crawler — فحص كل الروابط
        pages = crawl(url, max_pages=10)
        seen = set()
        for page in pages[1:]:
            if page not in seen:
                seen.add(page)
                sql = check_sql(page)
                xss = check_xss(page)
                csrf = check_csrf(page)
                for r in sql + xss + csrf:
                    if r["severity"] in ["critical", "medium"]:
                        all_results.append(r)

    if scan_type in ["crypto", "both"]:
        all_results.extend(check_ssl(url))

    if scan_type == "both" and hostname:
        all_results.extend(check_ports(hostname))

    return all_results
