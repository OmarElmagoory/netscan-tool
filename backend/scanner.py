import requests
import ssl
import socket
import datetime
from urllib.parse import urlparse

def check_headers(url):
    results = []
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = r.headers

        security_headers = {
            "Content-Security-Policy": {"name_ar": "Content-Security-Policy", "fix": "Add: Content-Security-Policy: default-src 'self'", "severity": "critical"},
            "X-Frame-Options": {"name_ar": "X-Frame-Options", "fix": "Add: X-Frame-Options: DENY", "severity": "medium"},
            "X-Content-Type-Options": {"name_ar": "X-Content-Type-Options", "fix": "Add: X-Content-Type-Options: nosniff", "severity": "medium"},
            "Strict-Transport-Security": {"name_ar": "HSTS", "fix": "Add: Strict-Transport-Security: max-age=31536000", "severity": "medium"},
            "Referrer-Policy": {"name_ar": "Referrer-Policy", "fix": "Add: Referrer-Policy: no-referrer-when-downgrade", "severity": "low"},
            "Permissions-Policy": {"name_ar": "Permissions-Policy", "fix": "Add: Permissions-Policy: geolocation=()", "severity": "low"},
        }

        for h, info in security_headers.items():
            if h not in headers:
                results.append({
                    "name_ar": f"رأس {info['name_ar']} مفقود",
                    "name_en": f"Missing Header: {h}",
                    "desc_ar": f"الموقع لا يُرسل رأس {h} مما يُضعف الأمان.",
                    "desc_en": f"Server does not send {h} header.",
                    "fix": info["fix"],
                    "severity": info["severity"]
                })
            else:
                results.append({
                    "name_ar": f"✓ {info['name_ar']} موجود",
                    "name_en": f"✓ {h} present",
                    "desc_ar": f"القيمة: {headers[h][:80]}",
                    "desc_en": f"Value: {headers[h][:80]}",
                    "fix": "",
                    "severity": "safe"
                })

        if url.startswith("http://"):
            results.append({
                "name_ar": "الموقع بدون HTTPS",
                "name_en": "No HTTPS",
                "desc_ar": "البيانات تُنقل بدون تشفير.",
                "desc_en": "Data is transmitted without encryption.",
                "fix": "Install SSL and redirect HTTP to HTTPS.",
                "severity": "critical"
            })

        if "Server" in headers:
            results.append({
                "name_ar": f"كشف معلومات السيرفر: {headers['Server']}",
                "name_en": f"Server Disclosed: {headers['Server']}",
                "desc_ar": "الخادم يكشف نوعه وإصداره.",
                "desc_en": "Server reveals its type and version.",
                "fix": "Remove or obscure the Server header.",
                "severity": "low"
            })

        return results
    except Exception as e:
        return [{"name_ar": f"خطأ: {str(e)}", "name_en": f"Error: {str(e)}", "desc_ar": "تعذر الاتصال.", "desc_en": "Could not connect.", "fix": "Check the URL.", "severity": "critical"}]


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
                    results.append({"name_ar": f"شهادة SSL: {msg_ar}", "name_en": f"SSL Certificate: {msg_en}", "desc_ar": f"تنتهي: {expire_date.strftime('%Y-%m-%d')}", "desc_en": f"Expires: {expire_date.strftime('%Y-%m-%d')}", "fix": "Renew via Let's Encrypt." if sev != "safe" else "", "severity": sev})

                weak = ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]
                if protocol in weak:
                    results.append({"name_ar": f"بروتوكول ضعيف: {protocol}", "name_en": f"Weak Protocol: {protocol}", "desc_ar": "بروتوكول قديم وغير آمن.", "desc_en": "Deprecated protocol.", "fix": "Enable only TLS 1.2 and TLS 1.3.", "severity": "critical"})
                else:
                    results.append({"name_ar": f"✓ بروتوكول آمن: {protocol}", "name_en": f"✓ Secure Protocol: {protocol}", "desc_ar": "بروتوكول حديث.", "desc_en": "Modern protocol.", "fix": "", "severity": "safe"})

                if cipher:
                    weak_c = ["RC4","DES","3DES","MD5","NULL","EXPORT"]
                    cn = cipher[0]
                    if any(w in cn.upper() for w in weak_c):
                        results.append({"name_ar": f"خوارزمية ضعيفة: {cn}", "name_en": f"Weak Cipher: {cn}", "desc_ar": "خوارزمية قديمة.", "desc_en": "Outdated cipher.", "fix": "Use AES-256-GCM.", "severity": "critical"})
                    else:
                        results.append({"name_ar": f"✓ خوارزمية قوية: {cn}", "name_en": f"✓ Strong Cipher: {cn}", "desc_ar": "خوارزمية قوية.", "desc_en": "Strong cipher.", "fix": "", "severity": "safe"})
    except Exception as e:
        results.append({"name_ar": "لا يوجد SSL", "name_en": "No SSL", "desc_ar": "الموقع لا يدعم HTTPS.", "desc_en": "No HTTPS support.", "fix": "Install SSL certificate.", "severity": "critical"})
    return results


def check_ports(hostname):
    results = []
    ports = {
        21:("FTP","critical"), 22:("SSH","low"), 23:("Telnet","critical"),
        80:("HTTP","low"), 443:("HTTPS","safe"), 3306:("MySQL","critical"),
        5432:("PostgreSQL","critical"), 6379:("Redis","critical"),
        27017:("MongoDB","critical"), 8080:("HTTP-Alt","medium")
    }
    for port,(service,sev) in ports.items():
        try:
            s = socket.socket()
            s.settimeout(1.5)
            r = s.connect_ex((hostname, port))
            s.close()
            if r == 0:
                if sev == "safe":
                    results.append({"name_ar": f"✓ منفذ {port} ({service})", "name_en": f"✓ Port {port} ({service})", "desc_ar": "طبيعي.", "desc_en": "Expected.", "fix": "", "severity": "safe"})
                elif sev == "critical":
                    results.append({"name_ar": f"منفذ خطير: {port} ({service})", "name_en": f"Dangerous Port: {port} ({service})", "desc_ar": f"منفذ {service} مكشوف.", "desc_en": f"{service} exposed.", "fix": f"Close port {port} via firewall.", "severity": "critical"})
                else:
                    results.append({"name_ar": f"منفذ مفتوح: {port} ({service})", "name_en": f"Open Port: {port} ({service})", "desc_ar": "تحقق إن كان ضرورياً.", "desc_en": "Verify if needed.", "fix": f"Close if not needed.", "severity": "medium"})
        except:
            pass
    return results


def full_scan(url, scan_type):
    parsed = urlparse(url)
    hostname = parsed.hostname
    results = []
    if scan_type in ["vuln", "both"]:
        results.extend(check_headers(url))
    if scan_type in ["crypto", "both"]:
        results.extend(check_ssl(url))
    if scan_type == "both" and hostname:
        results.extend(check_ports(hostname))
    return results
def check_sql_injection(url):
    results = []
    parsed = urlparse(url)
    
    # لو ما في parameters نحاول نضيف واحد
    if not parsed.query:
        test_url = url.rstrip('/') + "/?id=1"
    else:
        test_url = url

    # Payloads حقيقية لاختبار SQL Injection
    payloads = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1--",
        "\" OR 1=1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "admin'--",
        "1; DROP TABLE users--",
    ]

    # علامات تدل على وجود ثغرة SQL
    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-", "syntax error",
        "mysql error", "division by zero", "supplied argument is not",
        "unclosed quotation", "postgresql", "sqlite", "odbc",
        "jdbc", "sqlexception", "sql server", "microsoft ole db",
        "warning: mysql", "valid mysql result", "mssql_",
        "error in your sql", "incorrect syntax near",
    ]

    vulnerable = False
    findings = []

    try:
        # نجرب الـ URL الأصلي أولاً كمرجع
        base_response = requests.get(test_url, timeout=10, verify=False)
        base_length = len(base_response.text)
        base_status = base_response.status_code

        for payload in payloads:
            # نحاول نضيف الـ payload للـ URL
            if "?" in test_url:
                inject_url = test_url + payload
            else:
                inject_url = test_url + "/?id=" + requests.utils.quote(payload)

            try:
                r = requests.get(inject_url, timeout=8, verify=False)
                response_text = r.text.lower()

                # فحص 1: رسائل خطأ SQL
                for sig in error_signatures:
                    if sig in response_text:
                        vulnerable = True
                        findings.append(f"SQL error detected with payload: {payload}")
                        break

                # فحص 2: تغير كبير في حجم الرد
                length_diff = abs(len(r.text) - base_length)
                if length_diff > 500 and r.status_code != base_status:
                    vulnerable = True
                    findings.append(f"Response anomaly with payload: {payload}")

            except:
                pass

    except Exception as e:
        return [{"name_ar": f"خطأ في فحص SQL: {str(e)}", "name_en": f"SQL scan error: {str(e)}",
                 "desc_ar": "تعذر فحص SQL Injection.", "desc_en": "Could not scan for SQL Injection.",
                 "fix": "", "severity": "medium"}]

    if vulnerable:
        results.append({
            "name_ar": "🚨 ثغرة SQL Injection مكتشفة!",
            "name_en": "🚨 SQL Injection Vulnerability Found!",
            "desc_ar": f"الموقع عرضة لهجمات SQL Injection. تم اكتشافها عبر: {findings[0] if findings else 'payload test'}",
            "desc_en": f"Site is vulnerable to SQL Injection. Found via: {findings[0] if findings else 'payload test'}",
            "fix": "Use prepared statements. Never concatenate user input into SQL queries. Use an ORM.",
            "severity": "critical"
        })
    else:
        results.append({
            "name_ar": "✓ لم تُكتشف ثغرة SQL Injection",
            "name_en": "✓ No SQL Injection detected",
            "desc_ar": "الاختبار الأساسي لم يكشف ثغرات SQL Injection ظاهرة.",
            "desc_en": "Basic SQL Injection tests passed successfully.",
            "fix": "",
            "severity": "safe"
        })

    return results


def check_xss(url):
    results = []

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "\"><img src=x onerror=alert(1)>",
        "'><script>alert(document.cookie)</script>",
    ]

    vulnerable = False
    finding = ""

    try:
        for payload in xss_payloads:
            # نجرب في الـ URL parameters
            if "?" in url:
                test_url = url + payload
            else:
                test_url = url + "/?q=" + requests.utils.quote(payload)

            try:
                r = requests.get(test_url, timeout=8, verify=False)
                # لو الـ payload ظهر في الرد بدون تشفير = ثغرة
                if payload in r.text or payload.lower() in r.text.lower():
                    vulnerable = True
                    finding = payload
                    break
            except:
                pass

    except Exception as e:
        return [{"name_ar": f"خطأ في فحص XSS: {str(e)}", "name_en": f"XSS scan error: {str(e)}",
                 "desc_ar": "تعذر فحص XSS.", "desc_en": "Could not scan for XSS.",
                 "fix": "", "severity": "medium"}]

    if vulnerable:
        results.append({
            "name_ar": "🚨 ثغرة XSS مكتشفة!",
            "name_en": "🚨 XSS Vulnerability Found!",
            "desc_ar": f"الموقع عرضة لهجمات Cross-Site Scripting. الـ payload ظهر في الرد بدون تعقيم.",
            "desc_en": f"Site is vulnerable to XSS. Payload reflected without sanitization: {finding[:50]}",
            "fix": "Sanitize all user inputs. Use Content-Security-Policy. Encode output. Use htmlspecialchars().",
            "severity": "critical"
        })
    else:
        results.append({
            "name_ar": "✓ لم تُكتشف ثغرة XSS ظاهرة",
            "name_en": "✓ No reflected XSS detected",
            "desc_ar": "الاختبار الأساسي لم يكشف ثغرات XSS ظاهرة.",
            "desc_en": "Basic XSS reflection tests passed.",
            "fix": "",
            "severity": "safe"
        })

    return results


def check_directories(url):
    results = []
    base_url = url.rstrip('/')

    # ملفات ومجلدات خطيرة شائعة
    sensitive_paths = [
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/.env", "/.git", "/.git/config", "/config.php",
        "/backup", "/backup.zip", "/backup.sql", "/db.sql",
        "/phpinfo.php", "/info.php", "/test.php",
        "/robots.txt", "/sitemap.xml",
        "/.htaccess", "/web.config",
        "/api", "/api/v1", "/api/v2",
        "/login", "/admin/login", "/wp-login.php",
        "/phpmyadmin", "/mysql", "/database",
        "/uploads", "/files", "/images",
        "/tmp", "/temp", "/logs", "/log",
        "/.DS_Store", "/Thumbs.db",
        "/server-status", "/server-info",
    ]

    found_sensitive = []
    found_info = []

    for path in sensitive_paths:
        try:
            test_url = base_url + path
            r = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)

            if r.status_code == 200:
                # تصنيف حسب خطورة المسار
                if any(p in path for p in ['.env', '.git', 'config', 'backup', 'sql', 'phpinfo', 'phpmyadmin']):
                    found_sensitive.append((path, r.status_code, "critical"))
                elif any(p in path for p in ['admin', 'login', 'wp-admin', 'server-status']):
                    found_sensitive.append((path, r.status_code, "medium"))
                else:
                    found_info.append((path, r.status_code, "low"))

            elif r.status_code == 403:
                # 403 = موجود لكن محمي — معلومة مفيدة
                found_info.append((path + " (403 Forbidden)", r.status_code, "low"))

        except:
            pass

    for path, status, sev in found_sensitive:
        results.append({
            "name_ar": f"مسار حساس مكشوف: {path}",
            "name_en": f"Sensitive Path Exposed: {path}",
            "desc_ar": f"تم العثور على {path} (HTTP {status}) — قد يحتوي على معلومات حساسة.",
            "desc_en": f"Found {path} (HTTP {status}) — may contain sensitive data.",
            "fix": f"Restrict access to {path} via .htaccess or server config. Remove if not needed.",
            "severity": sev
        })

    for path, status, sev in found_info:
        results.append({
            "name_ar": f"مسار مكتشف: {path}",
            "name_en": f"Path Discovered: {path}",
            "desc_ar": f"تم العثور على {path} (HTTP {status}).",
            "desc_en": f"Found {path} (HTTP {status}).",
            "fix": f"Review if {path} should be publicly accessible.",
            "severity": sev
        })

    if not found_sensitive and not found_info:
        results.append({
            "name_ar": "✓ لم تُكتشف مسارات حساسة",
            "name_en": "✓ No sensitive paths found",
            "desc_ar": "لم يتم العثور على مسارات أو ملفات حساسة مكشوفة.",
            "desc_en": "No exposed sensitive paths or files detected.",
            "fix": "",
            "severity": "safe"
        })

    return results
def full_scan(url, scan_type):
    parsed = urlparse(url)
    hostname = parsed.hostname
    results = []
    if scan_type in ["vuln", "both"]:
        results.extend(check_headers(url))
        results.extend(check_sql_injection(url))
        results.extend(check_xss(url))
        results.extend(check_directories(url))
    if scan_type in ["crypto", "both"]:
        results.extend(check_ssl(url))
    if scan_type == "both" and hostname:
        results.extend(check_ports(hostname))
    return results
