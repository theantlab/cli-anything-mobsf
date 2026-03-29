"""Attack surface analysis — categorised smali/source string scanning."""
import json
import os
import re
import resource
import subprocess
from collections import defaultdict
from pathlib import Path


def _preexec_nice():
    """Lower CPU priority for grep subprocesses."""
    os.nice(10)

# ── Categorised search patterns ───────────────────────────────────────
# Each category maps to a list of (pattern, description) tuples.
# Patterns are literal strings matched with grep -F semantics.

CATEGORIES = {
    "Debugging & Instrumentation": {
        "description": "Hooks into debugging APIs or instrumentation frameworks that may be exploitable or indicate weak protections.",
        "risk": "HIGH",
        "patterns": [
            ("isDebuggerConnected", "Java debugger detection check"),
            ("Debug.isDebuggerConnected", "Explicit debugger detection"),
            ("android.os.Debug", "Debug class usage"),
            ("BuildConfig.DEBUG", "Debug build flag reference"),
            ("setDebuggable", "Debuggable flag manipulation"),
            ("StrictMode", "StrictMode policy (may leak info in debug)"),
        ],
    },
    "Hooking Framework Detection": {
        "description": "References to hooking frameworks. Presence may indicate detection logic OR that the app itself uses hooking.",
        "risk": "MEDIUM",
        "patterns": [
            ("Xposed", "Xposed framework reference"),
            ("XposedBridge", "Xposed bridge API"),
            ("XposedHelpers", "Xposed helper class"),
            ("de/robv/android/xposed", "Xposed package path"),
            ("frida", "Frida reference"),
            ("frida-gadget", "Frida gadget injection"),
            ("frida-agent", "Frida agent reference"),
            ("libfrida", "Frida native library"),
            ("substrate", "Cydia Substrate reference"),
            ("cydia", "Cydia reference"),
            ("com.saurik.substrate", "Substrate package"),
        ],
    },
    "Root Detection": {
        "description": "Root/jailbreak detection logic. Weak or bypassable checks expand the attack surface.",
        "risk": "MEDIUM",
        "patterns": [
            ("isRooted", "Root check method"),
            ("rootBeer", "RootBeer library"),
            ("RootTools", "RootTools library"),
            ("RootChecker", "Root checker utility"),
            ("checkRoot", "Root check method"),
            ("/system/app/Superuser", "Superuser app path check"),
            ("/system/xbin/su", "su binary path check"),
            ("/sbin/su", "su binary path check"),
            ("/system/bin/su", "su binary path check"),
            ("/data/local/su", "su binary path check"),
            ("/data/local/bin/su", "su binary path check"),
            ("com.noshufou.android.su", "SuperUser package check"),
            ("com.thirdparty.superuser", "Third-party superuser check"),
            ("eu.chainfire.supersu", "SuperSU package check"),
            ("com.koushikdutta.superuser", "Koush superuser check"),
            ("com.topjohnwu.magisk", "Magisk package check"),
            ("magisk", "Magisk reference"),
            ("magiskhide", "MagiskHide reference"),
            ("test-keys", "Test signing keys check"),
            ("ro.build.tags", "Build tags property check"),
            ("ro.debuggable", "Debuggable property check"),
            ("ro.secure", "Secure property check"),
        ],
    },
    "Cryptography": {
        "description": "Cryptographic API usage. Weak algorithms, modes, or padding schemes are direct vulnerabilities.",
        "risk": "HIGH",
        "patterns": [
            ("AES/ECB", "ECB mode — no diffusion, ciphertext patterns leak"),
            ("AES/CBC", "CBC mode — vulnerable to padding oracle if not authenticated"),
            ("AES/GCM", "GCM mode — authenticated encryption (good)"),
            ("AES/CTR", "CTR mode — needs unique nonces"),
            ("DES", "DES — 56-bit key, broken"),
            ("3DES", "Triple DES — deprecated, slow"),
            ("TripleDES", "Triple DES reference"),
            ("Blowfish", "Blowfish — aging algorithm"),
            ("PKCS5Padding", "PKCS5 padding (potential oracle)"),
            ("PKCS7Padding", "PKCS7 padding (potential oracle)"),
            ("NoPadding", "No padding — may indicate stream cipher or manual padding"),
            ("SecretKeySpec", "Symmetric key construction"),
            ("IvParameterSpec", "IV construction — check for static/predictable IVs"),
            ("KeyGenerator", "Key generation"),
            ("KeyPairGenerator", "Asymmetric key pair generation"),
            ("javax/crypto", "Java crypto package usage"),
            ("javax.crypto.Cipher", "Cipher API"),
            ("BouncyCastle", "BouncyCastle crypto provider"),
            ("Spongy", "SpongyCastle crypto provider"),
            ("RSA", "RSA algorithm usage"),
            ("ChaCha20", "ChaCha20 stream cipher"),
        ],
    },
    "Weak Hashing": {
        "description": "Hash algorithm usage. MD5 and SHA-1 are broken for security purposes.",
        "risk": "HIGH",
        "patterns": [
            ("MD5", "MD5 — collision attacks practical since 2004"),
            ("SHA-1", "SHA-1 — collision demonstrated (SHAttered, 2017)"),
            ("SHA1", "SHA-1 variant spelling"),
            ("MessageDigest.getInstance", "Hash algorithm instantiation"),
            ("PBKDF2", "Password-based key derivation"),
            ("bcrypt", "bcrypt password hashing"),
            ("scrypt", "scrypt key derivation"),
            ("Argon2", "Argon2 key derivation (strongest)"),
        ],
    },
    "Hardcoded Credentials & Secrets": {
        "description": "Potential hardcoded credentials, API keys, tokens. Direct path to account compromise or API abuse.",
        "risk": "CRITICAL",
        "patterns": [
            ("password", "Password string reference"),
            ("passwd", "Password variant"),
            ("passphrase", "Passphrase reference"),
            ("secret", "Secret reference"),
            ("secretKey", "Secret key reference"),
            ("secret_key", "Secret key reference"),
            ("SECRET_KEY", "Secret key constant"),
            ("api_key", "API key reference"),
            ("apikey", "API key variant"),
            ("API_KEY", "API key constant"),
            ("api_secret", "API secret reference"),
            ("access_token", "Access token reference"),
            ("accessToken", "Access token variant"),
            ("ACCESS_TOKEN", "Access token constant"),
            ("refresh_token", "Refresh token reference"),
            ("auth_token", "Auth token reference"),
            ("private_key", "Private key reference"),
            ("privateKey", "Private key variant"),
            ("PRIVATE_KEY", "Private key constant"),
            ("master_key", "Master key reference"),
            ("encryption_key", "Encryption key reference"),
            ("signing_key", "Signing key reference"),
            ("client_secret", "OAuth client secret"),
            ("client_id", "OAuth client ID"),
            ("app_secret", "App secret reference"),
            ("app_key", "App key reference"),
        ],
    },
    "Authentication & Session Management": {
        "description": "Authentication flows and session handling. Weaknesses here enable account takeover.",
        "risk": "HIGH",
        "patterns": [
            ("username", "Username reference"),
            ("login", "Login flow reference"),
            ("authenticate", "Authentication method"),
            ("Authorization", "Authorization header"),
            ("session_id", "Session ID reference"),
            ("sessionId", "Session ID variant"),
            ("JSESSIONID", "Java session ID"),
            ("OAuth", "OAuth protocol"),
            ("oauth2", "OAuth 2.0"),
            ("JWT", "JSON Web Token"),
            ("jsonwebtoken", "JWT library"),
            ("BasicAuth", "Basic authentication"),
            ("SAML", "SAML protocol"),
            ("BiometricPrompt", "Biometric authentication API"),
            ("FingerprintManager", "Fingerprint API (deprecated)"),
            ("KeyguardManager", "Device lock check"),
        ],
    },
    "Network & TLS Configuration": {
        "description": "Network security configuration. Weak TLS, disabled certificate validation, or cleartext traffic are critical.",
        "risk": "CRITICAL",
        "patterns": [
            ("TrustManager", "Custom TrustManager — may disable cert validation"),
            ("X509TrustManager", "X.509 trust manager — check for empty implementations"),
            ("HostnameVerifier", "Hostname verifier — check for ALLOW_ALL"),
            ("SSLSocketFactory", "Custom SSL socket factory"),
            ("SSLContext", "SSL context configuration"),
            ("ALLOW_ALL_HOSTNAME_VERIFIER", "Hostname verification disabled"),
            ("setHostnameVerifier", "Custom hostname verification"),
            ("checkServerTrusted", "Server certificate validation — empty = vulnerability"),
            ("checkClientTrusted", "Client certificate validation"),
            ("SSLCertificateSocketFactory", "SSL socket factory"),
            ("cleartext", "Cleartext traffic reference"),
            ("cleartextTrafficPermitted", "Cleartext traffic policy"),
            ("onReceivedSslError", "WebView SSL error handler — check for proceed()"),
            ("CertificatePinner", "Certificate pinning implementation"),
            ("ssl-pinning", "SSL pinning reference"),
            (".pem", "PEM certificate file"),
            (".crt", "Certificate file"),
            (".p12", "PKCS12 keystore"),
            (".bks", "BouncyCastle keystore"),
            (".jks", "Java keystore"),
            ("NetworkSecurityPolicy", "Network security policy API"),
        ],
    },
    "HTTP Client Libraries": {
        "description": "HTTP client libraries in use. Understanding the networking stack reveals interception points.",
        "risk": "INFO",
        "patterns": [
            ("OkHttp", "OkHttp client library"),
            ("okhttp3", "OkHttp3 package"),
            ("Retrofit", "Retrofit REST client"),
            ("retrofit2", "Retrofit2 package"),
            ("Volley", "Volley HTTP library"),
            ("HttpURLConnection", "Standard HTTP connection"),
            ("HttpsURLConnection", "Standard HTTPS connection"),
        ],
    },
    "WebView Attack Surface": {
        "description": "WebView configuration. JavaScript bridges and file access create code execution and data exfiltration paths.",
        "risk": "HIGH",
        "patterns": [
            ("addJavascriptInterface", "JS-to-Java bridge — RCE on Android < 4.2"),
            ("setJavaScriptEnabled", "JavaScript enabled in WebView"),
            ("evaluateJavascript", "JS evaluation from native code"),
            ("loadUrl", "URL loading in WebView"),
            ("loadData", "Data loading in WebView"),
            ("loadDataWithBaseURL", "Data loading with base URL"),
            ("setAllowFileAccess", "File access from WebView"),
            ("setAllowFileAccessFromFileURLs", "File URL access — data exfiltration risk"),
            ("setAllowUniversalAccessFromFileURLs", "Universal file access — critical if enabled"),
            ("setAllowContentAccess", "Content provider access from WebView"),
            ("shouldOverrideUrlLoading", "URL interception handler"),
        ],
    },
    "Insecure Data Storage": {
        "description": "Local data storage mechanisms. World-readable/writable files and unencrypted databases expose sensitive data.",
        "risk": "HIGH",
        "patterns": [
            ("SharedPreferences", "Shared preferences storage"),
            ("getSharedPreferences", "Shared preferences access"),
            ("MODE_WORLD_READABLE", "World-readable file mode — CRITICAL"),
            ("MODE_WORLD_WRITEABLE", "World-writable file mode — CRITICAL"),
            ("SQLiteDatabase", "SQLite database usage"),
            ("rawQuery", "Raw SQL query — injection risk"),
            ("execSQL", "SQL execution — injection risk"),
            ("openOrCreateDatabase", "Database creation"),
            ("getExternalStorage", "External storage access"),
            ("getExternalFilesDir", "External files directory"),
            ("openFileOutput", "File output stream"),
            ("EncryptedSharedPreferences", "Encrypted preferences (good)"),
            ("SqlCipher", "Encrypted database (good)"),
            ("RoomDatabase", "Room ORM database"),
        ],
    },
    "Information Leakage via Logging": {
        "description": "Logging statements that may expose sensitive data in logcat, readable by any app on older Android versions.",
        "risk": "MEDIUM",
        "patterns": [
            ("Log.d", "Debug log"),
            ("Log.v", "Verbose log"),
            ("Log.i", "Info log"),
            ("Log.e", "Error log"),
            ("Log.w", "Warning log"),
            ("Log.wtf", "WTF (What a Terrible Failure) log"),
            ("System.out.print", "System output print"),
            ("System.err.print", "System error print"),
            ("printStackTrace", "Stack trace print — leaks internals"),
            ("Timber", "Timber logging library"),
        ],
    },
    "IPC & Intent Attack Surface": {
        "description": "Inter-process communication. Exported components and unprotected intents enable injection and data theft.",
        "risk": "HIGH",
        "patterns": [
            ("sendBroadcast", "Broadcast — receivable by other apps if unprotected"),
            ("sendOrderedBroadcast", "Ordered broadcast"),
            ("sendStickyBroadcast", "Sticky broadcast — deprecated, data persists"),
            ("registerReceiver", "Dynamic receiver registration"),
            ("PendingIntent", "Pending intent — check for mutability"),
            ("FLAG_GRANT_READ_URI_PERMISSION", "URI read permission grant"),
            ("FLAG_GRANT_WRITE_URI_PERMISSION", "URI write permission grant"),
            ("deep_link", "Deep link handler"),
            ("deeplink", "Deep link reference"),
            ("ContentProvider", "Content provider — check export status"),
            ("ContentResolver", "Content resolver access"),
            ("FileProvider", "File provider"),
        ],
    },
    "Sensitive Data & PII Handling": {
        "description": "Personal and financial data handling. Identifies what sensitive data the app processes.",
        "risk": "HIGH",
        "patterns": [
            ("creditCard", "Credit card handling"),
            ("credit_card", "Credit card reference"),
            ("cardNumber", "Card number field"),
            ("card_number", "Card number reference"),
            ("cvv", "CVV handling"),
            ("CVC", "CVC handling"),
            ("ssn", "Social security number"),
            ("social_security", "Social security reference"),
            ("dateOfBirth", "Date of birth"),
            ("phone_number", "Phone number"),
            ("phoneNumber", "Phone number variant"),
            ("getLastKnownLocation", "Location access"),
            ("LocationManager", "Location manager API"),
            ("FusedLocationProvider", "Fused location API"),
            ("IMEI", "Device IMEI access"),
            ("IMSI", "SIM IMSI access"),
            ("getDeviceId", "Device ID retrieval"),
            ("getSubscriberId", "Subscriber ID retrieval"),
            ("getSimSerialNumber", "SIM serial number"),
            ("TelephonyManager", "Telephony API"),
            ("AccountManager", "Account manager"),
            ("ClipboardManager", "Clipboard access"),
        ],
    },
    "Financial & Payment": {
        "description": "Payment processing and financial transaction handling.",
        "risk": "CRITICAL",
        "patterns": [
            ("wallet", "Wallet functionality"),
            ("payment", "Payment processing"),
            ("transaction", "Transaction handling"),
            ("billing", "Billing reference"),
            ("InAppBilling", "In-app billing"),
            ("GooglePay", "Google Pay integration"),
            ("PayPal", "PayPal integration"),
            ("Stripe", "Stripe integration"),
            ("Braintree", "Braintree integration"),
            ("merchantId", "Merchant ID"),
            ("account_number", "Account number"),
            ("routing_number", "Routing number"),
            ("IBAN", "IBAN reference"),
            ("SWIFT", "SWIFT code"),
            ("PIX", "PIX payment (Brazil)"),
        ],
    },
    "App Integrity & Tamper Detection": {
        "description": "Integrity verification and anti-tampering. Weak checks allow repackaging and modification.",
        "risk": "HIGH",
        "patterns": [
            ("getPackageInfo", "Package info retrieval"),
            ("getInstallerPackageName", "Installer verification"),
            ("checkSignatures", "Signature verification"),
            ("DexClassLoader", "Dynamic DEX loading — code injection vector"),
            ("PathClassLoader", "Path class loading"),
            ("InMemoryDexClassLoader", "In-memory DEX loading"),
            ("loadClass", "Dynamic class loading"),
            ("loadDex", "DEX loading"),
            ("dalvik.system", "Dalvik system package"),
            ("Runtime.exec", "Runtime command execution — injection risk"),
            ("ProcessBuilder", "Process execution"),
            ("System.loadLibrary", "Native library loading"),
            ("System.load", "Native library loading (absolute path)"),
            ("JNI_OnLoad", "JNI initialization"),
            ("SafetyNet", "SafetyNet attestation (deprecated)"),
            ("PlayIntegrity", "Play Integrity API"),
            ("DeviceIntegrity", "Device integrity check"),
            ("AppIntegrity", "App integrity check"),
            ("attestation", "Attestation reference"),
        ],
    },
    "Emulator & VM Detection": {
        "description": "Environment detection checks. Reveals what detection logic exists and how thorough it is.",
        "risk": "MEDIUM",
        "patterns": [
            ("Build.FINGERPRINT", "Build fingerprint check"),
            ("Build.MODEL", "Device model check"),
            ("Build.MANUFACTURER", "Manufacturer check"),
            ("Build.PRODUCT", "Product check"),
            ("Build.HARDWARE", "Hardware check"),
            ("Build.BOARD", "Board check"),
            ("Build.SERIAL", "Serial number check"),
            ("Build.TAGS", "Build tags check"),
            ("goldfish", "Emulator kernel name"),
            ("ranchu", "Emulator kernel name"),
            ("sdk_gphone", "SDK phone emulator"),
            ("emulator", "Emulator reference"),
            ("ANDROID_ID", "Android device ID"),
            ("Settings.Secure", "Secure settings access"),
        ],
    },
    "Anti-Debug & Dynamic Analysis": {
        "description": "Anti-debugging and anti-analysis techniques. Indicates the app's defensive posture.",
        "risk": "MEDIUM",
        "patterns": [
            ("/proc/self/maps", "Process memory map check"),
            ("/proc/self/status", "Process status check"),
            ("/proc/self/cmdline", "Command line check"),
            ("/proc/net/tcp", "Network connection check"),
            ("TracerPid", "Debugger tracer PID check"),
            ("ptrace", "ptrace syscall — anti-debug"),
            ("PTRACE_TRACEME", "ptrace self-trace — prevents attachment"),
            ("anti-debug", "Anti-debug reference"),
            ("antidebug", "Anti-debug variant"),
            ("debugger", "Debugger reference"),
            ("dlopen", "Dynamic library loading"),
            ("dlsym", "Dynamic symbol resolution"),
        ],
    },
    "Protection Vendors": {
        "description": "Commercial protection and obfuscation tools detected. Indicates protection maturity level.",
        "risk": "INFO",
        "patterns": [
            ("ProGuard", "ProGuard obfuscation (basic)"),
            ("R8", "R8 compiler/shrinker"),
            ("DexGuard", "DexGuard (Guardsquare — commercial)"),
            ("DexProtector", "DexProtector (Licel — commercial)"),
            ("iXGuard", "iXGuard (Guardsquare — iOS)"),
            ("Arxan", "Arxan / Digital.ai protection"),
            ("Guardsquare", "Guardsquare vendor reference"),
            ("Promon", "Promon SHIELD"),
            ("Zimperium", "Zimperium zShield"),
            ("Appdome", "Appdome protection"),
            ("Verimatrix", "Verimatrix protection"),
            ("AppShield", "AppShield reference"),
            ("dexprotector", "DexProtector reference"),
            ("Trusteer", "IBM Trusteer"),
        ],
    },
    "Clipboard & Screenshot": {
        "description": "Clipboard and screen capture handling. Sensitive data in clipboard or screenshots is a data leak vector.",
        "risk": "MEDIUM",
        "patterns": [
            ("ClipData", "Clipboard data handling"),
            ("setPrimaryClip", "Setting clipboard content"),
            ("getPrimaryClip", "Reading clipboard content"),
            ("FLAG_SECURE", "Window FLAG_SECURE — prevents screenshots"),
            ("screenCapture", "Screen capture reference"),
        ],
    },
    "Cloud & Backend Services": {
        "description": "Cloud service integrations. Misconfigured backends are a top attack vector.",
        "risk": "HIGH",
        "patterns": [
            ("firebase", "Firebase reference"),
            ("firebaseio.com", "Firebase Realtime Database URL"),
            ("googleapis.com", "Google API endpoint"),
            ("google-services.json", "Google services config file"),
            ("FirebaseMessaging", "Firebase Cloud Messaging"),
            ("FirebaseAuth", "Firebase Authentication"),
            ("FirebaseDatabase", "Firebase Realtime Database"),
            ("FirebaseStorage", "Firebase Storage"),
            ("FirebaseAnalytics", "Firebase Analytics"),
            ("Crashlytics", "Firebase Crashlytics"),
            ("amazonaws.com", "AWS endpoint"),
            ("s3.amazonaws", "S3 bucket reference"),
            ("cognito", "AWS Cognito"),
            ("CloudFront", "AWS CloudFront CDN"),
            ("microsoftonline", "Azure AD / Microsoft endpoint"),
        ],
    },
    "Analytics & Third-Party SDKs": {
        "description": "Third-party analytics and advertising SDKs. Each is a data collection and supply chain risk.",
        "risk": "INFO",
        "patterns": [
            ("Adjust", "Adjust analytics"),
            ("AppsFlyer", "AppsFlyer attribution"),
            ("Branch", "Branch deep linking"),
            ("Mixpanel", "Mixpanel analytics"),
            ("Amplitude", "Amplitude analytics"),
            ("com.facebook.sdk", "Facebook SDK"),
            ("google_app_id", "Google app ID"),
            ("AdMob", "Google AdMob"),
            ("doubleclick", "Google DoubleClick ads"),
        ],
    },
}

# Files/dirs to exclude from scanning
EXCLUDE_PATHS = [
    "smali/android/", "smali/androidx/", "smali/kotlin/", "smali/kotlinx/",
    "smali/javax/", "smali/com/google/android/", "smali/com/google/protobuf/",
    "smali_classes*/android/", "smali_classes*/androidx/",
    "smali_classes*/kotlin/", "smali_classes*/kotlinx/",
    "smali_classes*/javax/",
]


def scan_attack_surface(smali_root, output_dir):
    """Scan smali directory for attack surface patterns and produce structured reports.

    Args:
        smali_root: Path to apktool-decoded app directory (contains smali/)
        output_dir: Path to write reports
    """
    smali_root = Path(smali_root)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    all_findings = []

    for category_name, category_data in CATEGORIES.items():
        cat_findings = []

        for pattern, description in category_data["patterns"]:
            matches = _grep_smali(smali_root, pattern)
            if matches:
                finding = {
                    "pattern": pattern,
                    "description": description,
                    "match_count": len(matches),
                    "files": _summarise_matches(matches),
                }
                cat_findings.append(finding)

        if cat_findings:
            total_matches = sum(f["match_count"] for f in cat_findings)
            results[category_name] = {
                "risk": category_data["risk"],
                "description": category_data["description"],
                "total_matches": total_matches,
                "pattern_hits": len(cat_findings),
                "pattern_total": len(category_data["patterns"]),
                "findings": cat_findings,
            }
            all_findings.append((category_name, category_data["risk"], total_matches, len(cat_findings)))

    # Write JSON report
    (output_dir / "attack_surface.json").write_text(json.dumps(results, indent=2))

    # Write human-readable report
    _write_text_report(results, all_findings, output_dir / "attack_surface_report.txt")

    # Write summary
    _write_summary(results, all_findings, output_dir / "attack_surface_summary.txt")

    return results


def _grep_smali(smali_root, pattern):
    """Search for a pattern in smali files, excluding framework code."""
    matches = []

    # Build exclude args
    exclude_args = []
    for ep in EXCLUDE_PATHS:
        exclude_args.extend(["--exclude-dir", ep.rstrip("/")])

    try:
        result = subprocess.run(
            ["grep", "-rFn", "--include=*.smali", pattern, str(smali_root)],
            capture_output=True, text=True, timeout=30,
            preexec_fn=_preexec_nice,
        )
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                # Filter out framework paths
                rel = line
                skip = False
                for ep in EXCLUDE_PATHS:
                    check = ep.replace("*", "")
                    if check in rel:
                        skip = True
                        break
                if not skip:
                    matches.append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return matches


def _summarise_matches(matches, max_files=10):
    """Group matches by file and return a summary."""
    file_counts = defaultdict(list)

    for match in matches:
        parts = match.split(":", 2)
        if len(parts) >= 3:
            filepath = parts[0]
            line_num = parts[1]
            # Shorten path — keep from smali/ onwards
            short = filepath
            for marker in ["/smali/", "/smali_classes"]:
                idx = filepath.find(marker)
                if idx != -1:
                    short = filepath[idx + 1:]
                    break
            file_counts[short].append(line_num)

    # Sort by match count descending
    sorted_files = sorted(file_counts.items(), key=lambda x: -len(x[1]))

    summary = []
    for filepath, lines in sorted_files[:max_files]:
        summary.append({
            "file": filepath,
            "lines": lines[:5],
            "hit_count": len(lines),
        })

    if len(sorted_files) > max_files:
        summary.append({"note": f"... and {len(sorted_files) - max_files} more files"})

    return summary


def _write_text_report(results, all_findings, output_path):
    """Write a human-readable attack surface report."""
    lines = []
    lines.append("=" * 80)
    lines.append("ATTACK SURFACE ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append("")

    # Risk order
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    sorted_cats = sorted(results.items(), key=lambda x: (risk_order.get(x[1]["risk"], 9), -x[1]["total_matches"]))

    for category_name, cat_data in sorted_cats:
        risk = cat_data["risk"]
        risk_badge = f"[{risk}]"
        lines.append("-" * 80)
        lines.append(f"{risk_badge} {category_name}")
        lines.append(f"    {cat_data['description']}")
        lines.append(f"    Patterns matched: {cat_data['pattern_hits']}/{cat_data['pattern_total']}  |  Total hits: {cat_data['total_matches']}")
        lines.append("")

        for finding in sorted(cat_data["findings"], key=lambda f: -f["match_count"]):
            lines.append(f"  * {finding['pattern']}  ({finding['match_count']} hits)")
            lines.append(f"    {finding['description']}")
            for finfo in finding["files"]:
                if "note" in finfo:
                    lines.append(f"      {finfo['note']}")
                else:
                    line_str = ",".join(finfo["lines"][:3])
                    if finfo["hit_count"] > 3:
                        line_str += f" (+{finfo['hit_count'] - 3} more)"
                    lines.append(f"      {finfo['file']}:{line_str}")
            lines.append("")

    Path(output_path).write_text("\n".join(lines))


def _write_summary(results, all_findings, output_path):
    """Write a concise attack surface summary."""
    lines = []
    lines.append("ATTACK SURFACE SUMMARY")
    lines.append("=" * 60)
    lines.append("")

    # Count by risk
    risk_counts = defaultdict(int)
    risk_matches = defaultdict(int)
    for cat_name, cat_data in results.items():
        risk_counts[cat_data["risk"]] += 1
        risk_matches[cat_data["risk"]] += cat_data["total_matches"]

    lines.append("Risk Distribution:")
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        if risk in risk_counts:
            lines.append(f"  {risk:10s}  {risk_counts[risk]:3d} categories  {risk_matches[risk]:6d} matches")
    lines.append("")

    total_matches = sum(c["total_matches"] for c in results.values())
    total_patterns = sum(c["pattern_hits"] for c in results.values())
    lines.append(f"Total: {total_patterns} patterns matched across {len(results)} categories ({total_matches} hits)")
    lines.append("")

    # Top findings by category
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    lines.append("Categories (by risk then volume):")
    lines.append(f"  {'Risk':10s}  {'Category':<45s}  {'Hits':>6s}  {'Patterns':>8s}")
    lines.append(f"  {'-'*10}  {'-'*45}  {'-'*6}  {'-'*8}")

    sorted_cats = sorted(results.items(), key=lambda x: (risk_order.get(x[1]["risk"], 9), -x[1]["total_matches"]))
    for cat_name, cat_data in sorted_cats:
        lines.append(f"  {cat_data['risk']:10s}  {cat_name:<45s}  {cat_data['total_matches']:6d}  {cat_data['pattern_hits']:3d}/{cat_data['pattern_total']:<3d}")

    lines.append("")
    lines.append("Key Attack Vectors:")
    lines.append("")

    # Auto-generate key observations
    if "Network & TLS Configuration" in results:
        tls = results["Network & TLS Configuration"]
        dangerous_tls = [f for f in tls["findings"] if f["pattern"] in
                        ("ALLOW_ALL_HOSTNAME_VERIFIER", "checkServerTrusted", "onReceivedSslError", "cleartext", "cleartextTrafficPermitted")]
        if dangerous_tls:
            lines.append("  [!] NETWORK: Potentially unsafe TLS configuration detected")
            for f in dangerous_tls:
                lines.append(f"      - {f['pattern']}: {f['match_count']} occurrences")

    if "Hardcoded Credentials & Secrets" in results:
        creds = results["Hardcoded Credentials & Secrets"]
        lines.append(f"  [!] SECRETS: {creds['total_matches']} potential hardcoded credential references across {creds['pattern_hits']} patterns")

    if "WebView Attack Surface" in results:
        wv = results["WebView Attack Surface"]
        js_bridge = [f for f in wv["findings"] if f["pattern"] == "addJavascriptInterface"]
        if js_bridge:
            lines.append(f"  [!] WEBVIEW: JavaScript bridge (addJavascriptInterface) found — {js_bridge[0]['match_count']} occurrences")

    if "Insecure Data Storage" in results:
        storage = results["Insecure Data Storage"]
        world_rw = [f for f in storage["findings"] if "WORLD" in f["pattern"]]
        if world_rw:
            lines.append(f"  [!] STORAGE: World-readable/writable files detected")

    if "Financial & Payment" in results:
        fin = results["Financial & Payment"]
        lines.append(f"  [!] FINANCIAL: Payment/financial code detected ({fin['total_matches']} references)")

    if "Information Leakage via Logging" in results:
        log = results["Information Leakage via Logging"]
        lines.append(f"  [!] LOGGING: {log['total_matches']} logging statements found in app code")

    Path(output_path).write_text("\n".join(lines))
