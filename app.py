import os
import re
import csv
import uuid
import json
import socket
import smtplib
import threading
from io import StringIO, BytesIO
from flask import Flask, request, jsonify, send_file, render_template
import pandas as pd

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

os.makedirs('uploads', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# ─── Load fake domains blocklist ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(BASE_DIR, 'fake_domains.json'), 'r') as f:
        _fd = json.load(f)
    FAKE_DOMAINS = set(_fd.get('fake_domains', []))
except Exception:
    FAKE_DOMAINS = set()

# ─── Disposable domains (separate from fake) ─────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","throwam.com",
    "yopmail.com","trashmail.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","guerrillamail.info","guerrillamail.biz","guerrillamail.de",
    "guerrillamail.net","guerrillamail.org","spam4.me","maildrop.cc",
    "tempmail.com","temp-mail.org","fakeinbox.com","mailnull.com",
    "spamgourmet.com","trashmail.me","dispostable.com","mailnesia.com",
    "discard.email","mytemp.email","tempail.com","spamevader.net",
    "tempr.email","mailtemp.info","emailondeck.com","mohmal.com",
    "spamhole.com","spamoff.de","dropmail.me","33mail.com",
    "jetable.org","jetable.net","filzmail.com","owlpic.com",
    "dayrep.com","einrot.com","fleckens.hu","spamcon.org",
    "spamfree24.de","spamspot.com","trashmail.at","trashmail.io",
    "trashmail.net","trashmailer.com","trashmail.xyz","trbvm.com",
    "twinmail.de","venompen.com","weg-werf-email.de","whyspam.me",
    "xagloo.com","zehnminutenmail.de","zippymail.info",
    "fakemailgenerator.com","spambog.com","spam.la",
    "safetymail.info","binkmail.com","bobmail.info",
    "anonaddy.com","simplelogin.co","proxymail.eu",
    "temporaryemail.net","temporaryforwarding.com","temporaryinbox.com",
    "thisisnotmyrealemail.com","trash-mail.at","trash-mail.cf",
    "trash-mail.ga","trash-mail.ml","trash-mail.tk",
    "inboxbear.com","spamhereplease.com","spamherelots.com",
}

# ─── Role-based prefixes ──────────────────────────────────────────────────────
ROLE_PREFIXES = {
    "admin","administrator","info","contact","support","help","sales","marketing",
    "billing","accounts","account","hr","legal","no-reply","noreply","donotreply",
    "do-not-reply","postmaster","hostmaster","webmaster","abuse","security",
    "privacy","press","media","jobs","careers","office","team","feedback",
    "hello","enquiries","enquiry","mail","service","services","tech","it",
    "dev","developer","api","bot","system","root","news","newsletter",
    "notifications","notify","alert","alerts","updates","operations","ops",
    "reception","general","management","director","ceo","cfo","cto",
    "invoice","invoices","finance","payments","orders","returns","warranty",
    "recruitment","hiring","talent","training","education","events",
}

# ─── Known good MX domains ────────────────────────────────────────────────────
KNOWN_GOOD_DOMAINS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com","msn.com",
    "icloud.com","me.com","mac.com","aol.com","protonmail.com","proton.me",
    "zoho.com","yandex.com","yandex.ru","mail.ru","gmx.com","gmx.net",
    "web.de","t-online.de","yahoo.co.uk","yahoo.co.in","yahoo.com.au",
    "yahoo.ca","yahoo.fr","yahoo.de","yahoo.es","yahoo.it","yahoo.co.jp",
    "hotmail.co.uk","hotmail.fr","hotmail.de","hotmail.it","hotmail.es",
    "live.co.uk","live.fr","live.de","live.it","live.es","live.com.au",
    "outlook.fr","outlook.de","outlook.it","outlook.es","outlook.co.uk",
    "fastmail.com","fastmail.fm","hey.com","pm.me","tutanota.com",
    "tutamail.com","tuta.io","keemail.me","mailfence.com","runbox.com",
    "hushmail.com","inbox.com","rediffmail.com","sina.com",
    "qq.com","163.com","126.com","sohu.com","vip.163.com",
    "comcast.net","verizon.net","att.net","sbcglobal.net","bellsouth.net",
    "cox.net","charter.net","earthlink.net","optonline.net","roadrunner.com",
    "rocketmail.com","ymail.com","btinternet.com","ntlworld.com","sky.com",
    "virginmedia.com","talk21.com","blueyonder.co.uk","orange.fr","free.fr",
    "laposte.net","sfr.fr","wanadoo.fr","alice.fr","voila.fr",
    "amazon.com","microsoft.com","apple.com","google.com","facebook.com",
    "twitter.com","linkedin.com","salesforce.com","hubspot.com",
}

# ─── Suspicious local-part patterns ──────────────────────────────────────────
SUSPICIOUS_LOCAL_RE = re.compile(
    r'^(\d{5,}|[a-z]{1,2}\d{4,}|(test|fake|dummy|temp|rand|sample|user|admin)\d*'
    r'|[a-z0-9]{20,}|asdf|qwerty|abcd|1234|xyz\d*)$', re.IGNORECASE
)

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# ─── Job store ────────────────────────────────────────────────────────────────
jobs = {}

# ─── MX lookup via DNS socket ─────────────────────────────────────────────────
def get_mx_host(domain: str):
    """Try to resolve MX via DNS. Returns (mx_host, error_reason)."""
    if domain.lower() in KNOWN_GOOD_DOMAINS:
        # Return known MX hosts for common providers
        mx_map = {
            "gmail.com": "alt1.gmail-smtp-in.l.google.com",
            "yahoo.com": "mta5.am0.yahoodns.net",
            "outlook.com": "outlook-com.olc.protection.outlook.com",
            "hotmail.com": "hotmail-com.olc.protection.outlook.com",
            "live.com": "live-com.olc.protection.outlook.com",
            "protonmail.com": "mail.protonmail.ch",
            "icloud.com": "mx01.mail.icloud.com",
        }
        return mx_map.get(domain.lower(), domain), None

    # Try DNS MX lookup
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX', lifetime=4)
        hosts = sorted(answers, key=lambda r: r.preference)
        return str(hosts[0].exchange).rstrip('.'), None
    except ImportError:
        pass
    except Exception as e:
        err = str(e).lower()
        if 'nxdomain' in err or 'does not exist' in err:
            return None, "Domain does not exist"
        if 'noanswer' in err or 'no answer' in err:
            return None, "No MX records found"
        return None, "MX lookup failed"

    # Fallback: try socket A-record as rough proxy
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return domain, None  # domain resolves, treat as possible MX
    except socket.gaierror:
        return None, "Domain does not exist"
    except Exception:
        return None, "Domain unreachable"


def smtp_verify(mx_host: str, email: str, domain: str):
    """
    Attempt SMTP RCPT TO verification.
    Returns (exists: bool|None, reason: str)
    - True  = mailbox accepted
    - False = mailbox rejected
    - None  = inconclusive (server blocked probe)
    """
    # Skip SMTP probe for domains that are known to block it
    NO_SMTP_PROBE = {
        "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com",
        "msn.com","icloud.com","me.com","mac.com","protonmail.com",
        "proton.me","yandex.com","yandex.ru","mail.ru","zoho.com",
        "fastmail.com","hey.com","tutanota.com","amazon.com",
        "microsoft.com","apple.com","google.com","facebook.com",
        "twitter.com","linkedin.com","qq.com","163.com","126.com",
    }
    if domain.lower() in NO_SMTP_PROBE:
        return None, "SMTP probe skipped (provider blocks it)"

    try:
        server = smtplib.SMTP(timeout=6)
        server.connect(mx_host, 25)
        server.ehlo_or_helo_if_needed()
        server.mail('verify@mailscan.app')
        code, msg = server.rcpt(email)
        server.quit()
        msg_str = msg.decode(errors='ignore').lower() if isinstance(msg, bytes) else str(msg).lower()

        if code == 250:
            return True, "SMTP mailbox verified"
        elif code in (550, 551, 552, 553, 554):
            return False, "SMTP mailbox rejected"
        elif code == 421:
            return None, "SMTP server temporarily unavailable"
        else:
            return None, f"SMTP inconclusive (code {code})"
    except smtplib.SMTPConnectError:
        return None, "SMTP connection failed"
    except smtplib.SMTPServerDisconnected:
        return None, "SMTP server disconnected"
    except (socket.timeout, TimeoutError):
        return None, "SMTP timeout"
    except ConnectionRefusedError:
        return None, "SMTP port blocked"
    except OSError:
        return None, "SMTP network error"
    except Exception as e:
        return None, f"SMTP error: {str(e)[:40]}"


# ─── Format check ─────────────────────────────────────────────────────────────
def validate_format(email: str):
    email = email.strip()
    if not email:
        return False, "Empty email address"
    if len(email) > 254:
        return False, "Email exceeds 254 characters"
    if email.count('@') != 1:
        return False, "Invalid format (@ count)"
    local, domain = email.rsplit('@', 1)
    if len(local) > 64:
        return False, "Local part exceeds 64 characters"
    if not EMAIL_RE.match(email):
        return False, "Format invalid"
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Invalid domain format"
    if '..' in domain or '..' in local:
        return False, "Consecutive dots detected"
    if len(domain.split('.')[-1]) < 2:
        return False, "Invalid TLD"
    return True, "Format valid"


# ─── Master verification pipeline ─────────────────────────────────────────────
def verify_email(email: str):
    """Returns (status, reason) where status is one of:
    VALID, INVALID, DISPOSABLE, ROLE-BASED, UNKNOWN
    """
    email = email.strip().lower()

    # 1. Format
    fmt_ok, fmt_reason = validate_format(email)
    if not fmt_ok:
        return "INVALID", fmt_reason

    local, domain = email.rsplit('@', 1)

    # 2. Fake domain check
    if domain in FAKE_DOMAINS:
        return "INVALID", "Fake domain detected"

    # 3. Disposable check
    if domain in DISPOSABLE_DOMAINS:
        return "DISPOSABLE", "Disposable email domain detected"

    # 4. Role-based check (before suspicious — role prefixes take priority)
    if local in ROLE_PREFIXES:
        return "ROLE-BASED", f"Role-based prefix '{local}'"

    # 5. Suspicious local part (e.g. 12345@anything, test123@, random strings)
    if SUSPICIOUS_LOCAL_RE.match(local):
        if domain not in KNOWN_GOOD_DOMAINS:
            return "INVALID", "Suspicious local part with unverified domain"

    # 6. MX / domain existence check
    mx_host, mx_error = get_mx_host(domain)
    if mx_host is None:
        return "INVALID", mx_error or "Domain does not exist"

    # 7. SMTP verification
    smtp_ok, smtp_reason = smtp_verify(mx_host, email, domain)
    if smtp_ok is False:
        return "INVALID", "SMTP mailbox rejected"
    if smtp_ok is True:
        return "VALID", "SMTP mailbox verified"

    # 8. Inconclusive SMTP — known good domain = VALID, unknown = UNKNOWN
    if domain in KNOWN_GOOD_DOMAINS:
        return "VALID", "MX verified (SMTP probe skipped)"
    return "UNKNOWN", f"MX found — {smtp_reason}"


# ─── Extract emails from dataframe ────────────────────────────────────────────
def extract_emails_from_df(df: pd.DataFrame):
    emails = []
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

    for col in df.columns:
        if 'email' in col.lower():
            for val in df[col].dropna():
                val = str(val).strip()
                if email_pattern.match(val):
                    emails.append(val)
            if emails:
                return list(dict.fromkeys(emails))

    for col in df.columns:
        for val in df[col].dropna():
            for match in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', str(val)):
                emails.append(match)

    return list(dict.fromkeys(emails))


# ─── Background verification worker ──────────────────────────────────────────
def run_verification(job_id, emails):
    jobs[job_id]['status'] = 'running'
    jobs[job_id]['total'] = len(emails)
    results = []
    for i, email in enumerate(emails):
        try:
            status, reason = verify_email(email)
        except Exception as e:
            status, reason = "UNKNOWN", f"Error: {str(e)[:60]}"
        results.append({'email': email, 'status': status, 'reason': reason})
        jobs[job_id]['progress'] = i + 1
        jobs[job_id]['results'] = results
    jobs[job_id]['status'] = 'done'


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    ext = f.filename.rsplit('.', 1)[-1].lower()
    if ext not in ('csv', 'xlsx', 'xls'):
        return jsonify({'error': 'Unsupported file type. Use CSV or Excel.'}), 400
    try:
        if ext == 'csv':
            from io import StringIO
            content = f.read().decode('utf-8', errors='replace')
            df = pd.read_csv(StringIO(content))
        else:
            df = pd.read_excel(BytesIO(f.read()))
    except Exception as e:
        return jsonify({'error': f'Could not parse file: {str(e)}'}), 400

    emails = extract_emails_from_df(df)
    if not emails:
        return jsonify({'error': 'No email addresses found in file.'}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {'status': 'queued', 'progress': 0, 'total': len(emails), 'results': []}
    t = threading.Thread(target=run_verification, args=(job_id, emails), daemon=True)
    t.start()
    return jsonify({'job_id': job_id, 'total': len(emails)})


@app.route('/status/<job_id>')
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify({'status': job['status'], 'progress': job['progress'], 'total': job['total']})


@app.route('/results/<job_id>')
def results(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify({'results': job.get('results', [])})


@app.route('/download/<job_id>/<filter_type>')
def download(job_id, filter_type):
    job = jobs.get(job_id)
    if not job or job['status'] != 'done':
        return jsonify({'error': 'Results not ready'}), 404

    all_results = job['results']
    filter_map = {
        'all': None,
        'valid': 'VALID',
        'invalid': 'INVALID',
        'disposable': 'DISPOSABLE',
        'role': 'ROLE-BASED',
        'unknown': 'UNKNOWN',
    }
    if filter_type not in filter_map:
        return jsonify({'error': 'Unknown filter'}), 400

    status_filter = filter_map[filter_type]
    rows = all_results if status_filter is None else [r for r in all_results if r['status'] == status_filter]

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=['email', 'status', 'reason'])
    writer.writeheader()
    writer.writerows(rows)
    buf.seek(0)

    filename = f"{filter_type}_emails.csv" if filter_type != 'all' else 'email_verification_report.csv'
    return send_file(
        BytesIO(buf.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    print("✉  MailScan running at http://127.0.0.1:5000")
    app.run(debug=False, threaded=True, port=5000)
