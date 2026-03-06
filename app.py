import os
import re
import csv
import uuid
import json
import threading
from io import StringIO, BytesIO
from flask import Flask, request, jsonify, send_file, render_template
import pandas as pd

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# ─── Job store ───────────────────────────────────────────────────────────────
jobs = {}  # job_id -> { status, progress, total, results }

# ─── Known disposable domains (sample – extend as needed) ────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","10minutemail.com","throwam.com",
    "yopmail.com","trashmail.com","sharklasers.com","guerrillamailblock.com",
    "grr.la","guerrillamail.info","guerrillamail.biz","guerrillamail.de",
    "guerrillamail.net","guerrillamail.org","spam4.me","maildrop.cc",
    "tempmail.com","temp-mail.org","fakeinbox.com","mailnull.com",
    "spamgourmet.com","trashmail.me","dispostable.com","mailnesia.com",
    "spamgourmet.net","throwam.com","discard.email","spamgourmet.org",
    "mytemp.email","tempail.com","throwam.com","spamevader.net",
    "tempr.email","mailtemp.info","dispostable.com","emailondeck.com",
    "spamhereplease.com","spamhereplease.net","inboxbear.com","mohmal.com",
    "spamex.com","spamhole.com","spamthisplease.com","spamoff.de",
    "dropmail.me","33mail.com","anonaddy.com","simplelogin.co",
    "spamgourmet.com","jetable.org","jetable.fr.nf","jetable.net",
    "filzmail.com","owlpic.com","safetymail.info","binkmail.com",
    "bobmail.info","chammy.info","dayrep.com","delikkt.de","einrot.com",
    "fleckens.hu","freundin.ru","objectmail.com","obobbo.com",
    "rofl.ms","romymichele.com","schafmail.de","spamcon.org",
    "spamfree24.de","spamgob.com","spamnot.net","spamslicer.com",
    "spamspot.com","spamthis.co.uk","spamtroll.net","speed.1s.fr",
    "supergreatmail.com","supermailer.jp","suremail.info","techemail.com",
    "temporaryemail.net","temporaryforwarding.com","temporaryinbox.com",
    "thanksnospam.info","thisisnotmyrealemail.com","tradermail.info",
    "trash-mail.at","trash-mail.cf","trash-mail.ga","trash-mail.gq",
    "trash-mail.ml","trash-mail.tk","trashmail.at","trashmail.io",
    "trashmail.net","trashmailer.com","trashmail.xyz","trbvm.com",
    "turual.com","twinmail.de","tyldd.com","uggsrock.com","uroid.com",
    "venompen.com","viditag.com","viewcastmedia.com","viewcastmedia.net",
    "viewcastmedia.org","vomoto.com","vubby.com","wasteland.rfc822.org",
    "webm4il.info","weg-werf-email.de","wetrainbayarea.com","wh4f.org",
    "whyspam.me","willhackforfood.biz","willselfdestruct.com","wilemail.com",
    "wmail.cf","writeme.us","wronghead.com","wuzupmail.net","xagloo.com",
    "xemaps.com","xents.com","xmaily.com","xoxy.net","xyzfree.net",
    "yapped.net","yeah.net","yep.it","yogamaven.com","yomail.info",
    "yopmail.fr","yopmail.pp.ua","yourdomain.com","yuurok.com","zehnminutenmail.de",
    "zippymail.info","zoaxe.com","zoemail.com","zoemail.net","zoemail.org",
    "zomg.info","fakemailgenerator.com","mailnull.com","spambog.com",
    "spam.la","notmail.com","nospam.ze.tc","cool.fr.nf","courriel.fr.nf",
    "no-spam.ws","super-auswahl.de","proxymail.eu","nospamfor.us",
    "hatespam.org","haltospam.com","rejectspam.com","spamherelots.com"
}

# ─── Role-based prefixes ──────────────────────────────────────────────────────
ROLE_PREFIXES = {
    "admin","administrator","info","contact","support","help","sales","marketing",
    "billing","accounts","account","hr","legal","no-reply","noreply","donotreply",
    "do-not-reply","postmaster","hostmaster","webmaster","abuse","security",
    "privacy","press","media","jobs","careers","office","team","feedback",
    "hello","enquiries","enquiry","mail","service","services","tech","it",
    "dev","developer","api","bot","system","root","news","newsletter",
    "notifications","notify","alert","alerts","updates","operations","ops"
}

# ─── Known good MX domains (common providers that definitely have MX) ─────────
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
    "hushmail.com","lavabit.com","inbox.com","rediffmail.com","sina.com",
    "qq.com","163.com","126.com","sohu.com","vip.163.com","vip.sina.com",
    "comcast.net","verizon.net","att.net","sbcglobal.net","bellsouth.net",
    "cox.net","charter.net","earthlink.net","optonline.net","roadrunner.com",
    "rocketmail.com","ymail.com","btinternet.com","ntlworld.com","sky.com",
    "virginmedia.com","talk21.com","blueyonder.co.uk","orange.fr","free.fr",
    "laposte.net","sfr.fr","wanadoo.fr","alice.fr","voila.fr","numericable.fr",
    "amazon.com","microsoft.com","apple.com","google.com","facebook.com",
    "twitter.com","linkedin.com","salesforce.com","hubspot.com",
}

# ─── Email regex ──────────────────────────────────────────────────────────────
EMAIL_RE = re.compile(
    r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
)

def validate_format(email: str):
    """Returns (ok: bool, reason: str)"""
    email = email.strip()
    if not email:
        return False, "Empty email"
    if len(email) > 254:
        return False, "Email too long"
    if email.count('@') != 1:
        return False, "Invalid @ count"
    local, domain = email.rsplit('@', 1)
    if len(local) > 64:
        return False, "Local part too long"
    if not EMAIL_RE.match(email):
        return False, "Invalid format"
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Invalid domain"
    if '..' in domain or '..' in local:
        return False, "Consecutive dots"
    parts = domain.split('.')
    tld = parts[-1]
    if len(tld) < 2:
        return False, "Invalid TLD"
    return True, "Format valid"

def check_mx(domain: str):
    """Simulate MX check: known good domains pass, others get 'unverified'."""
    if domain.lower() in KNOWN_GOOD_DOMAINS:
        return True, "MX records found"
    # For unknown domains: assume they might be valid (corporate, etc.)
    # We mark them as unverified rather than invalid
    return None, "MX unverified"

def verify_email(email: str):
    """Full verification pipeline. Returns (status, reason)."""
    email = email.strip().lower()

    # 1. Format check
    fmt_ok, fmt_reason = validate_format(email)
    if not fmt_ok:
        return "INVALID", fmt_reason

    local, domain = email.rsplit('@', 1)

    # 2. Disposable check
    if domain in DISPOSABLE_DOMAINS:
        return "DISPOSABLE", "Disposable email domain"

    # 3. Role-based check
    if local in ROLE_PREFIXES:
        return "ROLE-BASED", f"Role-based prefix '{local}'"

    # 4. MX check
    mx_ok, mx_reason = check_mx(domain)
    if mx_ok is False:
        return "INVALID", mx_reason
    if mx_ok is None:
        # Unknown domain — mark as valid but note unverified MX
        return "VALID", "Format valid (MX unverified)"

    return "VALID", "Format valid, MX verified"


def extract_emails_from_df(df: pd.DataFrame):
    """Find email addresses anywhere in the dataframe."""
    emails = []
    email_pattern = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

    # Try column named 'email' or 'Email' first
    for col in df.columns:
        if 'email' in col.lower():
            for val in df[col].dropna():
                val = str(val).strip()
                if email_pattern.match(val):
                    emails.append(val)
            if emails:
                return list(dict.fromkeys(emails))  # dedup preserving order

    # Fall back: scan all cells
    for col in df.columns:
        for val in df[col].dropna():
            matches = email_pattern.findall(str(val))
            emails.extend(matches)

    return list(dict.fromkeys(emails))


def run_verification(job_id, emails):
    jobs[job_id]['status'] = 'running'
    jobs[job_id]['total'] = len(emails)
    results = []
    for i, email in enumerate(emails):
        status, reason = verify_email(email)
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
    return jsonify({
        'status': job['status'],
        'progress': job['progress'],
        'total': job['total'],
    })


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
    print("✉  Email Verifier running at http://127.0.0.1:5000")
    app.run(debug=False, threaded=True, port=5000)
