from flask import Flask, request, render_template, redirect, send_from_directory, session
import sqlite3, os, random, smtplib, hashlib, time, requests
from email.mime.text import MIMEText
import qrcode
import cv2
import re
import base64
from cryptography.fernet import Fernet

# ===========================================================
# LOCAL HTTPS CERT GENERATOR (no OpenSSL required)
# ===========================================================
def generate_https_cert():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    import ipaddress
    import os

    # If certificate already exists, skip
    if os.path.exists("cert.pem") and os.path.exists("key.pem"):
        print("✔ HTTPS certificates already exist.")
        return

    print("🔒 Generating HTTPS certificates (cert.pem, key.pem)...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Local"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"LocalDev"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"HELIX Dev Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)

    alt_names = [
        x509.DNSName(u"localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open("key.pem", "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✔ HTTPS Certificate Created Successfully!")


# ===========================================================
# MAIN HELIX APP CONFIG
# ===========================================================
app = Flask(__name__)
app.secret_key = "HELIX_SUPER_SECRET_KEY"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security.db")
INTRUDER_DIR = os.path.join(BASE_DIR, "intruders")
QR_DIR = os.path.join(BASE_DIR, "qr_codes")

EMAIL_USER = "helix.auth.system@gmail.com"
EMAIL_PASS = "yazp aocq kmwx bhls"
EMAIL_FROM_NAME = "H.E.L.I.X Security System"

AUTO_LOGOUT_SECONDS = 900  # 15 minutes
failed_attempts = {}
MAX_ATTEMPTS = 5

# -----------------------------------------------------------
# AES ENCRYPTION HELPERS (FERNET = AES128 + HMAC)
# -----------------------------------------------------------
def aes_key_from_secret(secret: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())

AES_KEY = aes_key_from_secret(app.secret_key)
cipher = Fernet(AES_KEY)

def aes_encrypt(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def aes_decrypt(token: str) -> str:
    return cipher.decrypt(token.encode()).decode()

# -----------------------------------------------------------
# PASSWORD CHECK & HASH
# -----------------------------------------------------------
def is_strong_password(pw: str) -> bool:
    return (
        len(pw) >= 8 and
        re.search(r"[A-Z]", pw) and
        re.search(r"[a-z]", pw) and
        re.search(r"\d", pw) and
        re.search(r"[^A-Za-z0-9]", pw)
    )

def hash_pw(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()

# -----------------------------------------------------------
# EMAIL OTP (for MFA / verification / reset)
# -----------------------------------------------------------
def send_email_otp(to_email, code, purpose="Verification"):
    msg = MIMEText(f"Your HELIX {purpose} code is:\n\n{code}")
    msg["Subject"] = f"H.E.L.I.X {purpose} Code"
    msg["From"] = EMAIL_FROM_NAME
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(EMAIL_USER, EMAIL_PASS)
            s.send_message(msg)
    except Exception as e:
        print("[EMAIL ERROR]", e)

# -----------------------------------------------------------
# GENERIC SECURITY ALERT EMAILS
# -----------------------------------------------------------
def send_security_email(to_email, subject, message):
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = EMAIL_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
    except Exception as e:
        print("[EMAIL ERROR - SECURITY ALERT]", e)

# -----------------------------------------------------------
# DATABASE INIT
# -----------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Add name column in new DBs
    c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            verified INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            sec_q1 TEXT,
            sec_a1_hash TEXT,
            sec_q2 TEXT,
            sec_a2_hash TEXT,
            sec_q3 TEXT,
            sec_a3_hash TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            ip TEXT,
            geo TEXT,
            event TEXT,
            details TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS email_verification(
            email TEXT PRIMARY KEY,
            code TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            device_id TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            pw_hash TEXT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # If DB already exists without a name column, try to add it
    try:
        c.execute("ALTER TABLE users ADD COLUMN name TEXT")
    except sqlite3.OperationalError:
        # Column already exists or cannot be added; ignore
        pass

    conn.commit()
    conn.close()

# -----------------------------------------------------------
# GEO + LOGGING (encrypted events)
# -----------------------------------------------------------
def lookup_geoip(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        j = r.json()
        return ", ".join([j.get("city", ""), j.get("region", ""), j.get("country", "")])
    except:
        return "Unknown"

def log_event(email, ip, event, details=""):
    geo = lookup_geoip(ip or "unknown")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        event_enc = aes_encrypt(event)
        details_enc = aes_encrypt(details)
    except Exception:
        event_enc = event
        details_enc = details

    c.execute(
        "INSERT INTO logs(email,ip,geo,event,details) VALUES(?,?,?,?,?)",
        (email, ip, geo, event_enc, details_enc)
    )
    conn.commit()
    conn.close()

# -----------------------------------------------------------
# CAMERA CAPTURE (per-user intruder folder, kept for future use)
# -----------------------------------------------------------
def capture_intruder(email, ip):
    safe_email = (email or "UNKNOWN").replace("@", "_AT_")
    user_dir = os.path.join(INTRUDER_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)

    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()

    if ret:
        fname = f"intruder_{ip.replace('.', '_')}_{int(time.time())}.jpg"
        cv2.imwrite(os.path.join(user_dir, fname), frame)
        log_event(email or "UNKNOWN", ip, "INTRUDER_CAPTURED", fname)

    cam.release()
    cv2.destroyAllWindows()

# -----------------------------------------------------------
# USER LOOKUP
# -----------------------------------------------------------
def get_user(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT id, name, username, password_hash, role, verified, locked,
               sec_q1, sec_a1_hash,
               sec_q2, sec_a2_hash,
               sec_q3, sec_a3_hash
        FROM users WHERE username=?
    """, (email,))
    row = c.fetchone()
    conn.close()
    return row

def email_greeting(email):
    user = get_user(email)
    if user and user[1]:
        return f"Hi {user[1]},"
    return "Hi,"

# -----------------------------------------------------------
# AUTO LOGOUT ON INACTIVITY
# -----------------------------------------------------------
@app.before_request
def auto_logout():
    if "user" in session:
        last = session.get("last_active", 0)
        now = time.time()

        if last and (now - last > AUTO_LOGOUT_SECONDS):
            session.clear()
            return redirect("/")

        session["last_active"] = now

    return None

# ===========================================================
# SIGNUP (account created ONLY AFTER verification code is correct)
# ===========================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = ""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        pw = request.form.get("password", "")
        conf = request.form.get("confirm", "")

        sec_q1 = request.form.get("sec_q1", "")
        sec_a1 = request.form.get("sec_a1", "")
        sec_q2 = request.form.get("sec_q2", "")
        sec_a2 = request.form.get("sec_a2", "")
        sec_q3 = request.form.get("sec_q3", "")
        sec_a3 = request.form.get("sec_a3", "")

        if not name:
            msg = "Please enter your name."
        elif not email:
            msg = "Please enter email."
        elif "@" not in email:
            msg = "Invalid email."
        elif pw != conf:
            msg = "Passwords do not match."
        elif not is_strong_password(pw):
            msg = "Weak password. Use uppercase, lowercase, digits, symbol."
        elif not sec_q1 or not sec_q2 or not sec_q3:
            msg = "Select all security questions."
        elif not sec_a1 or not sec_a2 or not sec_a3:
            msg = "Answer all 3 questions."
        elif len({sec_q1, sec_q2, sec_q3}) < 3:
            msg = "Please choose 3 different security questions."
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT 1 FROM users WHERE username=?", (email,))
            existing = c.fetchone()
            if existing:
                conn.close()
                msg = "Email already registered."
                return render_template("signup.html", msg=msg)

            pending = {
                "name": name,
                "email": email,
                "password_hash": hash_pw(pw),
                "sec_q1": sec_q1,
                "sec_a1_hash": hash_pw(sec_a1.lower().strip() + app.secret_key),
                "sec_q2": sec_q2,
                "sec_a2_hash": hash_pw(sec_a2.lower().strip() + app.secret_key),
                "sec_q3": sec_q3,
                "sec_a3_hash": hash_pw(sec_a3.lower().strip() + app.secret_key),
            }

            session["pending_signup"] = pending

            code = str(random.randint(100000, 999999))
            c.execute(
                "INSERT OR REPLACE INTO email_verification(email,code) VALUES(?,?)",
                (email, code)
            )
            conn.commit()
            conn.close()

            send_email_otp(email, code, purpose="Account Verification")
            log_event(email, request.remote_addr, "SIGNUP_CODE_SENT", "Verification code sent")

            session["verify_email"] = email
            return redirect("/verify")

    return render_template("signup.html", msg=msg)

# ===========================================================
# VERIFY EMAIL (create user ONLY after correct code)
# ===========================================================
@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = session.get("verify_email")
    if not email:
        return redirect("/signup")

    msg = ""
    if request.method == "POST":
        code_entered = request.form.get("code", "").strip()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT code FROM email_verification WHERE email=?", (email,))
        row = c.fetchone()

        if row and row[0] == code_entered:
            pending = session.get("pending_signup")
            if not pending or pending.get("email") != email:
                conn.close()
                msg = "No pending signup found. Please register again."
                return render_template("verify.html", msg=msg, email=email)

            # Decide role (admin if first user)
            c.execute("SELECT COUNT(*) FROM users")
            user_count = c.fetchone()[0]
            role = "admin" if user_count == 0 else "user"

            # Insert user with verified=1
            c.execute("""
                INSERT INTO users(
                    name, username, password_hash, role, verified,
                    sec_q1, sec_a1_hash,
                    sec_q2, sec_a2_hash,
                    sec_q3, sec_a3_hash
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (
                pending["name"],
                pending["email"],
                pending["password_hash"],
                role,
                1,  # verified
                pending["sec_q1"], pending["sec_a1_hash"],
                pending["sec_q2"], pending["sec_a2_hash"],
                pending["sec_q3"], pending["sec_a3_hash"],
            ))

            c.execute("DELETE FROM email_verification WHERE email=?", (email,))
            conn.commit()
            conn.close()

            session.pop("pending_signup", None)
            session.pop("verify_email", None)

            # Personalized welcome email using name
            send_security_email(
                email,
                "Welcome to HELIX Security System!",
                f"""
Hi {pending['name']},

Thank you for registering with the HELIX Cybersecurity System!

HELIX offers:
• Multi-factor authentication with trusted devices
• Intelligent intruder detection via camera
• QR-based identity verification
• Device trust management and sign-out from all devices
• Lockout protection and real-time security logs

We are committed to keeping your digital identity safe.

Best regards,
HELIX Security Team
"""
            )

            log_event(email, request.remote_addr, "SIGNUP_COMPLETED", "Account created after email verification")

            return redirect("/")
        else:
            msg = "Incorrect verification code."

    return render_template("verify.html", msg=msg, email=email)

# ===========================================================
# LOGIN (with MFA, logging, intruder logic & liveness trigger)
# ===========================================================
@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"

    if request.method == "GET":
        return render_template("login.html", msg="")

    email = request.form.get("email", "").strip()
    pw = request.form.get("password", "")

    user = get_user(email)

    if not user:
        attempts = failed_attempts.get(ip, 0) + 1
        failed_attempts[ip] = attempts
        log_event(email, ip, "LOGIN_FAIL", "Email not found")
        return render_template("login.html", msg="Invalid email or password.")

    (
        uid, name, stored_email, pw_hash, role, verified, locked,
        sec_q1, a1, sec_q2, a2, sec_q3, a3
    ) = user

    if locked:
        return render_template("login.html", msg="Account locked. Use Unlock option.")

    if not verified:
        session["verify_email"] = email
        return redirect("/verify")

    # ----- WRONG PASSWORD LOGIC WITH ATTEMPT COUNTS -----
    if hash_pw(pw) != pw_hash:
        attempts = failed_attempts.get(ip, 0) + 1
        failed_attempts[ip] = attempts

        log_event(email, ip, "LOGIN_FAIL", f"Wrong password (attempt {attempts})")

        # Attempts 1–3: normal error
        if attempts < 4:
            return render_template("login.html", msg="Invalid email or password.")

        # Attempt 4: warning
        if attempts == 4:
            return render_template(
                "login.html",
                msg="Invalid email or password. WARNING: Next failed attempt will trigger identity verification and may lock your account."
            )

        # Attempt 5: redirect to liveness camera
        if attempts == 5:
            session["verify_identity_email"] = email
            return redirect("/verify_identity")

        # Attempt 6+: lock account
        if attempts >= 6:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET locked=1 WHERE username=?", (email,))
            conn.commit()
            conn.close()

            log_event(email, ip, "ACCOUNT_LOCKED", "Too many failed attempts")

            greet = email_greeting(email)
            send_security_email(
                email,
                "URGENT: HELIX Account Locked",
                f"""
{greet}

Your HELIX account has been locked due to multiple incorrect login attempts.

If this was you, you can unlock your account here:
http://127.0.0.1:5000/unlock

If this was NOT you:
Your account may be under attack.
We recommend reviewing your security settings once logged in.

IP Address: {ip}
Time: {time.ctime()}

— HELIX Security Team
"""
            )

            return render_template("login.html", msg="Account locked.")

        return render_template("login.html", msg="Invalid email or password.")

    # ----- CORRECT PASSWORD -----
    failed_attempts[ip] = 0

    greet = email_greeting(email)
    send_security_email(
        email,
        "HELIX Security Alert: New Login Attempt",
        f"""
{greet}

A login attempt was made to your HELIX Security account.

IP Address: {ip}
Time: {time.ctime()}

If this was you, you can ignore this message.
If it was NOT you, change your password immediately
and review your trusted devices.

— HELIX Security Team
"""
    )

    device_id = request.cookies.get("HELIX_DEVICE_ID")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM trusted_devices WHERE email=? AND device_id=?", (email, device_id))
    trusted = c.fetchone()[0] > 0
    conn.close()

    if not trusted:
        mfa_code = str(random.randint(100000, 999999))
        session["mfa_email"] = email
        session["mfa_code"] = mfa_code
        session["mfa_role"] = role

        send_email_otp(email, mfa_code, purpose="New Device Login")
        log_event(email, ip, "MFA_TRIGGERED", "Unrecognized device")

        return redirect("/mfa")

    log_event(email, ip, "LOGIN_SUCCESS", "User logged in")

    session["user"] = {"email": email, "role": role, "name": name}
    session["last_active"] = time.time()
    resp = redirect("/dashboard")
    resp.set_cookie("HELIX_DEVICE_ID", device_id or hashlib.sha256(os.urandom(16)).hexdigest())
    return resp

# ===========================================================
# MFA VERIFY
# ===========================================================
@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    email = session.get("mfa_email")
    code = session.get("mfa_code")
    role = session.get("mfa_role")

    if not email:
        return redirect("/")

    msg = ""
    ip = request.remote_addr

    if request.method == "POST":
        entered = request.form.get("code", "").strip()

        if entered == code:
            device_id = request.cookies.get("HELIX_DEVICE_ID") or hashlib.sha256(os.urandom(16)).hexdigest()

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO trusted_devices(email, device_id) VALUES(?,?)", (email, device_id))
            conn.commit()
            conn.close()

            log_event(email, ip, "MFA_SUCCESS", "Device added as trusted")

            # Fetch name for session
            user = get_user(email)
            name = user[1] if user else ""

            session["user"] = {"email": email, "role": role, "name": name}
            session["last_active"] = time.time()
            resp = redirect("/dashboard")
            resp.set_cookie("HELIX_DEVICE_ID", device_id)
            return resp

        else:
            msg = "Incorrect code."

    return render_template("mfa.html", email=email, msg=msg)

# ===========================================================
# LIVENESS CAMERA VERIFICATION (after suspicious attempts)
# ===========================================================
@app.route("/verify_identity")
def verify_identity():
    email = session.get("verify_identity_email")
    if not email:
        return redirect("/")

    return render_template("verify_identity.html", email=email)

@app.route("/verify_identity_capture", methods=["POST"])
def verify_identity_capture():
    email = session.get("verify_identity_email")
    if not email:
        return "NO_EMAIL", 400

    img_data = request.files.get("photo")
    if not img_data:
        return "NO_IMAGE", 400

    user_dir = os.path.join(INTRUDER_DIR, email.replace("@", "_AT_"))
    os.makedirs(user_dir, exist_ok=True)

    filename = f"liveness_{int(time.time())}.jpg"
    img_data.save(os.path.join(user_dir, filename))

    ip = request.remote_addr
    log_event(email, ip, "LIVENESS_PASS", filename)

    failed_attempts[ip] = 0

    session.pop("verify_identity_email", None)

    return "OK", 200

# NEW: route called when camera is denied / page is refreshed / user bails out
@app.route("/verify_identity_denied", methods=["POST"])
def verify_identity_denied():
    email = session.get("verify_identity_email")
    if not email:
        return "NO_EMAIL", 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET locked=1 WHERE username=?", (email,))
    conn.commit()
    conn.close()

    log_event(
        email,
        request.remote_addr,
        "ACCOUNT_LOCKED",
        "User denied/aborted liveness verification (camera refused, blocked, or refresh/back)."
    )

    session.pop("verify_identity_email", None)

    return "OK", 200

# ===========================================================
# UNLOCK FLOW (Email → Questions → MFA)
# ===========================================================
@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    msg = ""
    ip = request.remote_addr

    q1 = q2 = q3 = ""
    email = None
    show_questions = False

    if request.method == "POST" and "email_only" in request.form:
        email = request.form.get("email_only").strip()
        user = get_user(email)

        if not user:
            msg = "No such account."
        else:
            (
                uid, name, username, pw_hash, role, verified, locked,
                q1, a1, q2, a2, q3, a3
            ) = user

            if not locked:
                msg = "Account is not locked."
            else:
                show_questions = True

    elif request.method == "POST" and "answer1" in request.form:
        email = request.form.get("email")
        ans1 = request.form.get("answer1", "").strip()
        ans2 = request.form.get("answer2", "").strip()
        ans3 = request.form.get("answer3", "").strip()

        user = get_user(email)
        if not user:
            msg = "No such account."
        else:
            (
                uid, name, username, pw_hash, role, verified, locked,
                q1, a1, q2, a2, q3, a3
            ) = user

            if not locked:
                msg = "Account is not locked."
            else:
                h1 = hash_pw(ans1.lower().strip() + app.secret_key)
                h2 = hash_pw(ans2.lower().strip() + app.secret_key)
                h3 = hash_pw(ans3.lower().strip() + app.secret_key)

                correct1 = (h1 == a1)
                correct2 = (h2 == a2)
                correct3 = (h3 == a3)

                if not (correct1 and correct2 and correct3):
                    msg = "One or more answers incorrect."
                    show_questions = True
                else:
                    otp = str(random.randint(100000, 999999))
                    session["unlock_email"] = email
                    session["unlock_otp"] = otp

                    send_email_otp(email, otp, purpose="Unlock Account")
                    log_event(email, ip, "UNLOCK_QUESTIONS_PASSED",
                              "Security questions correct → MFA required")

                    return redirect("/unlock_verify_mfa")

    return render_template("unlock.html",
                           msg=msg,
                           show_questions=show_questions,
                           email=email,
                           q1=q1, q2=q2, q3=q3)

# ===========================================================
# MFA VERIFICATION FOR UNLOCK
# ===========================================================
@app.route("/unlock_verify_mfa", methods=["GET", "POST"])
def unlock_verify_mfa():
    email = session.get("unlock_email")
    otp = session.get("unlock_otp")

    if not email or not otp:
        return redirect("/unlock")

    msg = ""
    ip = request.remote_addr

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if code != otp:
            msg = "Incorrect OTP."
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET locked=0 WHERE username=?", (email,))
            conn.commit()
            conn.close()

            failed_attempts[ip] = 0

            log_event(email, ip, "ACCOUNT_UNLOCKED", "MFA verified after security questions")

            session.pop("unlock_email", None)
            session.pop("unlock_otp", None)

            return render_template("login.html", msg="Account unlocked successfully!")

    return render_template("unlock_mfa.html", email=email, msg=msg)

# ===========================================================
# FORGOT + RESET PASSWORD
# ===========================================================
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    msg = ""
    if request.method == "POST":
        email = request.form.get("email", "")
        code = str(random.randint(100000, 999999))
        session["reset_email"] = email
        session["reset_code"] = code
        send_email_otp(email, code, purpose="Password Reset")
        log_event(email, request.remote_addr, "RESET_REQUEST", "Code sent")
        return redirect("/reset")

    return render_template("forgot.html", msg=msg)

@app.route("/reset", methods=["GET", "POST"])
def reset():
    email = session.get("reset_email")
    if not email:
        return redirect("/forgot")

    msg = ""

    if request.method == "POST":
        code = request.form.get("code", "")
        pw = request.form.get("password", "")
        conf = request.form.get("confirm", "")

        if code != session.get("reset_code"):
            msg = "Incorrect code."
        elif pw != conf:
            msg = "Passwords do not match."
        elif not is_strong_password(pw):
            msg = "Weak password."
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_pw(pw), email))
            conn.commit()
            conn.close()

            log_event(email, request.remote_addr, "PASSWORD_RESET", "Password updated")
            return redirect("/")

    return render_template("reset.html", msg=msg)

# ===========================================================
# DASHBOARD
# ===========================================================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    email = session["user"]["email"]
    name = session["user"].get("name", "")
    return render_template("dashboard.html", email=email, name=name)

# ===========================================================
# SECURITY SETTINGS
# ===========================================================
@app.route("/security_settings")
def security_settings():
    if "user" not in session:
        return redirect("/")
    email = session["user"]["email"]
    return render_template("security_settings.html", email=email)

# ===========================================================
# CHANGE PASSWORD (with history)
# ===========================================================
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]
    msg = ""

    if request.method == "POST":
        current_pw = request.form.get("current_pw", "")
        new_pw = request.form.get("new_pw", "")
        confirm_pw = request.form.get("confirm_pw", "")

        user = get_user(email)
        stored_hash = user[3]  # password_hash

        if hash_pw(current_pw) != stored_hash:
            msg = "Current password is incorrect."
            return render_template("change_password.html", msg=msg)

        if new_pw != confirm_pw:
            msg = "New passwords do not match."
            return render_template("change_password.html", msg=msg)

        if not is_strong_password(new_pw):
            msg = "Weak password. Use uppercase, lowercase, digits, symbol."
            return render_template("change_password.html", msg=msg)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT pw_hash FROM password_history
            WHERE email=?
            ORDER BY ts DESC
            LIMIT 5
        """, (email,))
        old_hashes = [row[0] for row in c.fetchall()]
        conn.close()

        new_hash = hash_pw(new_pw)

        if new_hash in old_hashes or new_hash == stored_hash:
            msg = "You cannot reuse your recent passwords."
            return render_template("change_password.html", msg=msg)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO password_history(email, pw_hash) VALUES(?,?)",
                  (email, stored_hash))
        conn.commit()
        conn.close()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash=? WHERE username=?",
                  (new_hash, email))
        conn.commit()
        conn.close()

        greet = email_greeting(email)
        send_security_email(
            email,
            "HELIX Security Alert: Password Changed",
            f"""
{greet}

Your HELIX account password has been changed successfully.

IP Address: {request.remote_addr}
Time: {time.ctime()}

If this was NOT you, reset your password immediately.

— HELIX Security Team
"""
        )

        log_event(email, request.remote_addr, "PASSWORD_CHANGED", "User updated password")
        msg = "Password updated successfully."

    return render_template("change_password.html", msg=msg)

# ===========================================================
# CHANGE SECURITY QUESTIONS
# ===========================================================
@app.route("/change_security_questions", methods=["GET", "POST"])
def change_security_questions():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]
    msg = ""

    user = get_user(email)
    (
        uid, name, username, pw_hash, role, verified, locked,
        old_q1, old_a1,
        old_q2, old_a2,
        old_q3, old_a3
    ) = user

    if request.method == "POST":
        new_q1 = request.form.get("sec_q1", "")
        new_a1 = request.form.get("sec_a1", "")
        new_q2 = request.form.get("sec_q2", "")
        new_a2 = request.form.get("sec_a2", "")
        new_q3 = request.form.get("sec_q3", "")
        new_a3 = request.form.get("sec_a3", "")

        if not new_q1 or not new_q2 or not new_q3:
            msg = "Select all questions."
        elif not new_a1 or not new_a2 or not new_a3:
            msg = "Provide all answers."
        elif len({new_q1, new_q2, new_q3}) < 3:
            msg = "Please choose 3 different security questions."
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                UPDATE users SET
                    sec_q1=?, sec_a1_hash=?,
                    sec_q2=?, sec_a2_hash=?,
                    sec_q3=?, sec_a3_hash=?
                WHERE username=?
            """, (
                new_q1, hash_pw(new_a1.lower().strip() + app.secret_key),
                new_q2, hash_pw(new_a2.lower().strip() + app.secret_key),
                new_q3, hash_pw(new_a3.lower().strip() + app.secret_key),
                email
            ))
            conn.commit()
            conn.close()

            greet = email_greeting(email)
            send_security_email(
                email,
                "HELIX Security Alert: Security Questions Updated",
                f"""
{greet}

Your HELIX security questions have been updated.

If this was not you, someone may be attempting to gain access.

IP Address: {request.remote_addr}
Time: {time.ctime()}

— HELIX Security Team
"""
            )

            log_event(email, request.remote_addr, "SECURITY_QUESTIONS_CHANGED",
                      "All 3 questions updated")

            msg = "Security questions updated successfully."

    return render_template(
        "change_security_questions.html",
        msg=msg,
        old_q1=old_q1, old_q2=old_q2, old_q3=old_q3
    )

# ===========================================================
# TRUSTED DEVICE MANAGEMENT
# ===========================================================
@app.route("/trusted_devices")
def trusted_devices():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, device_id, ts FROM trusted_devices WHERE email=?", (email,))
    devices = c.fetchall()
    conn.close()

    return render_template("trusted_devices.html", devices=devices, email=email)

@app.route("/remove_device/<int:dev_id>")
def remove_device(dev_id):
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM trusted_devices WHERE id=? AND email=?", (dev_id, email))
    conn.commit()
    conn.close()

    log_event(email, request.remote_addr, "DEVICE_REMOVED",
              f"Removed trusted device ID {dev_id}")

    return redirect("/trusted_devices")

# ===========================================================
# SIGN OUT FROM ALL DEVICES
# ===========================================================
@app.route("/logout_all_devices")
def logout_all_devices():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]
    ip = request.remote_addr

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM trusted_devices WHERE email=?", (email,))
    conn.commit()
    conn.close()

    greet = email_greeting(email)
    send_security_email(
        email,
        "HELIX Security Alert: Signed Out From All Devices",
        f"""
{greet}

You have successfully signed out from ALL devices on your HELIX Security Account.

This means:
• All trusted devices were removed
• All active sessions were invalidated
• Next login from every device will require MFA

If this was NOT you, someone else may have access.

IP Address: {ip}
Time: {time.ctime()}

Stay safe,
HELIX Security Team
"""
    )

    log_event(email, ip, "LOGOUT_ALL_DEVICES", "User signed out from all devices")

    session.clear()
    return render_template("login.html", msg="Signed out from all devices. Please log in again.")

# ===========================================================
# INTRUDERS (per-user gallery)
# ===========================================================
@app.route("/gallery")
def gallery():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]
    safe_email = email.replace("@", "_AT_")
    user_dir = os.path.join(INTRUDER_DIR, safe_email)
    os.makedirs(user_dir, exist_ok=True)

    imgs = sorted(os.listdir(user_dir))
    return render_template("gallery.html", images=imgs, user=email)

@app.route("/intruders/<email>/<file>")
def intruders(email, file):
    safe_email = email.replace("@", "_AT_")
    user_dir = os.path.join(INTRUDER_DIR, safe_email)
    return send_from_directory(user_dir, file)

# ===========================================================
# LOGS (user sees only their logs, admin sees all)
# ===========================================================
@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect("/")

    email = session["user"]["email"]
    role = session["user"]["role"]

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if role == "admin":
        c.execute("SELECT email,ip,geo,event,details,ts FROM logs ORDER BY ts DESC LIMIT 500")
    else:
        c.execute("SELECT email,ip,geo,event,details,ts FROM logs WHERE email=? ORDER BY ts DESC", (email,))

    enc_rows = c.fetchall()
    conn.close()

    rows = []
    for em, ip, geo, ev, det, ts in enc_rows:
        try:
            ev_dec = aes_decrypt(ev)
            det_dec = aes_decrypt(det)
        except Exception:
            ev_dec = ev
            det_dec = det
        rows.append((em, ip, geo, ev_dec, det_dec, ts))

    return render_template("logs.html", rows=rows, role=role)

# ===========================================================
# QR BADGES (encrypted payload)
# ===========================================================
@app.route("/qr")
def qr():
    if "user" not in session:
        return redirect("/")
    email = session["user"]["email"]

    raw_payload = f"{email}|{int(time.time())}|{random.randint(100000,999999)}"
    enc_payload = aes_encrypt(raw_payload)
    sig = hashlib.sha256((app.secret_key + enc_payload).encode()).hexdigest()
    token = enc_payload + "|" + sig

    os.makedirs(QR_DIR, exist_ok=True)
    fname = f"{hashlib.md5(email.encode()).hexdigest()}.png"
    img = qrcode.make(token)
    img.save(os.path.join(QR_DIR, fname))

    return render_template("qr.html", token=token, image_name=fname)

@app.route("/qr_image/<file>")
def qr_image(file):
    return send_from_directory(QR_DIR, file)

# ===========================================================
# QR VERIFY
# ===========================================================
@app.route("/qr_verify", methods=["GET", "POST"])
def qr_verify():
    msg = ""
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        ip = request.remote_addr

        try:
            enc_payload, sig = token.split("|")
        except ValueError:
            msg = "Invalid format."
            log_event("UNKNOWN", ip, "QR_FAIL", "Invalid token format")
            return render_template("qr_verify.html", msg=msg)

        correct_sig = hashlib.sha256((app.secret_key + enc_payload).encode()).hexdigest()
        if sig != correct_sig:
            msg = "Invalid QR signature."
            log_event("UNKNOWN", ip, "QR_FAIL", "Invalid signature")
            return render_template("qr_verify.html", msg=msg)

        try:
            raw = aes_decrypt(enc_payload)
            email, ts, nonce = raw.split("|")
        except Exception:
            msg = "Decryption failure."
            log_event("UNKNOWN", ip, "QR_FAIL", "Decryption failed")
            return render_template("qr_verify.html", msg=msg)

        if time.time() - int(ts) > 300:
            msg = "Token expired."
            log_event(email, ip, "QR_FAIL", "QR expired")
        else:
            msg = f"Valid token for {email}"
            log_event(email, ip, "QR_VERIFY", "QR passed")

    return render_template("qr_verify.html", msg=msg)

# ===========================================================
# LOGOUT
# ===========================================================
@app.route("/logout")
def logout():
    user_email = session.get("user", {}).get("email", "")
    if user_email:
        log_event(user_email, request.remote_addr, "LOGOUT", "User logged out")
    session.clear()
    return redirect("/")

# ===========================================================
# RUN APP (HTTPS)
# ===========================================================
if __name__ == "__main__":
    generate_https_cert()
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=("cert.pem", "key.pem"))
