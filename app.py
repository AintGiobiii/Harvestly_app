import os
import re
import secrets
import time
import requests
from functools import wraps
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='static', template_folder='templates')

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

_database_url = os.environ.get('DATABASE_URL', '')
if _database_url.startswith('postgres://'):
   
    _database_url = _database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _database_url or 'sqlite:///harvestly.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 280,
}

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
FREE_CYCLE_LIMIT = 3

SESSION_PLANS = {
    'starter': {'price': 30, 'sessions': 4},
    'basic': {'price': 80, 'sessions': 10},
    'pro': {'price': 150, 'sessions': 20},
}

ADMIN_GCASH_NUMBER = os.environ.get('ADMIN_GCASH_NUMBER', '09756694159')
ADMIN_GCASH_NAME = os.environ.get('ADMIN_GCASH_NAME', 'Mhar Angelo')


app.config['BREVO_API_KEY'] = os.environ.get('BREVO_API_KEY', '')
app.config['BREVO_SENDER_EMAIL'] = os.environ.get('BREVO_SENDER_EMAIL', '')
app.config['BREVO_SENDER_NAME'] = os.environ.get('BREVO_SENDER_NAME', 'Harvestly')
VERIFICATION_CODE_TTL_MINUTES = 15
RESET_CODE_TTL_MINUTES = 15
CODE_RESEND_COOLDOWN_SECONDS = 60

def send_email(to_email, subject, body_html, body_text=None):
    api_key = app.config.get('BREVO_API_KEY')
    sender_email = app.config.get('BREVO_SENDER_EMAIL')
    if not api_key or not sender_email:
        print(f"[EMAIL DISABLED — walang BREVO_API_KEY/BREVO_SENDER_EMAIL env var] Hindi naipadala ang '{subject}' papunta sa {to_email}.")
        return False
    try:
        sender_name = app.config.get('BREVO_SENDER_NAME', 'Harvestly')
        payload = {
            'sender': {'name': sender_name, 'email': sender_email},
            'to': [{'email': to_email}],
            'subject': subject,
            'htmlContent': body_html,
        }
        if body_text:
            payload['textContent'] = body_text
        resp = requests.post(
            'https://api.brevo.com/v3/smtp/email',
            json=payload,
            headers={'api-key': api_key, 'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=15
        )
        if resp.status_code >= 400:
            print(f"Error sa pagpadala ng email papunta sa {to_email}: HTTP {resp.status_code} — {resp.text}")
            return False
        return True
    except Exception as e:
        print(f"Error sa pagpadala ng email papunta sa {to_email}: {e}")
        return False

def generate_code():
    """6-digit na code gamit ang secrets module (cryptographically secure)."""
    return f"{secrets.randbelow(1000000):06d}"

def make_expiry(minutes):
    return str(int(time.time()) + minutes * 60)

def is_code_expired(expiry_str):
    if not expiry_str:
        return True
    try:
        return int(time.time()) > int(expiry_str)
    except (ValueError, TypeError):
        return True


def can_send_code(key):
    row = RateLimitEntry.query.filter_by(key=f'code_send:{key}').first()
    if row and (time.time() - row.last_at) < CODE_RESEND_COOLDOWN_SECONDS:
        return False
    return True

def mark_code_sent(key):
    now = time.time()
    row = RateLimitEntry.query.filter_by(key=f'code_send:{key}').first()
    if row:
        row.last_at = now
    else:
        db.session.add(RateLimitEntry(key=f'code_send:{key}', count=0, first_at=now, last_at=now))
    db.session.commit()


CODE_MAX_ATTEMPTS = 5

def register_code_attempt(key):
    now = time.time()
    row = RateLimitEntry.query.filter_by(key=f'code_attempt:{key}').first()
    if row:
        row.count += 1
        row.last_at = now
    else:
        db.session.add(RateLimitEntry(key=f'code_attempt:{key}', count=1, first_at=now, last_at=now))
    db.session.commit()

def clear_code_attempts(key):
    RateLimitEntry.query.filter_by(key=f'code_attempt:{key}').delete()
    db.session.commit()

def code_attempts_exceeded(key):
    row = RateLimitEntry.query.filter_by(key=f'code_attempt:{key}').first()
    return bool(row and row.count >= CODE_MAX_ATTEMPTS)

def send_verification_email(user):
    code = generate_code()
    user.verification_code = code
    user.verification_code_expires = make_expiry(VERIFICATION_CODE_TTL_MINUTES)
    send_email(
        user.email,
        'Harvestly - Patunayan ang iyong email (Verification Code)',
        f"""<div style="font-family:sans-serif">
        <h2 style="color:#1F4D36">Harvestly</h2>
        <p>Kumusta, {user.full_name}!</p>
        <p>Gamitin ang code na ito para patunayan ang iyong email:</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:4px;color:#1F4D36">{code}</p>
        <p>Valid ito sa loob ng {VERIFICATION_CODE_TTL_MINUTES} minuto. Kung hindi ikaw ang humiling nito, i-ignore na lang ang email na ito.</p>
        </div>""",
        f"Ang iyong Harvestly verification code ay: {code} (valid for {VERIFICATION_CODE_TTL_MINUTES} minutes)"
    )
    mark_code_sent(user.email)
    clear_code_attempts('verify:' + user.email)

def send_reset_email(user):
    code = generate_code()
    user.reset_code = code
    user.reset_code_expires = make_expiry(RESET_CODE_TTL_MINUTES)
    send_email(
        user.email,
        'Harvestly - Password Reset Code',
        f"""<div style="font-family:sans-serif">
        <h2 style="color:#1F4D36">Harvestly</h2>
        <p>Kumusta, {user.full_name}!</p>
        <p>May humiling ng password reset para sa account mo. Gamitin ang code na ito:</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:4px;color:#1F4D36">{code}</p>
        <p>Valid ito sa loob ng {RESET_CODE_TTL_MINUTES} minuto. Kung hindi ikaw ang humiling nito, i-ignore na lang ang email na ito — hindi mababago ang password mo.</p>
        </div>""",
        f"Password reset code mo: {code} (valid for {RESET_CODE_TTL_MINUTES} minutes)"
    )
    mark_code_sent('reset:' + user.email)
    clear_code_attempts('reset:' + user.email)


EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
ALLOWED_AVATARS = ['🌾', '🌽', '🍅', '🥕', '🍓', '🐄', '🐓', '👩\u200d🌾', '👨\u200d🌾']
DEFAULT_AVATAR = ALLOWED_AVATARS[0]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    avatar = db.Column(db.String(10), nullable=False, default=DEFAULT_AVATAR)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='farmer')  
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_code = db.Column(db.String(10), nullable=True)
    verification_code_expires = db.Column(db.String(30), nullable=True)  
    reset_code = db.Column(db.String(10), nullable=True)
    reset_code_expires = db.Column(db.String(30), nullable=True)  
    subscription_status = db.Column(db.String(20), nullable=False, default='free')  
    cycle_count = db.Column(db.Integer, nullable=False, default=0)
    purchased_cycles = db.Column(db.Integer, nullable=False, default=0)
    cycle_has_product = db.Column(db.Boolean, nullable=False, default=False)
    cycle_has_expense = db.Column(db.Boolean, nullable=False, default=False)
    cycle_has_income = db.Column(db.Boolean, nullable=False, default=False)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False) 
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(200), nullable=True)
    qty = db.Column(db.Float, nullable=True)
    unit = db.Column(db.String(20), nullable=True)
    price_per_unit = db.Column(db.Float, nullable=True)
    expense_basis = db.Column(db.Float, nullable=True)
    possible_kita = db.Column(db.Float, nullable=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(20), nullable=False)
    produce_id = db.Column(db.Integer, db.ForeignKey('record.id'), nullable=True)
    rating = db.Column(db.Integer, nullable=True)

class ActualIncome(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(150), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    computed_net = db.Column(db.Float, nullable=False)
    discrepancy = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(20), nullable=False)

class SubscriptionRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='completed')  
    requested_at = db.Column(db.String(30), nullable=False)
    reviewed_at = db.Column(db.String(30), nullable=True)
    payment_reference = db.Column(db.String(100), nullable=True)
    plan = db.Column(db.String(20), nullable=True) 
    sessions_granted = db.Column(db.Integer, nullable=True)

class SupportMessage(db.Model):
    """Customer service: concern/message na ipinapadala ng farmer papunta sa
    admin, at ang reply ng admin dito. Simpleng isang-tanong-isang-sagot na
    modelo lang (hindi thread/chat) — sapat na para sa "reach out sa admin"
    na use case."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(150), nullable=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open')  
    admin_reply = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.String(30), nullable=False)
    replied_at = db.Column(db.String(30), nullable=True)

class RateLimitEntry(db.Model):
    """Database-backed na counter para sa login lockouts at verification
    code cooldowns/attempts."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), nullable=False, unique=True, index=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    first_at = db.Column(db.Float, nullable=False)
    last_at = db.Column(db.Float, nullable=False)
with app.app_context():
    db.create_all()

def run_safe_migrations():
    from sqlalchemy import text, inspect
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            table_names = inspector.get_table_names()
            if 'actual_income' in table_names:
                ai_columns = [c['name'] for c in inspector.get_columns('actual_income')]
                if 'product_name' not in ai_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE actual_income ADD COLUMN product_name VARCHAR(150)"))
                        conn.commit()
                    print("Migration: added 'product_name' column to actual_income.")
            if 'record' in table_names:
                record_columns = [c['name'] for c in inspector.get_columns('record')]
                if 'produce_id' not in record_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE record ADD COLUMN produce_id INTEGER"))
                        conn.commit()
                    print("Migration: added 'produce_id' column to record.")
                if 'rating' not in record_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE record ADD COLUMN rating INTEGER"))
                        conn.commit()
                    print("Migration: added 'rating' column to record.")
            if 'subscription_request' in table_names:
                sub_columns = [c['name'] for c in inspector.get_columns('subscription_request')]
                if 'payment_reference' not in sub_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE subscription_request ADD COLUMN payment_reference VARCHAR(100)"))
                        conn.commit()
                    print("Migration: added 'payment_reference' column to subscription_request.")
                if 'plan' not in sub_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE subscription_request ADD COLUMN plan VARCHAR(20)"))
                        conn.commit()
                    print("Migration: added 'plan' column to subscription_request.")
                if 'sessions_granted' not in sub_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE subscription_request ADD COLUMN sessions_granted INTEGER"))
                        conn.commit()
                    print("Migration: added 'sessions_granted' column to subscription_request.")
            if 'user' in table_names:
                user_columns = [c['name'] for c in inspector.get_columns('user')]

                if 'email_verified' not in user_columns:
                    with db.engine.connect() as conn:
                        conn.execute(text("ALTER TABLE user ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0"))
                        conn.execute(text("UPDATE user SET email_verified = 1"))
                        conn.commit()
                    print("Migration: added 'email_verified' column to user (existing accounts grandfathered as verified).")
                user_migrations = {
                    'role': "ALTER TABLE user ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'farmer'",
                    'subscription_status': "ALTER TABLE user ADD COLUMN subscription_status VARCHAR(20) NOT NULL DEFAULT 'free'",
                    'cycle_count': "ALTER TABLE user ADD COLUMN cycle_count INTEGER NOT NULL DEFAULT 0",
                    'cycle_has_product': "ALTER TABLE user ADD COLUMN cycle_has_product BOOLEAN NOT NULL DEFAULT 0",
                    'cycle_has_expense': "ALTER TABLE user ADD COLUMN cycle_has_expense BOOLEAN NOT NULL DEFAULT 0",
                    'cycle_has_income': "ALTER TABLE user ADD COLUMN cycle_has_income BOOLEAN NOT NULL DEFAULT 0",
                    'email': "ALTER TABLE user ADD COLUMN email VARCHAR(120)",
                    'avatar': f"ALTER TABLE user ADD COLUMN avatar VARCHAR(10) NOT NULL DEFAULT '{DEFAULT_AVATAR}'",
                    'verification_code': "ALTER TABLE user ADD COLUMN verification_code VARCHAR(10)",
                    'verification_code_expires': "ALTER TABLE user ADD COLUMN verification_code_expires VARCHAR(30)",
                    'reset_code': "ALTER TABLE user ADD COLUMN reset_code VARCHAR(10)",
                    'reset_code_expires': "ALTER TABLE user ADD COLUMN reset_code_expires VARCHAR(30)",
                    'purchased_cycles': "ALTER TABLE user ADD COLUMN purchased_cycles INTEGER NOT NULL DEFAULT 0",
                }
                with db.engine.connect() as conn:
                    for col, stmt in user_migrations.items():
                        if col not in user_columns:
                            conn.execute(text(stmt))
                            print(f"Migration: added '{col}' column to user.")
                    conn.commit()
        except Exception as e:
            print(f"Migration check skipped: {e}")
run_safe_migrations()

def ensure_default_admin():
    try:
        existing_admin = User.query.filter_by(role='admin').first()
        if not existing_admin:
            admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@harvestly.local')
            admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(12)
            hashed_pw = bcrypt.generate_password_hash(admin_password).decode('utf-8')
            admin = User(
                full_name='System Admin',
                username=admin_username,
                email=admin_email,
                avatar=DEFAULT_AVATAR,
                password_hash=hashed_pw,
                role='admin',
                subscription_status='active',
                email_verified=True  
            )
            db.session.add(admin)
            db.session.commit()
            print("=" * 60)
            print(f"Default admin created — log in gamit ang email: {admin_email}")
            if not os.environ.get('ADMIN_PASSWORD'):
                print(f"Generated password: {admin_password}")
                print("Isulat ito ngayon — hindi na ito muling ipapakita. Palitan agad pagkatapos mag-login.")
            print("=" * 60)
    except Exception as e:
        db.session.rollback()
        print(f"Admin seed check skipped: {e}")
with app.app_context():
    ensure_default_admin()

def get_current_user():
    uid = session.get('user_id')
    return User.query.get(uid) if uid else None

def get_current_user_id():
    return session.get('user_id')

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get('user_id')
        if not uid or not User.query.get(uid):
            session.clear()
            return jsonify({'error': 'Kailangan mong mag-login muna.'}), 401
        return f(*args, **kwargs)
    return wrapper

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300

def _client_ip():
    return request.remote_addr or 'unknown'

def is_login_locked(ip):
    row = RateLimitEntry.query.filter_by(key=f'login:{ip}').first()
    if not row:
        return False
    if time.time() - row.first_at > LOGIN_LOCKOUT_SECONDS:
        db.session.delete(row)
        db.session.commit()
        return False
    return row.count >= LOGIN_MAX_ATTEMPTS

def register_failed_login(ip):
    now = time.time()
    row = RateLimitEntry.query.filter_by(key=f'login:{ip}').first()
    if row:
        row.count += 1
        row.last_at = now
    else:
        db.session.add(RateLimitEntry(key=f'login:{ip}', count=1, first_at=now, last_at=now))
    db.session.commit()

def clear_login_attempts(ip):
    RateLimitEntry.query.filter_by(key=f'login:{ip}').delete()
    db.session.commit()

CSRF_EXEMPT_PATHS = {'/api/login', '/api/signup'}  

@app.before_request
def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(24)

@app.before_request
def check_csrf_token():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and request.path.startswith('/api/'):
        if request.path in CSRF_EXEMPT_PATHS:
            return
        sent_token = request.headers.get('X-CSRF-Token')
        real_token = session.get('csrf_token')
        if not sent_token or not real_token or not secrets.compare_digest(sent_token, real_token):
            return jsonify({'error': 'Invalid o missing CSRF token.'}), 403

def usage_status(user):
    total_allowed = FREE_CYCLE_LIMIT + user.purchased_cycles
    locked = (
        user.role == 'farmer' and
        user.cycle_count >= total_allowed
    )
    return {
        'subscriptionStatus': user.subscription_status,
        'cycleCount': user.cycle_count,
        'cycleLimit': FREE_CYCLE_LIMIT,
        'purchasedCycles': user.purchased_cycles,
        'totalAllowed': total_allowed,
        'cycleProgress': {
            'hasProduct': user.cycle_has_product,
            'hasExpense': user.cycle_has_expense,
            'hasIncome': user.cycle_has_income,
        },
        'locked': locked,
    }

def check_cycle_completion(user):
    if user.cycle_has_product and user.cycle_has_expense and user.cycle_has_income:
        user.cycle_count += 1
        user.cycle_has_product = False
        user.cycle_has_expense = False
        user.cycle_has_income = False

def require_admin():
    return session.get('role') == 'admin'

@app.route('/')
def home():
    return render_template('index.html', csrf_token=session.get('csrf_token', ''))

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.json or {}
        username = (data.get('username') or '').strip()
        password = data.get('password', '')
        contact = (data.get('contact') or '').strip()
        avatar = (data.get('avatar') or '').strip()
        if avatar not in ALLOWED_AVATARS:
            avatar = DEFAULT_AVATAR
        if not username or not password:
            return jsonify({'error': 'Kailangan ng username at password.'}), 400
        if len(password) < 6:
            return jsonify({'error': 'Dapat hindi bababa sa 6 characters ang password.'}), 400
        if not contact:
            return jsonify({'error': 'Kailangan ng email para sa pagpaparehistro.'}), 400
        if not EMAIL_RE.match(contact):
            return jsonify({'error': 'Hindi valid ang email address.'}), 400
        email_val = contact.lower()

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Ang username na ito ay ginagamit na.'}), 400
        if User.query.filter_by(email=email_val).first():
            return jsonify({'error': 'May account na gumagamit na ng email na ito.'}), 400

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            full_name=data.get('name', 'User'),
            username=username,
            email=email_val,
            avatar=avatar,
            password_hash=hashed_pw,
            role='farmer',
            email_verified=False
        )
        db.session.add(new_user)
        db.session.flush()
        send_verification_email(new_user)
        db.session.commit()
        return jsonify({
            'message': 'Nagawa ang account! Ipinadala ang verification code sa email mo.',
            'requiresVerification': True,
            'email': email_val
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error sa signup: {e}")
        return jsonify({'error': 'May naganap na error sa pag-signup.'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    ip = _client_ip()
    if is_login_locked(ip):
        return jsonify({'error': 'Sobra na ang failed login attempts. Subukan ulit mamaya.'}), 429
    try:
        data = request.json or {}
        identifier = (data.get('identifier') or '').strip()
        user = None
        if identifier:
            user = User.query.filter_by(email=identifier.lower()).first()
        if user and bcrypt.check_password_hash(user.password_hash, data.get('password', '')):
            if user.email and not user.email_verified:
                if not user.verification_code or is_code_expired(user.verification_code_expires):
                    send_verification_email(user)
                    db.session.commit()
                return jsonify({
                    'error': 'Kailangan mo munang i-verify ang email mo bago makapag-login.',
                    'requiresVerification': True,
                    'email': user.email
                }), 403
            clear_login_attempts(ip)
            session['user_id'] = user.id
            session['username'] = user.full_name
            session['role'] = user.role
            return jsonify({'message': 'Success', 'username': user.full_name, 'role': user.role, 'avatar': user.avatar})
        register_failed_login(ip)
        return jsonify({'error': 'Maling email o password.'}), 401
    except Exception as e:
        print(f"Error sa login: {e}")
        return jsonify({'error': 'May naganap na error sa pag-login.'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    uid = session.get('user_id')
    if not uid:
        return jsonify({'loggedIn': False})
    user = User.query.get(uid)
    if not user:
        session.clear()
        return jsonify({'loggedIn': False})
    return jsonify({'loggedIn': True, 'username': user.full_name, 'role': user.role, 'avatar': user.avatar})

@app.route('/api/verify-email', methods=['POST'])
def verify_email():
    try:
        data = request.json or {}
        email_val = (data.get('email') or '').strip().lower()
        code = (data.get('code') or '').strip()
        if not email_val or not code:
            return jsonify({'error': 'Kailangan ng email at code.'}), 400
        user = User.query.filter_by(email=email_val).first()
        if not user:
            return jsonify({'error': 'Hindi mahanap ang account na ito.'}), 404
        if user.email_verified:
            return jsonify({'message': 'Verified na ang email na ito. Maaari ka nang mag-login.'})
        attempt_key = 'verify:' + email_val
        if code_attempts_exceeded(attempt_key):
            return jsonify({'error': 'Sobra na ang maling pagsubok. Mag-request muna ng bagong code.'}), 429
        if not user.verification_code or code != user.verification_code or is_code_expired(user.verification_code_expires):
            register_code_attempt(attempt_key)
            return jsonify({'error': 'Mali o expired na ang verification code.'}), 400
        clear_code_attempts(attempt_key)
        user.email_verified = True
        user.verification_code = None
        user.verification_code_expires = None
        db.session.commit()
        session['user_id'] = user.id
        session['username'] = user.full_name
        session['role'] = user.role
        return jsonify({'message': 'Na-verify na ang email mo!', 'username': user.full_name, 'role': user.role, 'avatar': user.avatar})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa email verification: {e}")
        return jsonify({'error': 'May naganap na error sa pag-verify.'}), 500

@app.route('/api/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.json or {}
        email_val = (data.get('email') or '').strip().lower()
        if not email_val:
            return jsonify({'error': 'Kailangan ng email.'}), 400
        generic_ok = {'message': 'Kung valid ang account na ito, may naipadalang bagong code.'}
        user = User.query.filter_by(email=email_val).first()
        if not user or user.email_verified:
            return jsonify(generic_ok)
        if not can_send_code(email_val):
            return jsonify({'error': f'Maghintay muna ng ilang segundo bago humiling ulit ng code.'}), 429
        send_verification_email(user)
        db.session.commit()
        return jsonify(generic_ok)
    except Exception as e:
        db.session.rollback()
        print(f"Error sa resend verification: {e}")
        return jsonify({'error': 'May naganap na error.'}), 500


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.json or {}
        identifier = (data.get('identifier') or '').strip().lower()
        generic_ok = {'message': 'Kung may account na gumagamit ng email na ito, may naipadalang reset code.'}
        if not identifier:
            return jsonify({'error': 'Maglagay ng email address.'}), 400
        if not EMAIL_RE.match(identifier):
            return jsonify({'error': 'Maglagay ng valid na email address.'}), 400
        user = User.query.filter_by(email=identifier).first()
        if not user:
            return jsonify(generic_ok)
        if not can_send_code('reset:' + identifier):
            return jsonify({'error': 'Maghintay muna ng ilang segundo bago humiling ulit ng code.'}), 429
        send_reset_email(user)
        db.session.commit()
        return jsonify(generic_ok)
    except Exception as e:
        db.session.rollback()
        print(f"Error sa forgot password: {e}")
        return jsonify({'error': 'May naganap na error.'}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json or {}
        email_val = (data.get('email') or '').strip().lower()
        code = (data.get('code') or '').strip()
        new_password = data.get('newPassword', '')
        if not email_val or not code or not new_password:
            return jsonify({'error': 'Kumpletuhin ang lahat ng fields.'}), 400
        if len(new_password) < 6:
            return jsonify({'error': 'Dapat hindi bababa sa 6 characters ang bagong password.'}), 400
        user = User.query.filter_by(email=email_val).first()
        if not user:
            return jsonify({'error': 'Mali o expired na ang reset code.'}), 400
        attempt_key = 'reset:' + email_val
        if code_attempts_exceeded(attempt_key):
            return jsonify({'error': 'Sobra na ang maling pagsubok. Mag-request muna ng bagong reset code.'}), 429
        if not user.reset_code or code != user.reset_code or is_code_expired(user.reset_code_expires):
            register_code_attempt(attempt_key)
            return jsonify({'error': 'Mali o expired na ang reset code.'}), 400
        clear_code_attempts(attempt_key)
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.reset_code = None
        user.reset_code_expires = None
        db.session.commit()
        return jsonify({'message': 'Na-reset na ang password mo. Maaari ka nang mag-login gamit ang bagong password.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pag-reset ng password: {e}")
        return jsonify({'error': 'May naganap na error sa pag-reset.'}), 500

@app.route('/api/data', methods=['GET'])
@login_required
def get_data():
    try:
        user = get_current_user()
        records = Record.query.filter_by(user_id=user.id).order_by(Record.id.desc()).all()
        incomes = ActualIncome.query.filter_by(user_id=user.id).order_by(ActualIncome.id.desc()).all()
        records_list = [{
            'id': r.id, 'type': r.type, 'name': r.name, 'category': r.category,
            'description': r.description, 'qty': r.qty, 'unit': r.unit,
            'pricePerUnit': r.price_per_unit, 'expenseBasis': r.expense_basis,
            'possibleKita': r.possible_kita, 'amount': r.amount, 'date': r.date,
            'produceId': r.produce_id, 'rating': r.rating
        } for r in records]
        income_list = [{
            'id': i.id, 'productName': i.product_name, 'amount': i.amount, 'computedNet': i.computed_net,
            'discrepancy': i.discrepancy, 'date': i.date
        } for i in incomes]
        return jsonify({
            'records': records_list,
            'incomeHistory': income_list,
            'role': user.role,
            'avatar': user.avatar,
            'usage': usage_status(user),
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pagkuha ng data: {e}")
        return jsonify({'error': 'May naganap na error sa pagkuha ng data.'}), 500

@app.route('/api/records', methods=['POST'])
@login_required
def add_records():
    try:
        user = get_current_user()
        status = usage_status(user)
        if status['locked']:
            return jsonify({'error': 'Naabot na ang 3 free uses. Mag-request ng subscription para magpatuloy.', 'locked': True}), 403
        payload = request.json
        if not payload:
            return jsonify({'error': 'Walang ipinadalang data.'}), 400
        items = payload if isinstance(payload, list) else [payload]
        last_new_produce_id = None
        for data in items:
            rec_type = data.get('type', 'expense')
            rec_name = data.get('name') or data.get('category') or 'Farm Expense'
            raw_amount = data.get('amount', 0)
            try:
                rec_amount = float(raw_amount)
            except (ValueError, TypeError):
                rec_amount = 0.0
            raw_produce_id = data.get('produceId')
            try:
                linked_produce_id = int(raw_produce_id) if raw_produce_id not in (None, '') else None
            except (ValueError, TypeError):
                linked_produce_id = None
            if rec_type == 'expense' and linked_produce_id is None and last_new_produce_id is not None:
                linked_produce_id = last_new_produce_id
            new_rec = Record(
                user_id=user.id,
                type=rec_type,
                name=rec_name,
                category=data.get('category'),
                description=data.get('description'),
                qty=float(data['qty']) if data.get('qty') is not None else None,
                unit=data.get('unit'),
                price_per_unit=float(data['pricePerUnit']) if data.get('pricePerUnit') is not None else None,
                expense_basis=float(data['expenseBasis']) if data.get('expenseBasis') is not None else None,
                possible_kita=float(data['possibleKita']) if data.get('possibleKita') is not None else None,
                amount=rec_amount,
                date=data.get('date', ''),
                produce_id=linked_produce_id
            )
            db.session.add(new_rec)
            if rec_type == 'produce':
                user.cycle_has_product = True
                db.session.flush()
                last_new_produce_id = new_rec.id
            elif rec_type == 'expense':
                user.cycle_has_expense = True
        check_cycle_completion(user)
        db.session.commit()
        return jsonify({'message': 'Nai-save na sa Database!', 'usage': usage_status(user)}), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pag-save ng record: {e}")
        return jsonify({'error': 'May naganap na error sa pag-save ng record.'}), 500

@app.route('/api/records/<int:rec_id>', methods=['DELETE'])
@login_required
def delete_record(rec_id):
    uid = get_current_user_id()
    rec = Record.query.filter_by(id=rec_id, user_id=uid).first()
    if rec:
        db.session.delete(rec)
        db.session.commit()
        return jsonify({'message': 'Nai-delete na.'})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/records/<int:rec_id>', methods=['PATCH'])
@login_required
def update_record(rec_id):
    uid = get_current_user_id()
    rec = Record.query.filter_by(id=rec_id, user_id=uid).first()
    if not rec:
        return jsonify({'error': 'Not found'}), 404
    try:
        data = request.json or {}
        if 'qty' in data and data['qty'] not in (None, ''):
            try:
                rec.qty = float(data['qty'])
            except (ValueError, TypeError):
                pass
        if 'unit' in data and data['unit']:
            rec.unit = data['unit']
        if 'pricePerUnit' in data and data['pricePerUnit'] not in (None, ''):
            try:
                rec.price_per_unit = float(data['pricePerUnit'])
            except (ValueError, TypeError):
                pass
        if 'amount' in data and data['amount'] not in (None, ''):
            try:
                rec.amount = float(data['amount'])
            except (ValueError, TypeError):
                pass
        if 'rating' in data:
            raw_rating = data.get('rating')
            if raw_rating in (None, ''):
                rec.rating = None
            else:
                try:
                    rating_val = int(raw_rating)
                    if 1 <= rating_val <= 5:
                        rec.rating = rating_val
                except (ValueError, TypeError):
                    pass
        db.session.commit()
        return jsonify({'message': 'Na-update na.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pag-update ng record: {e}")
        return jsonify({'error': 'May naganap na error sa pag-update.'}), 500

@app.route('/api/income', methods=['POST'])
@login_required
def add_income():
    try:
        user = get_current_user()
        status = usage_status(user)
        if status['locked']:
            return jsonify({'error': 'Naabot na ang 3 free uses. Mag-request ng subscription para magpatuloy.', 'locked': True}), 403
        data = request.json or {}
        new_inc = ActualIncome(
            user_id=user.id,
            product_name=data.get('productName'),
            amount=float(data.get('amount', 0)),
            computed_net=float(data.get('computedNet', 0)),
            discrepancy=float(data.get('discrepancy', 0)),
            date=data.get('date', '')
        )
        db.session.add(new_inc)
        user.cycle_has_income = True
        check_cycle_completion(user)
        db.session.commit()
        return jsonify({'message': 'Income saved!', 'usage': usage_status(user)})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pag-save ng income: {e}")
        return jsonify({'error': 'May naganap na error sa pag-save ng income.'}), 500

@app.route('/api/income/<int:inc_id>', methods=['DELETE'])
@login_required
def delete_income(inc_id):
    uid = get_current_user_id()
    inc = ActualIncome.query.filter_by(id=inc_id, user_id=uid).first()
    if inc:
        db.session.delete(inc)
        db.session.commit()
        return jsonify({'message': 'Nai-delete na.'})
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/gcash-info', methods=['GET'])
@login_required
def gcash_info():
    return jsonify({
        'gcashNumber': ADMIN_GCASH_NUMBER,
        'gcashName': ADMIN_GCASH_NAME,
        'plans': SESSION_PLANS,
    })

@app.route('/api/subscription/request', methods=['POST'])
@login_required
def request_subscription():
    try:
        user = get_current_user()
        data = request.json or {}
        plan_key = (data.get('plan') or '').strip()
        payment_ref = (data.get('paymentReference') or '').strip()
        if plan_key not in SESSION_PLANS:
            return jsonify({'error': 'Pumili ng valid na plan.'}), 400
        if not payment_ref:
            return jsonify({'error': 'Kailangan ng GCash reference number.'}), 400
        plan = SESSION_PLANS[plan_key]
        req = SubscriptionRequest(
            user_id=user.id,
            status='completed',
            requested_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M'),
            reviewed_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M'),
            payment_reference=payment_ref,
            plan=plan_key,
            sessions_granted=plan['sessions'],
        )
        db.session.add(req)
        user.purchased_cycles += plan['sessions']
        user.subscription_status = 'active'
        db.session.commit()
        return jsonify({
            'message': f"Na-activate na ang {plan['sessions']} bagong sessions mo!",
            'usage': usage_status(user)
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error sa subscription request: {e}")
        return jsonify({'error': 'May naganap na error sa subscription request.'}), 500


@app.route('/api/support', methods=['GET'])
@login_required
def list_my_support_messages():
    try:
        user = get_current_user()
        msgs = SupportMessage.query.filter_by(user_id=user.id).order_by(SupportMessage.id.desc()).all()
        result = [{
            'id': m.id, 'subject': m.subject, 'message': m.message,
            'status': m.status, 'adminReply': m.admin_reply,
            'createdAt': m.created_at, 'repliedAt': m.replied_at,
        } for m in msgs]
        return jsonify({'messages': result})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pagkuha ng support messages: {e}")
        return jsonify({'error': 'May naganap na error sa pagkuha ng mensahe.'}), 500

@app.route('/api/support', methods=['POST'])
@login_required
def submit_support_message():
    try:
        user = get_current_user()
        data = request.json or {}
        subject = (data.get('subject') or '').strip()[:150] or None
        message = (data.get('message') or '').strip()
        if not message:
            return jsonify({'error': 'Kailangan ng mensahe.'}), 400
        if len(message) > 2000:
            return jsonify({'error': 'Masyadong mahaba ang mensahe (max 2000 characters).'}), 400
        new_msg = SupportMessage(
            user_id=user.id,
            subject=subject,
            message=message,
            status='open',
            created_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        )
        db.session.add(new_msg)
        db.session.commit()
        return jsonify({'message': 'Naipadala ang concern mo. Sasagutin ito ng admin sa lalong madaling panahon.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa pagpadala ng support message: {e}")
        return jsonify({'error': 'May naganap na error sa pagpadala ng mensahe.'}), 500

@app.route('/api/admin/support', methods=['GET'])
def admin_list_support_messages():
    if not require_admin():
        return jsonify({'error': 'Admin access only.'}), 403
    try:
        msgs = SupportMessage.query.order_by(
            (SupportMessage.status == 'replied'), SupportMessage.id.desc()
        ).all()
        result = []
        for m in msgs:
            u = User.query.get(m.user_id)
            result.append({
                'id': m.id,
                'username': u.username if u else 'Unknown',
                'fullName': u.full_name if u else 'Unknown',
                'subject': m.subject,
                'message': m.message,
                'status': m.status,
                'adminReply': m.admin_reply,
                'createdAt': m.created_at,
                'repliedAt': m.replied_at,
            })
        return jsonify({'messages': result})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa admin support list: {e}")
        return jsonify({'error': 'May naganap na error.'}), 500

@app.route('/api/admin/support/<int:msg_id>/reply', methods=['POST'])
def admin_reply_support_message(msg_id):
    if not require_admin():
        return jsonify({'error': 'Admin access only.'}), 403
    try:
        msg = SupportMessage.query.get(msg_id)
        if not msg:
            return jsonify({'error': 'Not found'}), 404
        data = request.json or {}
        reply = (data.get('reply') or '').strip()
        if not reply:
            return jsonify({'error': 'Kailangan ng reply.'}), 400
        if len(reply) > 2000:
            return jsonify({'error': 'Masyadong mahaba ang reply (max 2000 characters).'}), 400
        msg.admin_reply = reply
        msg.status = 'replied'
        msg.replied_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M')
        db.session.commit()
        return jsonify({'message': 'Naipadala ang reply.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error sa admin reply: {e}")
        return jsonify({'error': 'May naganap na error sa pag-reply.'}), 500
@app.route('/api/admin/dashboard', methods=['GET'])
def admin_dashboard():
    if not require_admin():
        return jsonify({'error': 'Admin access only.'}), 403
    try:
        try:
            days = int(request.args.get('range', 30))
        except (TypeError, ValueError):
            days = 30
        if days not in (7, 30, 90):
            days = 30

        today = datetime.utcnow().date()
        start = today - timedelta(days=days - 1)         
        prev_start = start - timedelta(days=days)         
        prev_end = start - timedelta(days=1)

        s_cur, s_prev, e_prev = start.isoformat(), prev_start.isoformat(), prev_end.isoformat()
        s_today = today.isoformat()

        def in_range(dstr, lo, hi):
            return bool(dstr) and lo <= dstr <= hi

        def pct(cur, prev):
            if prev == 0:
                return None
            return round(((cur - prev) / prev) * 100, 1)

        records = Record.query.all()
        incomes = ActualIncome.query.all()

        produce_cur = expense_cur = 0.0
        produce_prev = expense_prev = 0.0
        produce_count_cur = produce_count_prev = 0
        active_cur, active_prev = set(), set()
        daily = {}   

        for i in range(days):
            daily[(start + timedelta(days=i)).isoformat()] = {'produce': 0.0, 'expense': 0.0}

        for r in records:
            amt = float(r.amount or 0)
            if in_range(r.date, s_cur, s_today):
                active_cur.add(r.user_id)
                if r.type == 'produce':
                    produce_cur += amt
                    produce_count_cur += 1
                    if r.date in daily:
                        daily[r.date]['produce'] += amt
                elif r.type == 'expense':
                    expense_cur += amt
                    if r.date in daily:
                        daily[r.date]['expense'] += amt
            elif in_range(r.date, s_prev, e_prev):
                active_prev.add(r.user_id)
                if r.type == 'produce':
                    produce_prev += amt
                    produce_count_prev += 1
                elif r.type == 'expense':
                    expense_prev += amt

        income_cur = sum(float(i.amount or 0) for i in incomes if in_range(i.date, s_cur, s_today))
        income_prev = sum(float(i.amount or 0) for i in incomes if in_range(i.date, s_prev, e_prev))

        chart = [
            {'date': d, 'produce': round(v['produce'], 2), 'expense': round(v['expense'], 2)}
            for d, v in sorted(daily.items())
        ]

        total_farmers = User.query.filter_by(role='farmer').count()
        subscribed = User.query.filter(User.role == 'farmer', User.purchased_cycles > 0).count()
        open_concerns = SupportMessage.query.filter_by(status='open').count()
        total_concerns = SupportMessage.query.count()

        rated = [r.rating for r in records if r.rating]
        avg_rating = round(sum(rated) / len(rated), 1) if rated else None

        names = {u.id: (u.full_name or u.username, u.avatar) for u in User.query.all()}
        activity = []
        for r in sorted(records, key=lambda x: (x.date or '', x.id), reverse=True)[:12]:
            who, av = names.get(r.user_id, ('Unknown', '🌾'))
            activity.append({
                'farmer': who, 'avatar': av, 'item': r.name,
                'category': r.category or '—', 'date': r.date,
                'amount': round(float(r.amount or 0), 2),
                'type': 'produce' if r.type == 'produce' else 'expense',
                'sort': (r.date or '', r.id),
            })
        for i in sorted(incomes, key=lambda x: (x.date or '', x.id), reverse=True)[:6]:
            who, av = names.get(i.user_id, ('Unknown', '🌾'))
            activity.append({
                'farmer': who, 'avatar': av, 'item': i.product_name or 'Aktwal na kita',
                'category': 'Benta', 'date': i.date,
                'amount': round(float(i.amount or 0), 2),
                'type': 'income',
                'sort': (i.date or '', i.id),
            })
        activity.sort(key=lambda a: a['sort'], reverse=True)
        for a in activity:
            a.pop('sort', None)
        activity = activity[:8]

        net_cur = produce_cur - expense_cur
        net_prev = produce_prev - expense_prev

        return jsonify({
            'rangeDays': days,
            'periodStart': s_cur,
            'periodEnd': s_today,
            'produceValue': round(produce_cur, 2),
            'produceChange': pct(produce_cur, produce_prev),
            'expenses': round(expense_cur, 2),
            'expenseChange': pct(expense_cur, expense_prev),
            'netValue': round(net_cur, 2),
            'netChange': pct(net_cur, net_prev),
            'actualIncome': round(income_cur, 2),
            'incomeChange': pct(income_cur, income_prev),
            'activeFarmers': len(active_cur),
            'activeFarmersChange': pct(len(active_cur), len(active_prev)),
            'totalFarmers': total_farmers,
            'produceLogged': produce_count_cur,
            'produceLoggedChange': pct(produce_count_cur, produce_count_prev),
            'subscribedFarmers': subscribed,
            'openConcerns': open_concerns,
            'totalConcerns': total_concerns,
            'avgRating': avg_rating,
            'chart': chart,
            'activity': activity,
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error sa admin dashboard: {e}")
        return jsonify({'error': 'May naganap na error sa dashboard.'}), 500

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, port=5000)
