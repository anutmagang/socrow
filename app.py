import os as _os
_DEBUG = _os.environ.get('DEBUG', '0').lower() in ('1', 'true', 'yes', 'y')
if not _DEBUG:
    try:
        import eventlet
        eventlet.monkey_patch()
    except Exception:
        pass

from flask import Flask, render_template, request, redirect, session, jsonify, flash, abort, url_for, send_from_directory, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()
from fpdf import FPDF
import io
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, random, string, re, json, logging, uuid, hmac, secrets
import magic
from PIL import Image

# ─── KONFIGURASI ────────────────────────────────────────────────────────────
app = Flask(__name__)
DEBUG = _DEBUG
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', '1' if not DEBUG else '0').lower() in ('1', 'true', 'yes', 'y')
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY and not DEBUG:
    raise RuntimeError("SECRET_KEY is required when DEBUG is false")

app.secret_key      = SECRET_KEY or os.urandom(32)
app.permanent_session_lifetime = timedelta(days=7)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = FORCE_HTTPS

csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com"
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com"
    ],
    'font-src': [
        "'self'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.gstatic.com"
    ],
    'img-src': ["'self'", "data:", "https:"],
    'media-src': ["'self'", "data:", "https:"]
}

talisman = Talisman(app, content_security_policy=csp, force_https=FORCE_HTTPS)
_cors_raw = os.environ.get('CORS_ALLOWED_ORIGINS', '').strip()
_cors_list = [o.strip() for o in _cors_raw.split(',') if o.strip()] if _cors_raw else None
REDIS_URL = os.environ.get('REDIS_URL', '').strip() or None
socketio = SocketIO(app, cors_allowed_origins=_cors_list, async_mode='eventlet', message_queue=REDIS_URL)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=REDIS_URL or "memory://",
)

UPLOAD_FOLDER   = 'static/uploads'
ALLOWED_EXT     = {'png','jpg','jpeg','gif','webp','mp4','pdf'}
MAX_UPLOAD_MB   = 16
ADMIN_EMAIL     = os.environ.get('ADMIN_EMAIL', 'admin@socrow.com')
BASE_URL        = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
DATABASE_URL    = os.environ.get('DATABASE_URL', '').strip()
APP_NAME        = 'Socrow'
FEE_PERSEN      = 0.015          # 1.5% ke platform
FEE_AFILIASI    = 0.005          # 0.5% ke afiliator
WITHDRAW_FEE    = 2500
WITHDRAW_MIN    = 50000
AFILIASI_MIN    = 10000
DISPUTE_HOURS   = 24             # deadline admin selesaikan dispute

app.config['UPLOAD_FOLDER']       = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH']  = MAX_UPLOAD_MB * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(f'{UPLOAD_FOLDER}/digital', exist_ok=True)
os.makedirs(f'{UPLOAD_FOLDER}/evidence', exist_ok=True)

# Xendit (opsional)
invoice_api = None
X_CALLBACK_TOKEN = (os.environ.get('XENDIT_WEBHOOK_TOKEN') or os.environ.get('XENDIT_CALLBACK_TOKEN') or '').strip()
try:
    import xendit
    from xendit.apis import InvoiceApi
    X_KEY = os.environ.get('XENDIT_SECRET_KEY','')
    if X_KEY and not X_KEY.startswith('xnd_development_...'):
        api_client = xendit.ApiClient(configuration=xendit.Configuration(
            api_key={'XENDIT_API_KEY': X_KEY}))
        invoice_api = InvoiceApi(api_client)
except ImportError:
    logging.warning("Xendit library not found. Running without Xendit integration.")
except Exception as e:
    logging.error(f"Error initializing Xendit: {e}", exc_info=True)


# ─── SECURITY HEADERS ────────────────────────────────────────────────────────
# Talisman already handles most of these.
@app.before_request
def update_last_seen():
    if 'user_id' in session:
        try:
            conn = get_db()
            conn.execute("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=?", (session['user_id'],))
            conn.commit(); conn.close()
        except: pass

def csrf_token():
    tok = session.get('_csrf_token')
    if not tok:
        tok = secrets.token_urlsafe(32)
        session['_csrf_token'] = tok
    return tok

@app.before_request
def enforce_csrf():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    p = request.path or ''
    if p.startswith('/socket.io'):
        return
    if p == '/xendit_webhook':
        return
    sent = request.headers.get('X-CSRFToken')
    if not sent:
        sent = request.form.get('_csrf_token') if request.form else None
    if not sent:
        try:
            j = request.get_json(silent=True) or {}
            sent = j.get('_csrf_token')
        except Exception:
            sent = None
    tok = session.get('_csrf_token') or ''
    if not sent or not tok or not hmac.compare_digest(str(sent), str(tok)):
        abort(403)

@app.after_request
def add_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return resp

# ─── HELPERS ────────────────────────────────────────────────────────────────
class _DummyCursor:
    def fetchone(self): return None
    def fetchall(self): return []

class _HybridRow(dict):
    def __init__(self, cols, row):
        super().__init__(zip(cols, row))
        self._row = row
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._row[key]
        return super().__getitem__(key)

def _psycopg_hybrid_row(cursor, row):
    cols = [d.name for d in (cursor.description or [])]
    return _HybridRow(cols, row)

def _adapt_sql_for_postgres(sql):
    s = sql.strip()
    up = s.upper()
    if up.startswith("PRAGMA "):
        return None
    if up.startswith("BEGIN IMMEDIATE"):
        return "BEGIN"
    if "LAST_INSERT_ROWID()" in up:
        return "SELECT LASTVAL()"
    if up.startswith("INSERT OR IGNORE INTO"):
        s2 = re.sub(r'(?i)^INSERT OR IGNORE INTO', 'INSERT INTO', s)
        if "ON CONFLICT" not in s2.upper():
            s2 = s2.rstrip().rstrip(';') + " ON CONFLICT DO NOTHING"
        s = s2
    return s.replace("?", "%s")

class _CompatConn:
    def __init__(self, conn, backend):
        self._conn = conn
        self._backend = backend
    def execute(self, sql, params=None):
        if self._backend == "postgres":
            sql = _adapt_sql_for_postgres(sql)
            if sql is None:
                return _DummyCursor()
            if params is None:
                return self._conn.execute(sql)
            return self._conn.execute(sql, params)
        if params is None:
            return self._conn.execute(sql)
        return self._conn.execute(sql, params)
    def commit(self): return self._conn.commit()
    def rollback(self): return self._conn.rollback()
    def close(self): return self._conn.close()

def get_db():
    if DATABASE_URL and (DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgres://")):
        try:
            import psycopg
        except Exception as e:
            raise RuntimeError("psycopg is required for PostgreSQL") from e
        conn = psycopg.connect(DATABASE_URL, row_factory=_psycopg_hybrid_row)
        return _CompatConn(conn, "postgres")

    db_path = 'sosmed_rekber.db'
    if DATABASE_URL.startswith("sqlite:///"):
        db_path = DATABASE_URL.replace("sqlite:///", "")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return _CompatConn(conn, "sqlite")

def allowed_file(file_obj):
    if not file_obj or not file_obj.filename: return False
    fn = file_obj.filename
    if '.' not in fn: return False
    ext = fn.rsplit('.', 1)[1].lower()
    if ext not in ALLOWED_EXT: return False
    
    # MIME-Type Validation (More Secure)
    try:
        header = file_obj.read(2048)
        file_obj.seek(0)
        mime = magic.from_buffer(header, mime=True)
        
        allowed_mimes = {
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'application/pdf'
        }
        return mime in allowed_mimes
    except Exception as e:
        logging.error(f"MIME check error: {e}")
        return False

def gen_ref_code(n=8):
    return ''.join(random.choices(string.ascii_uppercase+string.digits, k=n))

def validate_password(pw):
    return len(pw)>=8 and re.search(r'[A-Za-z]',pw) and re.search(r'[0-9]',pw)

def rupiah(v):
    try:
        return "Rp {:,.0f}".format(float(v)).replace(",",".")
    except (ValueError, TypeError):
        return "Rp 0"

def optimize_image(file_path, max_width=1080):
    try:
        if file_path.lower().endswith(('.mp4', '.pdf')): return
        img = Image.open(file_path)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        if img.width > max_width:
            w_percent = (max_width / float(img.width))
            h_size = int((float(img.height) * float(w_percent)))
            img = img.resize((max_width, h_size), Image.Resampling.LANCZOS)
        img.save(file_path, "JPEG", quality=80, optimize=True)
    except Exception as e:
        logging.error(f"Image optimization error: {e}")

def audit(action, detail=None, user_id=None):
    try:
        conn = get_db()
        uid  = user_id or session.get('user_id')
        ip   = request.remote_addr if request else '127.0.0.1'
        ua   = request.headers.get('User-Agent','') if request else ''
        conn.execute("INSERT INTO audit_logs(user_id,action,detail,ip_address,user_agent) VALUES(?,?,?,?,?)",
                     (uid, action, detail, ip, ua))
        conn.commit(); conn.close()
    except sqlite3.Error as e:
        logging.error(f"Database error in audit: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in audit: {e}", exc_info=True)


def notif(user_id, title, message, link='/', ntype='info'):
    try:
        conn = get_db()
        conn.execute("INSERT INTO notifications(user_id,title,message,type,link) VALUES(?,?,?,?,?)",
                     (user_id, title, message, ntype, link))
        conn.commit(); conn.close()
        # Broadcast real-time
        socketio.emit('notification', {
            'title': title,
            'message': message,
            'link': link,
            'type': ntype
        }, room=f"user_{user_id}")
    except sqlite3.Error as e:
        logging.error(f"Database error in notif: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in notif: {e}", exc_info=True)


def sys_msg(room_id, text):
    try:
        conn = get_db()
        conn.execute("INSERT INTO messages(room_id,sender_id,message_text,message_type) VALUES(?,0,?,'system')",
                     (room_id, text))
        conn.commit(); conn.close()
        # Broadcast to room
        socketio.emit('new_message', {
            'sender_id': 0,
            'sender_name': 'SYSTEM',
            'message_text': text,
            'message_type': 'system',
            'created_at': datetime.now().strftime('%H:%M')
        }, room=f"room_{room_id}")
    except sqlite3.Error as e:
        logging.error(f"Database error in sys_msg: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in sys_msg: {e}", exc_info=True)


def get_notif_count():
    if 'user_id' not in session: return 0
    try:
        conn = get_db()
        n = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                         (session['user_id'],)).fetchone()[0]
        conn.close(); return n
    except sqlite3.Error as e:
        logging.error(f"Database error in get_notif_count: {e}")
        return 0
    except Exception as e:
        logging.error(f"Unexpected error in get_notif_count: {e}", exc_info=True)
        return 0

def hashtag_link(text):
    if not text: return ""
    import html
    text = html.escape(text)
    # Replace #hashtag with <a href="/explore?q=%23hashtag">#hashtag</a>
    text = re.sub(r'#([a-zA-Z0-9_]+)', r'<a href="/explore?q=%23\1" style="color:var(--accent); text-decoration:none; font-weight:600;">#\1</a>', text)
    # Replace @username with <a href="/user/\1">@\1</a>
    return re.sub(r'@([a-zA-Z0-9_]+)', r'<a href="/user/\1" style="color:var(--accent-light); text-decoration:none; font-weight:700;">@\1</a>', text)

def process_mentions(text, post_uuid=None, comment_id=None):
    if not text: return
    mentions = re.findall(r'@([a-zA-Z0-9_]+)', text)
    if not mentions: return
    
    conn = get_db()
    for username in set(mentions):
        user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if user and user['id'] != session.get('user_id'):
            link = f"/?q={post_uuid}" if post_uuid else f"/post/{post_uuid}#comment-{comment_id}"
            notif(user['id'], f'👤 Kamu ditandai!', f'@{session["username"]} menyebut kamu dalam postingan.', link, 'info')
    conn.close()

def is_online(last_seen_str):
    if not last_seen_str: return False
    try:
        if '.' in last_seen_str:
            ls = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S.%f')
        else:
            ls = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
        return (datetime.now() - ls).total_seconds() < 300 # 5 minutes
    except: return False

def get_seller_badge(user_id):
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE seller_id=? AND status='selesai'", (user_id,)).fetchone()[0]
    conn.close()
    
    if count >= 200: return {'name': 'Platinum Seller', 'color': '#e5e4e2', 'icon': 'fa-gem'}
    if count >= 50:  return {'name': 'Gold Seller', 'color': '#ffd700', 'icon': 'fa-crown'}
    if count >= 10:  return {'name': 'Silver Seller', 'color': '#c0c0c0', 'icon': 'fa-medal'}
    return {'name': 'Bronze Seller', 'color': '#cd7f32', 'icon': 'fa-award'}

app.jinja_env.filters['hashtags'] = hashtag_link
app.jinja_env.filters['rupiah'] = rupiah
app.jinja_env.globals.update(get_notif_count=get_notif_count, is_online=is_online, get_seller_badge=get_seller_badge,
                             app_name=APP_NAME, admin_email=ADMIN_EMAIL, now=datetime.now, csrf_token=csrf_token)

# ─── DECORATORS ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.','warning')
            return redirect(f'/login?next={request.path}')
        return f(*a,**k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        if session.get('email') != ADMIN_EMAIL: abort(403)
        return f(*a,**k)
    return w

# ─── ERROR HANDLERS ─────────────────────────────────────────────────────────
@app.errorhandler(403)
def e403(e): return render_template('error.html',code=403,msg="Akses Ditolak"),403
@app.errorhandler(404)
def e404(e): return render_template('error.html',code=404,msg="Halaman Tidak Ditemukan"),404
@app.errorhandler(500)
def e500(e): return render_template('error.html',code=500,msg="Kesalahan Server"),500

# ─── AUTH ────────────────────────────────────────────────────────────────────
@app.route('/daftar', methods=['GET','POST'])
@limiter.limit("5 per hour")
def daftar():
    if 'user_id' in session: return redirect('/')
    ref = request.args.get('ref','')
    if request.method == 'POST':
        u  = request.form.get('username','').strip()
        e  = request.form.get('email','').strip().lower()
        p  = request.form.get('phone','').strip()
        pw = request.form.get('password','')
        c  = request.form.get('confirm_password','')
        ref_code = request.form.get('ref_code','').strip().upper()

        errs = []
        if not u or len(u)<3: errs.append("Username minimal 3 karakter.")
        if not re.match(r'^[a-zA-Z0-9_]+$',u): errs.append("Username hanya huruf, angka, dan underscore.")
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', e):
            errs.append("Format email tidak valid.")
        if not p or not re.match(r'^\d{10,15}$', p):
            errs.append("Nomor telepon tidak valid (10-15 digit angka).")
        if not validate_password(pw): errs.append("Password minimal 8 karakter, huruf+angka.")
        if pw!=c: errs.append("Konfirmasi password tidak cocok.")
        for er in errs:
            flash(er,'danger')
        if errs: return render_template('daftar.html', ref=ref)

        code = gen_ref_code()
        conn = get_db()
        try:
            # Cek referral
            referrer_id = None
            if ref_code:
                ref_row = conn.execute("SELECT user_id FROM affiliates WHERE code=? AND is_active=1",(ref_code,)).fetchone()
                if ref_row:
                    referrer_id = ref_row['user_id']
                    referred_by = conn.execute("SELECT id FROM users WHERE id=?",(referrer_id,)).fetchone()
                    if not referred_by: referrer_id = None

            conn.execute("""INSERT INTO users(uuid,username,email,phone,password,referral_code,referred_by)
                            VALUES(?,?,?,?,?,?,?)""",
                         (str(uuid.uuid4()), u, e, p, ph.hash(pw), code, referrer_id))
            user_id = conn.execute("SELECT id FROM users WHERE email=?",(e,)).fetchone()['id']

            # Buat kode afiliasi otomatis
            conn.execute("INSERT INTO affiliates(user_id,code) VALUES(?,?)",(user_id,code))

            if referrer_id:
                conn.execute("UPDATE affiliates SET total_referred=total_referred+1 WHERE user_id=?",
                             (referrer_id,))
                notif(referrer_id,'🎉 Referral Baru!',
                      f'{u} bergabung menggunakan kode referralmu!','/akun')

            conn.execute("UPDATE platform_stats SET total_users=total_users+1 WHERE id=1")
            conn.commit()
            audit('REGISTER', f'user={u}', user_id)
            flash('Akun berhasil dibuat! Silakan login.','success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username atau email sudah terdaftar.','danger')
        finally: conn.close()
    return render_template('daftar.html', ref=ref)

# ─── OTP HELPERS ─────────────────────────────────────────────────────────────
def send_otp(user_id, email):
    otp = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=10)
    conn = get_db()
    conn.execute("UPDATE users SET otp_code=?, otp_expiry=? WHERE id=?", (otp, expiry, user_id))
    conn.commit(); conn.close()
    if DEBUG or os.environ.get('OTP_CONSOLE', '0').lower() in ('1', 'true', 'yes', 'y'):
        print(f"\n[EMAIL SIMULATION] To: {email} | OTP Code: {otp}\n")
    else:
        logging.info("OTP generated for user_id=%s", user_id)
    return otp

@app.route('/login', methods=['GET','POST'])
@limiter.limit("10 per minute")
def login():
    if 'user_id' in session: return redirect('/')
    if request.method == 'POST':
        ident = request.form.get('username','').strip()
        pw    = request.form.get('password','')
        conn  = get_db()
        try:
            user  = conn.execute("SELECT * FROM users WHERE (username=? OR email=?) AND is_banned=0",
                                 (ident, ident.lower())).fetchone()
            
            if user:
                # Multi-algorithm Password Check (Argon2 + Legacy PBKDF2)
                is_valid = False
                needs_rehash = False
                
                if user['password'].startswith('$argon2'):
                    try:
                        ph.verify(user['password'], pw)
                        is_valid = True
                        # check_needs_rehash requires a full hash string
                        if ph.check_needs_rehash(user['password']):
                            needs_rehash = True
                    except (VerifyMismatchError, Exception):
                        is_valid = False
                else:
                    # Legacy check
                    from werkzeug.security import check_password_hash
                    if check_password_hash(user['password'], pw):
                        is_valid = True
                        needs_rehash = True # Force upgrade to Argon2
                
                if is_valid:
                    # Upgrade hash to Argon2 if needed
                    if needs_rehash:
                        new_h = ph.hash(pw)
                        conn.execute("UPDATE users SET password=? WHERE id=?", (new_h, user['id']))
                        conn.commit()
                    
                    # 2FA Login Flow
                    send_otp(user['id'], user['email'])
                    session['pending_user_id'] = user['id']
                    session['otp_next'] = request.args.get('next', '/')
                    
                    audit('LOGIN_OTP_SENT', f'user={user["username"]}', user['id'])
                    flash('Kode OTP telah dikirim ke email kamu (cek konsol).', 'info')
                    conn.close()
                    return redirect('/verify_otp')
                else:
                    flash('Username atau password salah.', 'danger')
            else:
                flash('Username atau password salah.', 'danger')
        except Exception as e:
            logging.error(f"Login error: {e}")
            flash('Terjadi kesalahan sistem.', 'danger')
        finally:
            if conn: conn.close()
    return render_template('login.html')

@app.route('/api/posts')
def api_posts():
    offset = int(request.args.get('offset', 0))
    cat    = request.args.get('cat','')
    q      = request.args.get('q','')
    mode   = request.args.get('mode','social') # 'social' or 'market'
    
    conn = get_db()
    sql = '''SELECT p.*, u.username, u.kyc_status FROM posts p 
             JOIN users u ON p.user_id=u.id 
             WHERE p.is_active=1 AND u.is_banned=0'''
    params = []
    
    if mode == 'social':
        sql += " AND p.is_for_sale=0"
    else:
        sql += " AND p.is_for_sale=1"

    if q: 
        if q.startswith('#'):
            # Hashtag search
            tag = q[1:]
            sql += " AND p.caption LIKE ?"
            params.append(f'%#{tag}%')
        else:
            sql += " AND p.caption LIKE ?"
            params.append(f'%{q}%')
    if cat: sql += " AND p.product_category=?"; params.append(cat)
    
    sql += " ORDER BY p.id DESC LIMIT 10 OFFSET ?"
    params.append(offset)
    
    posts = conn.execute(sql, params).fetchall()
    conn.close()
    
    return jsonify([dict(p) for p in posts])

@app.route('/verify_otp', methods=['GET','POST'])
def verify_otp():
    if 'pending_user_id' not in session: return redirect('/login')
    
    if request.method == 'POST':
        otp = request.form.get('otp','')
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['pending_user_id'],)).fetchone()
        
        if user and user['otp_code'] == otp:
            # Cek expiry secara robust
            expiry_str = user['otp_expiry']
            try:
                # SQLite TIMESTAMP could be in various formats depending on how it was saved
                if '.' in expiry_str:
                    expiry_dt = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
                else:
                    expiry_dt = datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')
            except (ValueError, TypeError):
                expiry_dt = datetime.min # Force expired if format error
            
            if datetime.now() < expiry_dt:
                uid = user['id']
                session.clear(); session.permanent = True
                session.update({
                    'user_id': user['id'],
                    'user_uuid': user['uuid'],
                    'username': user['username'],
                    'email': user['email']
                })
                
                # Cleanup OTP session
                session.pop('pending_user_id', None)
                next_url = session.pop('otp_next', '/')
                
                # Enhanced Logging
                ua = request.headers.get('User-Agent','')
                audit('LOGIN_2FA', f'UA: {ua[:100]}', uid)
                
                conn.execute("UPDATE users SET otp_code=NULL, otp_expiry=NULL WHERE id=?", (uid,))
                conn.commit(); conn.close()
                flash(f'Selamat datang kembali, {user["username"]}! 👋','success')
                return redirect(next_url)
            else:
                logging.warning(f"OTP expired for user_id {user['id']} from IP {request.remote_addr}")
                flash('OTP sudah kadaluwarsa.','danger')
        else:
            logging.warning(f"Failed OTP verification attempt for user_id {user['id']} from IP {request.remote_addr}")
            flash('OTP salah.','danger')
        conn.close()
        
    return render_template('verify_otp.html')

@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    flash('Berhasil logout.','info')
    return redirect('/')

# ─── HOME / FEED (SOCIAL ONLY) ──────────────────────────────────────────────
@app.route('/')
def home():
    q_target = request.args.get('q','')
    conn = get_db()
    
    # Base query
    sql = '''SELECT p.*, u.username, u.kyc_status,
                    (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as like_count,
                    (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comment_count
             FROM posts p JOIN users u ON p.user_id=u.id
             WHERE p.is_active=1 AND p.is_for_sale=0 AND u.is_banned=0'''
    params = []
    
    if q_target:
        if len(str(q_target)) > 30:
            sql += " AND p.uuid=?"
            params.append(q_target)
        elif str(q_target).isdigit():
            sql += " AND p.id=?"
            params.append(int(q_target))
    
    sql += " ORDER BY p.id DESC LIMIT 10"
    posts_raw = conn.execute(sql, params).fetchall()
    
    posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        posts.append(p_dict)

    # Stories
    stories = conn.execute('''SELECT s.*, u.username FROM stories s 
                              JOIN users u ON s.user_id=u.id 
                              WHERE s.expires_at > CURRENT_TIMESTAMP 
                              ORDER BY s.id DESC''').fetchall()
    
    conn.close()
    return render_template('index.html', posts=posts, stories=stories)

@app.route('/explore')
def explore():
    conn = get_db()
    # Postingan populer (berdasarkan jumlah like)
    posts_raw = conn.execute('''SELECT p.*, u.username, 
                                     (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as like_count
                              FROM posts p JOIN users u ON p.user_id=u.id
                              WHERE p.is_active=1 AND p.is_for_sale=0 AND u.is_banned=0
                              ORDER BY like_count DESC LIMIT 21''').fetchall()
    
    posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        posts.append(p_dict)
    
    # Rekomendasi user untuk diikuti
    suggested_users = conn.execute('''SELECT id, username, rating_avg FROM users 
                                      WHERE is_banned=0 AND id != ?
                                      ORDER BY rating_avg DESC LIMIT 5''', (session.get('user_id', 0),)).fetchall()
    conn.close()
    return render_template('explore.html', posts=posts, suggested_users=suggested_users)

@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    if not q: return redirect('/explore')
    
    conn = get_db()
    # Search Users
    users = conn.execute("SELECT id, username, bio, kyc_status, user_uuid, avatar_url FROM users WHERE username LIKE ? AND is_banned=0 LIMIT 10", (f'%{q}%',)).fetchall()
    
    # Search Social Posts
    posts_raw = conn.execute('''SELECT p.*, u.username, u.kyc_status,
                                     (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as like_count
                              FROM posts p JOIN users u ON p.user_id=u.id
                              WHERE p.is_active=1 AND p.is_for_sale=0 AND u.is_banned=0 AND p.caption LIKE ?
                              ORDER BY p.id DESC LIMIT 10''', (f'%{q}%',)).fetchall()
    
    social_posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        social_posts.append(p_dict)

    # Search Products
    prod_raw = conn.execute('''SELECT p.*, u.username, u.kyc_status, u.rating_avg
                              FROM posts p JOIN users u ON p.user_id=u.id
                              WHERE p.is_active=1 AND p.is_for_sale=1 AND u.is_banned=0 AND p.caption LIKE ?
                              ORDER BY p.id DESC LIMIT 10''', (f'%{q}%',)).fetchall()
    
    products = []
    for p in prod_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        products.append(p_dict)
        
    conn.close()
    return render_template('search_results.html', users=users, social_posts=social_posts, products=products, q=q)

# ─── STORE / MARKETPLACE ────────────────────────────────────────────────────
@app.route('/store')
def store():
    q    = request.args.get('q','')
    cat  = request.args.get('cat','')
    min_p = request.args.get('min_price','')
    max_p = request.args.get('max_price','')
    sort  = request.args.get('sort','latest')

    conn = get_db()
    sql  = '''SELECT p.*, u.username, u.kyc_status, u.store_name, u.rating_avg
              FROM posts p JOIN users u ON p.user_id=u.id
              WHERE p.is_active=1 AND p.is_for_sale=1 AND u.is_banned=0'''
    params = []
    if q:    sql += " AND (p.caption LIKE ? OR u.username LIKE ?)"; params+=[f'%{q}%',f'%{q}%']
    if cat:  sql += " AND p.product_category=?"; params.append(cat)
    if min_p: sql += " AND p.price >= ?"; params.append(float(min_p))
    if max_p: sql += " AND p.price <= ?"; params.append(float(max_p))

    allowed_sorts = {'latest': 'p.id DESC', 'cheapest': 'p.price ASC', 'expensive': 'p.price DESC'}
    order_by_clause = allowed_sorts.get(sort, 'p.id DESC')
    sql += f" ORDER BY {order_by_clause}"

    posts_raw = conn.execute(sql, params).fetchall()
    posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        posts.append(p_dict)
    
    conn.close()
    
    cats = [
        {'id':'umum','icon':'fa-box'},
        {'id':'elektronik','icon':'fa-laptop'},
        {'id':'fashion','icon':'fa-shirt'},
        {'id':'makanan','icon':'fa-bowl-food'},
        {'id':'digital','icon':'fa-code'},
        {'id':'jasa','icon':'fa-handshake-angle'},
        {'id':'otomotif','icon':'fa-car'},
        {'id':'hobi','icon':'fa-puzzle-piece'}
    ]
    return render_template('store.html', posts=posts, q=q, cat=cat, 
                           min_price=min_p, max_price=max_p, sort=sort, cats=cats)

@app.route('/store/@<username>')
def merchant_store(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND is_banned=0", (username,)).fetchone()
    if not user: conn.close(); abort(404)
    
    # Store Posts only
    posts_raw = conn.execute('''SELECT p.*, u.username, u.kyc_status, u.store_name, u.rating_avg
                                FROM posts p JOIN users u ON p.user_id=u.id
                                WHERE p.user_id=? AND p.is_active=1 AND p.is_for_sale=1
                                ORDER BY p.id DESC''', (user['id'],)).fetchall()
    
    posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        posts.append(p_dict)
        
    reviews = conn.execute("""SELECT r.*, u.username as reviewer FROM ratings r
                              JOIN users u ON r.reviewer_id=u.id
                              WHERE r.reviewed_id=? ORDER BY r.id DESC LIMIT 20""",(user['id'],)).fetchall()
    
    conn.close()
    return render_template('merchant_store.html', seller=user, posts=posts, reviews=reviews)

# ─── POST / PRODUK ──────────────────────────────────────────────────────────
@app.route('/tambah/post', methods=['GET','POST'])
@login_required
@limiter.limit("3 per minute")
def tambah_social():
    if request.method == 'POST':
        caption  = request.form.get('caption','').strip()
        if not caption:
            flash('Caption wajib diisi.','danger')
            return render_template('tambah_social.html')

        media = request.files.get('media_file')
        filename, pt = '', 'text'
        if media and media.filename and allowed_file(media):
            ext = media.filename.rsplit('.',1)[1].lower()
            clean_fn = secure_filename(media.filename)
            filename = f"social_{session['user_id']}_{random.randint(10000,99999)}_{clean_fn}"
            fpath = os.path.join(UPLOAD_FOLDER, filename)
            media.save(fpath)
            if ext != 'mp4': optimize_image(fpath)
            pt = 'video' if ext=='mp4' else 'image'

        conn = get_db()
        post_uuid = str(uuid.uuid4())
        conn.execute("""INSERT INTO posts(uuid,user_id,post_type,media_url,caption,is_for_sale)
                        VALUES(?,?,?,?,?,0)""",(post_uuid,session['user_id'],pt,filename,caption))
        
        post_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Multiple Images
        for f in request.files.getlist('extra_images'):
            if f and f.filename and allowed_file(f):
                ext2 = f.filename.rsplit('.',1)[1].lower()
                fn2  = f"extra_{post_id}_{random.randint(1000,9999)}.{ext2}"
                fpath2 = os.path.join(UPLOAD_FOLDER, fn2)
                f.save(fpath2)
                if ext2 != 'mp4': optimize_image(fpath2)
                conn.execute("INSERT INTO post_images(post_id,image_url) VALUES(?,?)",(post_id,fn2))

        conn.commit(); conn.close()
        process_mentions(caption, post_uuid=post_uuid)
        flash('Postingan sosial berhasil dibagikan! 📸','success')
        return redirect('/')
    return render_template('tambah_social.html')

@app.route('/tambah/produk', methods=['GET','POST'])
@login_required
@limiter.limit("3 per minute")
def tambah_produk():
    if request.method == 'POST':
        caption  = request.form.get('caption','').strip()
        cat      = request.form.get('product_category','umum')
        kind     = request.form.get('product_kind','fisik')
        
        if not caption:
            flash('Nama produk wajib diisi.','danger')
            return render_template('tambah_produk.html')

        media = request.files.get('media_file')
        if not media or not media.filename:
            flash('Foto produk wajib diunggah.','danger')
            return render_template('tambah_produk.html')

        ext = media.filename.rsplit('.',1)[1].lower()
        clean_fn = secure_filename(media.filename)
        filename = f"prod_{session['user_id']}_{random.randint(10000,99999)}_{clean_fn}"
        fpath = os.path.join(UPLOAD_FOLDER, filename)
        media.save(fpath)
        optimize_image(fpath)

        conn = get_db()
        kyc = 'verified' if session.get('email')==ADMIN_EMAIL else \
              conn.execute("SELECT kyc_status FROM users WHERE id=?",(session['user_id'],)).fetchone()['kyc_status']
        
        if kyc != 'verified':
            conn.close(); flash('Wajib verifikasi KYC sebelum berjualan.','warning'); return redirect('/akun')

        try:
            price  = float(request.form.get('price',0))
            stock  = int(request.form.get('stock',1))
            weight = int(request.form.get('weight_gram',0))
        except ValueError:
            conn.close(); flash('Harga/stok/berat harus angka.','danger'); return render_template('tambah_produk.html')

        dig_file = None
        if kind == 'digital':
            df = request.files.get('digital_file')
            if df and df.filename and allowed_file(df):
                dext = df.filename.rsplit('.',1)[1].lower()
                dig_file = f"digital_{session['user_id']}_{random.randint(10000,99999)}.{dext}"
                df.save(os.path.join(UPLOAD_FOLDER,'digital',dig_file))

        post_uuid = str(uuid.uuid4())
        conn.execute("""INSERT INTO posts(uuid,user_id,post_type,product_category,product_kind,
                        media_url,caption,is_for_sale,price,stock,weight_gram,digital_file)
                        VALUES(?,?,?,?,?,?,?,1,?,?,?,?)""",
                     (post_uuid,session['user_id'],'image',cat,kind,filename,caption,price,stock,weight,dig_file))
        
        post_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit(); conn.close()
        process_mentions(caption, post_uuid=post_uuid)
        flash('Produk berhasil dipublikasikan di Store! 🛍️','success')
        return redirect('/store')
    
    cats = [
        {'id':'umum','icon':'fa-box'}, {'id':'elektronik','icon':'fa-laptop'},
        {'id':'fashion','icon':'fa-shirt'}, {'id':'makanan','icon':'fa-bowl-food'},
        {'id':'digital','icon':'fa-code'}, {'id':'jasa','icon':'fa-handshake-angle'},
        {'id':'otomotif','icon':'fa-car'}, {'id':'hobi','icon':'fa-puzzle-piece'}
    ]
    return render_template('tambah_produk.html', cats=cats)

@app.route('/tambah')
@login_required
def tambah_pilihan():
    return render_template('tambah_pilihan.html')

@app.route('/post/delete/<target>', methods=['POST'])
@login_required
def delete_post(target):
    conn = get_db()
    if len(str(target)) > 30:
        post = conn.execute("SELECT * FROM posts WHERE uuid=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT * FROM posts WHERE id=?", (target,)).fetchone()
        
    if not post or post['user_id'] != session['user_id']:
        conn.close(); abort(403)
    
    # Soft delete
    conn.execute("UPDATE posts SET is_active=0 WHERE id=?", (post['id'],))
    conn.commit(); conn.close()
    flash('Postingan berhasil dihapus.','success')
    return redirect(request.referrer or '/')

@app.route('/post/edit/<target>', methods=['GET','POST'])
@login_required
def edit_post(target):
    conn = get_db()
    if len(str(target)) > 30:
        post = conn.execute("SELECT * FROM posts WHERE uuid=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT * FROM posts WHERE id=?", (target,)).fetchone()
        
    if not post or post['user_id'] != session['user_id']:
        conn.close(); abort(403)
    
    if request.method == 'POST':
        caption = request.form.get('caption','').strip()[:1000]
        price   = float(request.form.get('price', 0)) if post['is_for_sale'] else 0
        stock   = int(request.form.get('stock', 1)) if post['is_for_sale'] else 0
        
        conn.execute("UPDATE posts SET caption=?, price=?, stock=? WHERE id=?", 
                     (caption, price, stock, post['id']))
        conn.commit(); conn.close()
        flash('Postingan berhasil diperbarui.','success')
        return redirect(url_for('user_profile', username=session['username']))
    
    conn.close()
    return render_template('edit_post.html', p=post)

@app.route('/cart')
@login_required
def cart_page():
    conn = get_db()
    items = conn.execute('''SELECT c.*, p.caption, p.price, p.media_url, u.username as seller_name
                            FROM carts c JOIN posts p ON c.post_id=p.id
                            JOIN users u ON p.user_id=u.id
                            WHERE c.user_id=?''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('cart.html', items=items)

@app.route('/cart/add/<target>', methods=['POST'])
@login_required
def add_to_cart(target):
    conn = get_db()
    # Resolve target (can be ID or UUID)
    if str(target).isdigit():
        post = conn.execute("SELECT * FROM posts WHERE id=? AND is_for_sale=1 AND is_active=1", (target,)).fetchone()
    else:
        post = conn.execute("SELECT * FROM posts WHERE uuid=? AND is_for_sale=1 AND is_active=1", (target,)).fetchone()

    if not post: conn.close(); return jsonify({"status":"err","msg":"Produk tidak tersedia"}), 404
    
    post_id = post['id']
    if post['user_id'] == session['user_id']:
        conn.close(); return jsonify({"status":"err","msg":"Tidak bisa beli produk sendiri"}), 400

    try:
        conn.execute("INSERT INTO carts(user_id, post_id) VALUES(?,?)", (session['user_id'], post_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.execute("UPDATE carts SET quantity=quantity+1 WHERE user_id=? AND post_id=?", (session['user_id'], post_id))
        conn.commit()
    
    count = conn.execute("SELECT SUM(quantity) FROM carts WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    conn.close()
    return jsonify({"status":"ok", "cart_count": count})

@app.route('/cart/remove/<int:cart_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_id):
    conn = get_db()
    conn.execute("DELETE FROM carts WHERE id=? AND user_id=?", (cart_id, session['user_id']))
    conn.commit(); conn.close()
    return redirect('/cart')

# ─── VOUCHER SYSTEM ─────────────────────────────────────────────────────────
@app.route('/voucher/create', methods=['POST'])
@login_required
def create_voucher():
    code = request.form.get('code','').strip().upper()
    disc = float(request.form.get('discount', 0))
    min_p = float(request.form.get('min_purchase', 0))
    if not code or disc <= 0: return redirect('/akun')
    
    conn = get_db()
    try:
        conn.execute("INSERT INTO vouchers(seller_id, code, discount_amount, min_purchase) VALUES(?,?,?,?)",
                     (session['user_id'], code, disc, min_p))
        conn.commit()
        flash(f'Voucher {code} berhasil dibuat!','success')
    except sqlite3.IntegrityError:
        flash('Kode voucher sudah digunakan.','danger')
    except sqlite3.Error as e:
        logging.error(f"Database error in create_voucher: {e}")
        flash('Terjadi kesalahan saat membuat voucher.','danger')
    except Exception as e:
        logging.error(f"Unexpected error in create_voucher: {e}", exc_info=True)
        flash('Terjadi kesalahan tak terduga.','danger')
    conn.close()
    return redirect('/akun')

# ─── CHECKOUT PAGE ──────────────────────────────────────────────────────────
@app.route('/checkout/<target>', methods=['GET'])
@login_required
def checkout(target):
    conn = get_db()
    if target == 'cart':
        # Get all items in cart
        items = conn.execute('''SELECT c.*, p.caption, p.price, p.media_url, p.user_id as seller_id, u.username as seller_name, p.uuid as p_uuid
                                FROM carts c JOIN posts p ON c.post_id=p.id
                                JOIN users u ON p.user_id=u.id
                                WHERE c.user_id=?''', (session['user_id'],)).fetchall()
        if not items:
            conn.close(); flash('Keranjang kosong.', 'warning'); return redirect('/cart')
        
        # Professional marketplaces handle multiple items by grouping by seller.
        # For Socrow's current room-based architecture, we process the first item.
        post = conn.execute("SELECT p.*, u.username as seller_name FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?", (items[0]['post_id'],)).fetchone()
    else:
        # Resolve target
        if str(target).isdigit():
            post = conn.execute("SELECT p.*, u.username as seller_name FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?", (target,)).fetchone()
        else:
            post = conn.execute("SELECT p.*, u.username as seller_name FROM posts p JOIN users u ON p.user_id=u.id WHERE p.uuid=?", (target,)).fetchone()

    if not post: abort(404)
    
    # Calculate Shipping (Simulated)
    # Rp 10.000 per 1000g (min 1kg)
    weight = post['weight_gram'] or 0
    kg = max(1, (weight + 999) // 1000)
    shipping_cost = kg * 10000 if post['product_kind'] == 'fisik' else 0
    
    conn.close()
    return render_template('checkout.html', post=post, shipping_cost=shipping_cost)
@app.route('/bayar/<target>', methods=['POST'])
@login_required
def bayar(target):
    conn = get_db()
    # Pessimistic Locking
    conn.execute("BEGIN IMMEDIATE")
    try:
        # Resolve target
        if str(target).isdigit():
            post = conn.execute("SELECT * FROM posts WHERE id=? AND is_for_sale=1 AND is_active=1", (target,)).fetchone()
        else:
            post = conn.execute("SELECT * FROM posts WHERE uuid=? AND is_for_sale=1 AND is_active=1", (target,)).fetchone()
            
        if not post:          conn.close(); flash('Produk tidak ditemukan.','danger');  return redirect('/')
        if post['user_id']==session['user_id']: conn.close(); flash('Tidak bisa beli produk sendiri.','warning'); return redirect('/')
        if post['stock']<1:   conn.close(); flash('Stok habis.','warning');            return redirect('/')

        post_id = post['id']
        user    = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
        ext_id  = f"SCR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(1000,9999)}"
        aff_code= request.form.get('affiliate_code','').strip().upper()
        v_code  = request.form.get('voucher_code','').strip().upper()
        
        price = float(post['price'])
        discount = 0
        if v_code:
            v = conn.execute("SELECT * FROM vouchers WHERE code=? AND seller_id=? AND is_active=1", (v_code, post['user_id'])).fetchone()
            if v and price >= v['min_purchase']:
                discount = v['discount_amount']
        
        # Calculate Shipping (Simulated)
        weight = post['weight_gram'] or 0
        kg = max(1, (weight + 999) // 1000)
        shipping_cost = kg * 10000 if post['product_kind'] == 'fisik' else 0
                
        total   = (price - discount) + shipping_cost + 2500
        if total < 0: total = 2500

        # Validasi kode afiliasi
        valid_aff = None
        if aff_code:
            ar = conn.execute("SELECT * FROM affiliates WHERE code=? AND is_active=1",(aff_code,)).fetchone()
            if ar and ar['user_id'] != session['user_id']:
                valid_aff = aff_code

        if invoice_api:
            inv = invoice_api.create_invoice(create_invoice_request={
                "external_id": ext_id, "amount": total,
                "payer_email": user['email'],
                "description": f"[{APP_NAME}] {post['caption'][:50]}",
                "success_redirect_url": f"{BASE_URL}/dasbor",
                "failure_redirect_url": f"{BASE_URL}/",
            })
            invoice_url = inv.invoice_url
        else:
            invoice_url = f"{BASE_URL}/demo_bayar/{ext_id}"

        room_uuid = str(uuid.uuid4())
        conn.execute("""INSERT INTO rekber_rooms(uuid,post_id,buyer_id,seller_id,status,price_deal,xendit_id,affiliate_code)
                        VALUES(?,?,?,?,'menunggu_pembayaran',?,?,?)""",
                     (room_uuid, post_id, session['user_id'], post['user_id'], (price - discount), ext_id, valid_aff))
        
        # Clear item from cart if exists
        conn.execute("DELETE FROM carts WHERE user_id=? AND post_id=?", (session['user_id'], post_id))
        
        conn.commit(); conn.close()
        audit('BAYAR_INIT', f'post={post_id} ext={ext_id}')
        return redirect(invoice_url)
    except Exception as ex:
        conn.execute("ROLLBACK")
        logging.error(f"Error creating Xendit invoice or rekber room: {ex}", exc_info=True)
        conn.close(); flash(f"Gagal buat invoice: {ex}","danger"); return redirect("/")

# ─── DEMO PAYMENT ───────────────────────────────────────────────────────────
@app.route('/demo_bayar/<ext_id>')
@login_required
def demo_bayar(ext_id):
    conn = get_db()
    room = conn.execute("""SELECT r.*,p.caption as barang,p.price,u2.username as seller_name
                           FROM rekber_rooms r JOIN posts p ON r.post_id=p.id
                           JOIN users u2 ON r.seller_id=u2.id
                           WHERE r.xendit_id=? AND r.buyer_id=?""",(ext_id,session['user_id'])).fetchone()
    conn.close()
    if not room: flash('Transaksi tidak ditemukan.','danger'); return redirect('/')
    return render_template('demo_bayar.html', room=room, ext_id=ext_id)

@app.route('/demo_bayar/<ext_id>/proses', methods=['POST'])
@login_required
def demo_proses(ext_id):
    metode = request.form.get('metode','Transfer Bank')
    conn   = get_db()
    room   = conn.execute("SELECT * FROM rekber_rooms WHERE xendit_id=? AND buyer_id=?",
                          (ext_id, session['user_id'])).fetchone()
    if not room or room['status']!='menunggu_pembayaran':
        conn.close(); flash('Transaksi tidak valid.','warning'); return redirect('/dasbor')

    conn.execute("UPDATE rekber_rooms SET status='dibayar',payment_method=?,updated_at=CURRENT_TIMESTAMP WHERE xendit_id=?",
                 (metode, ext_id))
    conn.commit()
    rid = room['id']
    r_uuid = room['uuid']
    conn.close()
    notif(room['seller_id'],'💰 Pembayaran Masuk!','Pesanan dibayar! Segera kirim barang dalam 1×24 jam.',f'/ruang/{r_uuid}','success')
    sys_msg(rid, f'🛡️ SISTEM: Pembayaran via {metode} dikonfirmasi. Dana aman di Socrow. Penjual harap kirim secepatnya.')
    audit('BAYAR_DEMO', f'room={rid} metode={metode}')
    flash('✅ Pembayaran berhasil! Dana disimpan aman oleh Socrow.','success')
    return redirect(f'/ruang/{r_uuid}')

# ─── WEBHOOK XENDIT ─────────────────────────────────────────────────────────
@app.route('/xendit_webhook', methods=['POST'])
def xendit_webhook():
    if not X_CALLBACK_TOKEN:
        return jsonify({"status":"disabled"}), 503
    cb_token = request.headers.get('x-callback-token')
    if cb_token != X_CALLBACK_TOKEN:
        logging.warning(f"Unauthorized webhook attempt from IP {request.remote_addr}")
        return jsonify({"status":"unauthorized"}), 401

    data = request.json or {}
    if data.get('status') in ['PAID','SETTLED']:
        # Webhook Integrity Verification (Simulated for Demo)
        # In production, check X-CALLBACK-TOKEN or HMAC signature
        ext_id = data.get('external_id','')
        conn   = get_db()
        # Use IMMEDIATE transaction for webhook updates to prevent race conditions
        conn.execute("BEGIN IMMEDIATE")
        try:
            room = conn.execute("SELECT * FROM rekber_rooms WHERE xendit_id=?",(ext_id,)).fetchone()
            if room and room['status']=='menunggu_pembayaran':
                conn.execute("UPDATE rekber_rooms SET status='dibayar',payment_method=?,updated_at=CURRENT_TIMESTAMP WHERE xendit_id=?",
                             (data.get('payment_channel','Xendit'), ext_id))
                conn.commit()
                notif(room['seller_id'],'💰 Pembayaran Masuk!','Pesanan dibayar!',f'/ruang/{room["uuid"]}','success')
                sys_msg(room['id'],'🛡️ SISTEM: Pembayaran dikonfirmasi Payment Gateway. Dana aman di Socrow.')
            else:
                conn.execute("ROLLBACK")
        except Exception as e:
            conn.execute("ROLLBACK")
            logging.error(f"Webhook processing failed: {e}")
        conn.close()
    return jsonify({"status":"ok"}),200

# ─── AKSI REKBER ─────────────────────────────────────────────────────────────
@app.route('/aksi_rekber/<target>/<aksi>', methods=['POST'])
@login_required
def aksi_rekber(target, aksi):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        r = conn.execute("""SELECT r.*,p.price,p.user_id as s_id,p.product_kind,p.digital_file
                            FROM rekber_rooms r JOIN posts p ON r.post_id=p.id WHERE r.id=?""",(target,)).fetchone()
    else:
        r = conn.execute("""SELECT r.*,p.price,p.user_id as s_id,p.product_kind,p.digital_file
                            FROM rekber_rooms r JOIN posts p ON r.post_id=p.id WHERE r.uuid=?""",(target,)).fetchone()
                            
    if not r: conn.close(); abort(404)
    room_id = r['id']

    if aksi == 'barang_diterima':
        if r['buyer_id'] != session['user_id']: conn.close(); abort(403)
        if r['status'] not in ['dibayar', 'dikirim', 'sampai']:
            conn.close()
            flash('Status tidak sesuai.','warning')
            return redirect(f'/ruang/{target}')

        r_info, bersih = _internal_complete_transaction(room_id, conn)

        sys_msg(room_id,'✅ SISTEM: Pembeli konfirmasi barang diterima. Dana dikirim ke penjual. Terima kasih!')
        audit('SELESAI', f'room={room_id}')
        conn.commit(); conn.close()
        flash('Transaksi selesai! Terima kasih sudah belanja di Socrow.','success')
        return redirect(f'/ruang/{target}')

    elif aksi == 'input_resi':
        if r['seller_id'] != session['user_id']: conn.close(); abort(403)
        if r['status'] != 'dibayar':
            conn.close()
            flash('Status tidak sesuai untuk input resi.','warning')
            return redirect(f'/ruang/{target}')
        
        resi    = request.form.get('resi_number','').strip()
        courier = request.form.get('courier_name','').strip()
        if not resi: conn.close(); flash('Nomor resi wajib diisi.','danger'); return redirect(f'/ruang/{target}')
        conn.execute("UPDATE rekber_rooms SET resi_number=?,courier_name=?,status='dikirim',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (resi, courier, room_id))
        conn.execute("INSERT INTO shipment_tracking(room_id,courier,resi,status) VALUES(?,?,?,'in_transit')",
                     (room_id, courier, resi))
        notif(r['buyer_id'],'📦 Barang Dikirim!',f'Penjual kirim via {courier}. Resi: {resi}',f'/ruang/{target}','info')
        sys_msg(room_id, f'📦 SISTEM: Penjual input resi pengiriman. Kurir: {courier} | No. Resi: {resi}')
        flash('Resi berhasil diinput!','success')

    conn.commit(); conn.close()
    return redirect(f'/ruang/{target}')

# ─── RUANG CHAT ──────────────────────────────────────────────────────────────
@app.route('/ruang/<target>')
@login_required
def ruang_chat(target):
    conn = get_db()
    # Check if target is UUID or ID (for backward compatibility)
    if len(str(target)) > 30:
        room = conn.execute("""SELECT r.*,p.caption as barang,p.price,p.media_url,p.product_kind,p.digital_file,
                                      u1.username as buyer_name,u2.username as seller_name
                               FROM rekber_rooms r JOIN posts p ON r.post_id=p.id
                               JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                               WHERE r.uuid=?""",(target,)).fetchone()
    else:
        room = conn.execute("""SELECT r.*,p.caption as barang,p.price,p.media_url,p.product_kind,p.digital_file,
                                      u1.username as buyer_name,u2.username as seller_name
                               FROM rekber_rooms r JOIN posts p ON r.post_id=p.id
                               JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                               WHERE r.id=?""",(target,)).fetchone()
                               
    if not room: conn.close(); abort(404)
    if session['user_id'] not in [room['buyer_id'],room['seller_id']] and session.get('email')!=ADMIN_EMAIL:
        conn.close(); abort(403)

    room_id = room['id']
    msgs  = conn.execute("""SELECT m.*,u.username as sender_name FROM messages m
                            LEFT JOIN users u ON m.sender_id=u.id
                            WHERE m.room_id=? ORDER BY m.id ASC""",(room_id,)).fetchall()
    dispute = conn.execute("SELECT * FROM disputes WHERE room_id=?",(room_id,)).fetchone()
    rating  = conn.execute("SELECT * FROM ratings WHERE room_id=?",(room_id,)).fetchone()
    conn.close()
    return render_template('ruang_rekber.html', room=room, pesan=msgs,
                           dispute=dispute, rating=rating,
                           user_id=session['user_id'])

@app.route('/kirim_pesan/<target>', methods=['POST'])
@login_required
def kirim_pesan(target):
    teks = request.form.get('teks_pesan','').strip()[:1000]
    conn = get_db()
    
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("SELECT * FROM rekber_rooms WHERE id=?",(target,)).fetchone()
    else:
        room = conn.execute("SELECT * FROM rekber_rooms WHERE uuid=?",(target,)).fetchone()
        
    if not room: conn.close(); abort(404)
    room_id = room['id']
    
    if not teks: return redirect(f'/ruang/{target}')
    
    if session['user_id'] in [room['buyer_id'],room['seller_id']]:
        conn.execute("INSERT INTO messages(room_id,sender_id,message_text) VALUES(?,?,?)",
                     (room_id,session['user_id'],teks))
        conn.commit()
        # Broadcast real-time
        socketio.emit('new_message', {
            'sender_id': session['user_id'],
            'sender_name': session['username'],
            'message_text': teks,
            'message_type': 'text',
            'created_at': datetime.now().strftime('%H:%M')
        }, room=f"room_{room_id}")
    conn.close()
    return redirect(f'/ruang/{target}')

# ─── STORIES ────────────────────────────────────────────────────────────────
@app.route('/story/tambah', methods=['POST'])
@login_required
def tambah_story():
    f = request.files.get('story_file')
    if f and f.filename and allowed_file(f):
        ext = f.filename.rsplit('.',1)[1].lower()
        fn = f"story_{session['user_id']}_{random.randint(1000,9999)}.{ext}"
        fpath = os.path.join(UPLOAD_FOLDER, fn)
        f.save(fpath)
        if ext != 'mp4': optimize_image(fpath)
        
        expires = datetime.now() + timedelta(hours=24)
        conn = get_db()
        conn.execute("INSERT INTO stories(user_id, media_url, expires_at) VALUES(?,?,?)",
                     (session['user_id'], fn, expires))
        conn.commit(); conn.close()
        flash('Cerita berhasil dibagikan!','success')
    return redirect('/')

# ─── WISHLIST ───────────────────────────────────────────────────────────────
@app.route('/wishlist')
@login_required
def wishlist_page():
    conn = get_db()
    posts_raw = conn.execute('''SELECT p.*, u.username, u.kyc_status, u.store_name, u.rating_avg
                                FROM wishlists w JOIN posts p ON w.post_id=p.id
                                JOIN users u ON p.user_id=u.id
                                WHERE w.user_id=? AND p.is_active=1
                                ORDER BY w.id DESC''', (session['user_id'],)).fetchall()
    posts = []
    for p in posts_raw:
        p_dict = dict(p)
        p_dict['images'] = conn.execute("SELECT image_url FROM post_images WHERE post_id=?", (p['id'],)).fetchall()
        posts.append(p_dict)
    conn.close()
    return render_template('wishlist.html', posts=posts)

@app.route('/wishlist/toggle/<target>', methods=['POST'])
@login_required
def toggle_wishlist(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        post = conn.execute("SELECT id FROM posts WHERE id=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT id FROM posts WHERE uuid=?", (target,)).fetchone()
        
    if not post: conn.close(); return jsonify({"status":"err"}), 404
    post_id = post['id']

    ex = conn.execute("SELECT id FROM wishlists WHERE user_id=? AND post_id=?", (session['user_id'], post_id)).fetchone()
    if ex:
        conn.execute("DELETE FROM wishlists WHERE id=?", (ex['id'],))
        status = 'removed'
    else:
        conn.execute("INSERT INTO wishlists(user_id, post_id) VALUES(?,?)", (session['user_id'], post_id))
        status = 'added'
    conn.commit(); conn.close()
    return jsonify({"status": status})

@app.route('/vouchers', methods=['GET','POST'])
@login_required
def manage_vouchers():
    conn = get_db()
    if request.method == 'POST':
        code   = request.form.get('code','').strip().upper()
        amount = float(request.form.get('amount',0))
        min_p  = float(request.form.get('min_purchase',0))
        if not code or amount <= 0:
            flash('Kode dan nominal diskon wajib diisi.','danger')
        else:
            try:
                conn.execute("INSERT INTO vouchers(seller_id, code, discount_amount, min_purchase) VALUES(?,?,?,?)",
                             (session['user_id'], code, amount, min_p))
                conn.commit()
                flash(f'Voucher {code} berhasil dibuat!','success')
            except sqlite3.IntegrityError:
                flash('Kode voucher sudah digunakan.','danger')
    
    vouchers = conn.execute("SELECT * FROM vouchers WHERE seller_id=? ORDER BY id DESC", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('vouchers.html', vouchers=vouchers)

@app.route('/voucher/delete/<int:vid>', methods=['POST'])
@login_required
def delete_voucher(vid):
    conn = get_db()
    conn.execute("DELETE FROM vouchers WHERE id=? AND seller_id=?", (vid, session['user_id']))
    conn.commit(); conn.close()
    flash('Voucher dihapus.','info')
    return redirect('/vouchers')

@app.route('/report', methods=['POST'])
@login_required
def submit_report():
    target_type = request.form.get('target_type')
    target_id   = request.form.get('target_id')
    reason      = request.form.get('reason', '').strip()
    
    if not target_type or not target_id or not reason:
        flash('Alasan laporan wajib diisi.', 'danger')
        return redirect(request.referrer or '/')
    
    conn = get_db()
    # Resolve target_id if it's UUID
    real_target_id = target_id
    if len(str(target_id)) > 30:
        if target_type == 'user':
            u = conn.execute("SELECT id FROM users WHERE uuid=?", (target_id,)).fetchone()
            if u: real_target_id = u['id']
        else:
            p = conn.execute("SELECT id FROM posts WHERE uuid=?", (target_id,)).fetchone()
            if p: real_target_id = p['id']

    conn.execute("INSERT INTO reports(reporter_id, target_type, target_id, reason) VALUES(?,?,?,?)",
                 (session['user_id'], target_type, real_target_id, reason))
    conn.commit(); conn.close()
    
    flash('Laporan kamu telah dikirim dan akan segera ditinjau oleh admin.', 'success')
    return redirect(request.referrer or '/')

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    conn = get_db()
    reports = conn.execute('''SELECT r.*, u.username as reporter 
                              FROM reports r JOIN users u ON r.reporter_id=u.id 
                              WHERE r.status='pending' ORDER BY r.id DESC''').fetchall()
    conn.close()
    return render_template('admin_reports.html', reports=reports)

@app.route('/admin/report/<int:rid>/<action>', methods=['POST'])
@login_required
@admin_required
def handle_report(rid, action):
    conn = get_db()
    report = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    if not report: conn.close(); abort(404)
    
    if action == 'resolve':
        conn.execute("UPDATE reports SET status='reviewed' WHERE id=?", (rid,))
    elif action == 'ban' and report['target_type'] == 'user':
        conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (report['target_id'],))
        conn.execute("UPDATE reports SET status='action_taken' WHERE id=?", (rid,))
    elif action == 'delete' and report['target_type'] == 'post':
        conn.execute("UPDATE posts SET is_active=0 WHERE id=?", (report['target_id'],))
        conn.execute("UPDATE reports SET status='action_taken' WHERE id=?", (rid,))
        
    conn.commit(); conn.close()
    flash('Laporan telah diproses.', 'success')
    return redirect('/admin/reports')

# ─── DIRECT MESSAGING ────────────────────────────────────────────────────────
@app.route('/dm')
@login_required
def dm_list():
    conn = get_db()
    # List of rooms where user is participant
    rooms = conn.execute("""SELECT r.*, 
                                   u1.username as u1_name, u2.username as u2_name
                            FROM chat_rooms r
                            JOIN users u1 ON r.user1_id=u1.id
                            JOIN users u2 ON r.user2_id=u2.id
                            WHERE r.user1_id=? OR r.user2_id=?
                            ORDER BY r.updated_at DESC""", (session['user_id'], session['user_id'])).fetchall()
    conn.close()
    return render_template('dm_list.html', rooms=rooms)

@app.route('/dm/<target>')
@login_required
def dm_room(target):
    conn = get_db()
    
    # Target can be integer (UID) or UUID
    if len(str(target)) > 30:
        room = conn.execute("SELECT * FROM chat_rooms WHERE uuid=?", (target,)).fetchone()
        if not room: conn.close(); abort(404)
        if session['user_id'] not in [room['user1_id'], room['user2_id']]: conn.close(); abort(403)
        other_id = room['user2_id'] if session['user_id']==room['user1_id'] else room['user1_id']
    else:
        uid = int(target)
        if uid == session['user_id']: return redirect('/dm')
        u1, u2 = sorted([session['user_id'], uid])
        room = conn.execute("SELECT * FROM chat_rooms WHERE user1_id=? AND user2_id=?", (u1, u2)).fetchone()
        if not room:
            conn.execute("INSERT INTO chat_rooms(uuid, user1_id, user2_id) VALUES(?,?,?)", (str(uuid.uuid4()), u1, u2))
            conn.commit()
            room = conn.execute("SELECT * FROM chat_rooms WHERE user1_id=? AND user2_id=?", (u1, u2)).fetchone()
        other_id = uid

    room_id = room['id']
    messages = conn.execute("""SELECT m.*, u.username as sender_name FROM chat_messages m
                               JOIN users u ON m.sender_id=u.id
                               WHERE m.room_id=? ORDER BY m.id ASC""", (room_id,)).fetchall()
    
    # Mark messages as read
    conn.execute("UPDATE chat_messages SET is_read=1 WHERE room_id=? AND sender_id=?", (room_id, other_id))
    conn.commit()
    
    # Notify other user via Socket.IO
    socketio.emit('messages_read', {'room_id': room_id, 'reader_id': session['user_id']}, room=f"dm_{room_id}")
    
    other_user = conn.execute("SELECT * FROM users WHERE id=?", (other_id,)).fetchone()
    conn.close()
    return render_template('dm_room.html', room=room, messages=messages, other_user=other_user)

@app.route('/dm/send/<target>', methods=['POST'])
@login_required
def dm_send(target):
    teks = request.form.get('teks','').strip()[:1000]
    media = request.files.get('chat_file')
    
    if not teks and not media: return jsonify({"status":"err"}), 400
    
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("SELECT * FROM chat_rooms WHERE id=?", (target,)).fetchone()
    else:
        room = conn.execute("SELECT * FROM chat_rooms WHERE uuid=?", (target,)).fetchone()
        
    if not room or session['user_id'] not in [room['user1_id'], room['user2_id']]:
        conn.close(); abort(403)
    
    room_id = room['id']
    filename = None
    m_type = 'text'
    if media and media.filename and allowed_file(media):
        ext = media.filename.rsplit('.',1)[1].lower()
        filename = f"chat_{room_id}_{session['user_id']}_{random.randint(1000,9999)}.{ext}"
        media.save(os.path.join(UPLOAD_FOLDER, filename))
        m_type = 'image'
        if not teks: teks = '🖼️ Gambar'

    conn.execute("INSERT INTO chat_messages(room_id, sender_id, message_text, file_url, message_type) VALUES(?,?,?,?,?)",
                 (room_id, session['user_id'], teks, filename, m_type))
    conn.execute("UPDATE chat_rooms SET last_message=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (teks, room_id))
    conn.commit()
    
    # Socket.IO Broadcast
    socketio.emit('new_dm', {
        'room_id': room_id,
        'sender_id': session['user_id'],
        'sender_name': session['username'],
        'message': teks,
        'file_url': filename,
        'message_type': m_type,
        'created_at': datetime.now().strftime('%H:%M')
    }, room=f"dm_{room_id}")
    
    # Notify other user
    other_id = room['user2_id'] if session['user_id']==room['user1_id'] else room['user1_id']
    notif(other_id, f'💬 Pesan dari {session["username"]}', teks, f'/dm/{session["user_uuid"]}', 'info')
    
    conn.close()
    return jsonify({"status":"ok"})

# ─── SOCKET.IO EVENTS ────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect(auth=None):
    if 'user_id' in session:
        try:
            conn = get_db()
            conn.execute("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=?", (session['user_id'],))
            conn.commit(); conn.close()
            join_room(f"user_{session['user_id']}")
            logging.info(f"User {session['user_id']} connected.")
        except Exception as e:
            logging.error(f"Error in on_connect: {e}")

@socketio.on('join_dm')
def on_join_dm(data):
    target = data.get('room_id')
    if not target: return
    
    conn = get_db()
    if str(target).isdigit():
        room = conn.execute("SELECT id FROM chat_rooms WHERE id=?", (target,)).fetchone()
    else:
        room = conn.execute("SELECT id FROM chat_rooms WHERE uuid=?", (target,)).fetchone()
    conn.close()
    
    if room:
        join_room(f"dm_{room['id']}")

@socketio.on('join')
def on_join(data):
    # This can be for rekber rooms or user notification rooms
    target = data.get('room_id')
    uid = data.get('user_id')
    
    if uid:
        join_room(f"user_{uid}")
        logging.info(f"User {uid} joined notification room.")
        
    if target:
        conn = get_db()
        if str(target).isdigit():
            room = conn.execute("SELECT id FROM rekber_rooms WHERE id=?", (target,)).fetchone()
        else:
            room = conn.execute("SELECT id FROM rekber_rooms WHERE uuid=?", (target,)).fetchone()
        conn.close()
        
        if room:
            join_room(f"room_{room['id']}")
            logging.info(f"Joined rekber room {room['id']}")

@socketio.on('typing')
def on_typing(data):
    target = data.get('room_id')
    if not target: return
    
    conn = get_db()
    # Try chat_rooms first then rekber_rooms
    room = None
    prefix = "dm_"
    if str(target).isdigit():
        room = conn.execute("SELECT id FROM chat_rooms WHERE id=?", (target,)).fetchone()
        if not room:
            room = conn.execute("SELECT id FROM rekber_rooms WHERE id=?", (target,)).fetchone()
            prefix = "room_"
    else:
        room = conn.execute("SELECT id FROM chat_rooms WHERE uuid=?", (target,)).fetchone()
        if not room:
            room = conn.execute("SELECT id FROM rekber_rooms WHERE uuid=?", (target,)).fetchone()
            prefix = "room_"
    conn.close()
    
    if room:
        emit('is_typing', {
            'username': session.get('username'),
            'user_id': session.get('user_id')
        }, room=f"{prefix}{room['id']}", include_self=False)

@socketio.on('stop_typing')
def on_stop_typing(data):
    target = data.get('room_id')
    if not target: return
    
    conn = get_db()
    room = None
    prefix = "dm_"
    if str(target).isdigit():
        room = conn.execute("SELECT id FROM chat_rooms WHERE id=?", (target,)).fetchone()
        if not room:
            room = conn.execute("SELECT id FROM rekber_rooms WHERE id=?", (target,)).fetchone()
            prefix = "room_"
    else:
        room = conn.execute("SELECT id FROM chat_rooms WHERE uuid=?", (target,)).fetchone()
        if not room:
            room = conn.execute("SELECT id FROM rekber_rooms WHERE uuid=?", (target,)).fetchone()
            prefix = "room_"
    conn.close()
    
    if room:
        emit('not_typing', {
            'user_id': session.get('user_id')
        }, room=f"{prefix}{room['id']}", include_self=False)

# ─── DOWNLOAD FILE DIGITAL ──────────────────────────────────────────────────
@app.route('/download_digital/<target>')
@login_required
def download_digital(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("""SELECT r.*,p.digital_file FROM rekber_rooms r
                               JOIN posts p ON r.post_id=p.id WHERE r.id=?""",(target,)).fetchone()
    else:
        room = conn.execute("""SELECT r.*,p.digital_file FROM rekber_rooms r
                               JOIN posts p ON r.post_id=p.id WHERE r.uuid=?""",(target,)).fetchone()
                               
    if not room or room['buyer_id']!=session['user_id'] or room['status']!='selesai':
        conn.close(); abort(403)
    fn = room['digital_file']
    conn.close()
    if not fn: abort(404)
    return send_from_directory(os.path.join(UPLOAD_FOLDER,'digital'), fn, as_attachment=True)

# ─── DISPUTE / MEDIASI ───────────────────────────────────────────────────────
@app.route('/dispute/<target>', methods=['GET','POST'])
@login_required
def dispute(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("SELECT * FROM rekber_rooms WHERE id=?",(target,)).fetchone()
    else:
        room = conn.execute("SELECT * FROM rekber_rooms WHERE uuid=?",(target,)).fetchone()
        
    if not room: conn.close(); abort(404)
    room_id = room['id']
    
    if session['user_id'] not in [room['buyer_id'],room['seller_id']]: conn.close(); abort(403)
    if room['status'] not in ['dibayar','dikirim','sampai']: conn.close(); flash('Tidak bisa komplain di status ini.','warning'); return redirect(f'/ruang/{target}')

    existing = conn.execute("SELECT * FROM disputes WHERE room_id=?",(room_id,)).fetchone()
    if existing: conn.close(); return redirect(f'/dispute/detail/{existing["id"]}')

    if request.method == 'POST':
        reason = request.form.get('reason','')
        detail = request.form.get('detail','').strip()
        if not reason: conn.close(); flash('Pilih alasan komplain.','danger'); return render_template('dispute_form.html',room=room)

        deadline = datetime.now() + timedelta(hours=DISPUTE_HOURS)
        conn.execute("""INSERT INTO disputes(room_id,opened_by,reason,detail,status,deadline)
                        VALUES(?,?,?,?,'open',?)""",
                     (room_id, session['user_id'], reason, detail, deadline))
        conn.execute("UPDATE rekber_rooms SET status='komplain',updated_at=CURRENT_TIMESTAMP WHERE id=?",(room_id,))

        # Upload bukti awal
        disp_id = conn.execute("SELECT id FROM disputes WHERE room_id=?",(room_id,)).fetchone()['id']
        for f in request.files.getlist('evidence'):
            if f and f.filename and allowed_file(f):
                ext = f.filename.rsplit('.',1)[1].lower()
                fn  = f"ev_{disp_id}_{random.randint(1000,9999)}.{ext}"
                f.save(os.path.join(UPLOAD_FOLDER,'evidence',fn))
                ftype = 'video' if ext=='mp4' else ('pdf' if ext=='pdf' else 'image')
                conn.execute("INSERT INTO dispute_evidence(dispute_id,uploaded_by,file_url,file_type,description) VALUES(?,?,?,?,?)",
                             (disp_id, session['user_id'], fn, ftype, request.form.get('ev_desc','')))

        conn.commit()
        other_id = room['seller_id'] if session['user_id']==room['buyer_id'] else room['buyer_id']
        notif(other_id,'⚠️ Komplain Diajukan!',f'Pihak lain mengajukan komplain pada transaksi ini.',f'/dispute/detail/{disp_id}','danger')
        sys_msg(room_id, f'⚠️ SISTEM: Komplain diajukan dengan alasan: {reason}. Admin akan meninjau dalam {DISPUTE_HOURS} jam. Kedua pihak harap upload bukti.')
        audit('DISPUTE_OPEN', f'room={room_id} reason={reason}')
        flash('Komplain berhasil diajukan. Admin akan meninjau segera.','warning')
        return redirect(f'/dispute/detail/{disp_id}')

    conn.close()
    reasons = ['Barang tidak sesuai deskripsi','Barang tidak diterima','Barang rusak/cacat',
               'Penjual tidak responsif','File digital tidak berfungsi','Penipuan','Lainnya']
    return render_template('dispute_form.html', room=room, reasons=reasons)

@app.route('/dispute/detail/<int:disp_id>')
@login_required
def dispute_detail(disp_id):
    conn = get_db()
    d = conn.execute("""SELECT d.*,r.buyer_id,r.seller_id,r.price_deal,
                               u1.username as buyer_name,u2.username as seller_name,
                               p.caption as barang
                        FROM disputes d JOIN rekber_rooms r ON d.room_id=r.id
                        JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                        JOIN posts p ON r.post_id=p.id WHERE d.id=?""",(disp_id,)).fetchone()
    if not d: conn.close(); abort(404)
    if session['user_id'] not in [d['buyer_id'],d['seller_id']] and session.get('email')!=ADMIN_EMAIL:
        conn.close(); abort(403)
    evidences = conn.execute("SELECT e.*,u.username FROM dispute_evidence e JOIN users u ON e.uploaded_by=u.id WHERE e.dispute_id=? ORDER BY e.id",(disp_id,)).fetchall()
    conn.close()
    return render_template('dispute_detail.html', d=d, evidences=evidences)

@app.route('/dispute/upload_bukti/<int:disp_id>', methods=['POST'])
@login_required
def upload_bukti(disp_id):
    conn = get_db()
    d = conn.execute("SELECT d.*,r.buyer_id,r.seller_id FROM disputes d JOIN rekber_rooms r ON d.room_id=r.id WHERE d.id=?",(disp_id,)).fetchone()
    if not d or session['user_id'] not in [d['buyer_id'],d['seller_id']]: conn.close(); abort(403)
    if d['status'] != 'open': conn.close(); flash('Dispute sudah ditutup.','warning'); return redirect(f'/dispute/detail/{disp_id}')

    for f in request.files.getlist('evidence'):
        if f and f.filename and allowed_file(f):
            ext = f.filename.rsplit('.',1)[1].lower()
            fn  = f"ev_{disp_id}_{random.randint(1000,9999)}.{ext}"
            f.save(os.path.join(UPLOAD_FOLDER,'evidence',fn))
            ftype = 'video' if ext=='mp4' else ('pdf' if ext=='pdf' else 'image')
            conn.execute("INSERT INTO dispute_evidence(dispute_id,uploaded_by,file_url,file_type,description) VALUES(?,?,?,?,?)",
                         (disp_id, session['user_id'], fn, ftype, request.form.get('ev_desc','')))
    conn.commit(); conn.close()
    flash('Bukti berhasil diupload.','success')
    return redirect(f'/dispute/detail/{disp_id}')

@app.route('/admin/dispute/<int:disp_id>/verdict', methods=['POST'])
@login_required
@admin_required
def dispute_verdict(disp_id):
    verdict = request.form.get('verdict')          # 'buyer' / 'seller' / 'split'
    note    = request.form.get('verdict_note','').strip()
    if verdict not in ['buyer','seller','split']: abort(400)

    conn = get_db()
    d = conn.execute("""SELECT d.*,r.buyer_id,r.seller_id,r.price_deal
                        FROM disputes d JOIN rekber_rooms r ON d.room_id=r.id WHERE d.id=?""",(disp_id,)).fetchone()
    if not d or d['status']!='open': conn.close(); flash('Dispute tidak valid.','danger'); return redirect('/admin/disputes')

    price = d['price_deal']
    if verdict == 'buyer':
        conn.execute("UPDATE users SET saldo=saldo+? WHERE id=?",(price, d['buyer_id']))
        msg = f'Komplain dimenangkan PEMBELI. Dana {rupiah(price)} dikembalikan ke pembeli.'
    elif verdict == 'seller':
        fee   = price * FEE_PERSEN
        bersih= price - fee
        conn.execute("UPDATE users SET saldo=saldo+? WHERE id=?",(bersih, d['seller_id']))
        conn.execute("UPDATE platform_stats SET total_revenue=total_revenue+? WHERE id=1",(fee,))
        msg = f'Komplain dimenangkan PENJUAL. Dana {rupiah(bersih)} dikirim ke penjual.'
    else:  # split
        half = price / 2
        conn.execute("UPDATE users SET saldo=saldo+? WHERE id=?",(half, d['buyer_id']))
        conn.execute("UPDATE users SET saldo=saldo+? WHERE id=?",(half, d['seller_id']))
        msg = f'Dana dibagi 50/50. Pembeli dan penjual masing-masing mendapat {rupiah(half)}.'

    conn.execute("UPDATE disputes SET status='resolved',verdict=?,verdict_note=?,resolved_by=?,resolved_at=CURRENT_TIMESTAMP WHERE id=?",
                 (verdict, note, session['user_id'], disp_id))
    conn.execute("UPDATE rekber_rooms SET status='selesai',updated_at=CURRENT_TIMESTAMP WHERE id=?",(d['room_id'],))
    conn.commit()
    notif(d['buyer_id'],'⚖️ Keputusan Dispute',msg,f'/dispute/detail/{disp_id}','info')
    notif(d['seller_id'],'⚖️ Keputusan Dispute',msg,f'/dispute/detail/{disp_id}','info')
    sys_msg(d['room_id'], f'⚖️ ADMIN: {msg} Catatan: {note or "-"}')
    audit('VERDICT', f'dispute={disp_id} verdict={verdict}')
    conn.close()
    flash('Keputusan berhasil disimpan dan dana sudah disalurkan.','success')
    return redirect('/admin/disputes')

# ─── RATING ─────────────────────────────────────────────────────────────────
@app.route('/rating/<target>', methods=['POST'])
@login_required
def beri_rating(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("SELECT * FROM rekber_rooms WHERE id=? AND status='selesai'",(target,)).fetchone()
    else:
        room = conn.execute("SELECT * FROM rekber_rooms WHERE uuid=? AND status='selesai'",(target,)).fetchone()
        
    if not room or room['buyer_id']!=session['user_id']: conn.close(); abort(403)
    room_id = room['id']

    existing = conn.execute("SELECT id FROM ratings WHERE room_id=?",(room_id,)).fetchone()
    if existing: conn.close(); flash('Sudah pernah memberi rating.','warning'); return redirect(f'/ruang/{target}')

    score = int(request.form.get('score',5))
    text  = request.form.get('review_text','').strip()[:500]
    conn.execute("INSERT INTO ratings(room_id,reviewer_id,reviewed_id,score,review_text) VALUES(?,?,?,?,?)",
                 (room_id, session['user_id'], room['seller_id'], score, text))
    # Update rata-rata
    avg = conn.execute("SELECT AVG(score),COUNT(*) FROM ratings WHERE reviewed_id=?",(room['seller_id'],)).fetchone()
    conn.execute("UPDATE users SET rating_avg=?,rating_count=? WHERE id=?",(avg[0],avg[1],room['seller_id']))
    conn.commit(); conn.close()
    flash('Rating berhasil dikirim. Terima kasih! ⭐','success')
    return redirect(f'/ruang/{target}')

# ─── WITHDRAWAL ──────────────────────────────────────────────────────────────
@app.route('/withdraw', methods=['GET','POST'])
@login_required
@limiter.limit("2 per hour")
def withdraw():
    conn = get_db()
    # Pessimistic Locking: BEGIN IMMEDIATE locks the database for writes
    conn.execute("BEGIN IMMEDIATE")
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
        if not user:
            conn.close()
            flash('Pengguna tidak ditemukan.','danger')
            return redirect('/logout')
        
        history = conn.execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20",(session['user_id'],)).fetchall()

        if request.method == 'POST':
            source  = request.form.get('source','saldo')  # 'saldo' or 'afiliasi'
            try:
                amount = float(request.form.get('amount',0))
            except (ValueError, TypeError):
                amount = 0

            bal = float(user['saldo']) if source=='saldo' else float(user['saldo_afiliasi'])
            min_wd = WITHDRAW_MIN if source=='saldo' else AFILIASI_MIN

            if amount < min_wd:
                flash(f'Minimal penarikan {rupiah(min_wd)}','danger')
            elif amount > bal:
                flash('Saldo tidak mencukupi.','danger')
            elif not user['bank_account']:
                flash('Lengkapi data bank di halaman akun terlebih dahulu.','warning')
                conn.close(); return redirect('/akun')
            else:
                net = amount - WITHDRAW_FEE
                if net < 0: net = 0
                
                # Update balance first (Debit)
                field = 'saldo' if source=='saldo' else 'saldo_afiliasi'
                conn.execute(f"UPDATE users SET {field}={field}-? WHERE id=?", (amount, session['user_id']))
                
                # Record withdrawal request
                conn.execute("""INSERT INTO withdrawals(user_id,amount,fee,net_amount,bank_name,bank_account,account_name,source,status)
                                VALUES(?,?,?,?,?,?,?,?,'pending')""",
                             (session['user_id'], amount, WITHDRAW_FEE, net,
                              user['bank_name'], user['bank_account'], user['kyc_name'] or user['username'], source))
                
                conn.commit()
                audit('WITHDRAW_REQUEST', f'amount={amount} source={source}')
                flash(f'Permintaan penarikan {rupiah(net)} berhasil diajukan! Diproses 1-2 hari kerja.','success')
                conn.close()
                return redirect('/withdraw')
        
        conn.close()
        return render_template('withdraw.html', user=user, history=history,
                               withdraw_fee=WITHDRAW_FEE, withdraw_min=WITHDRAW_MIN,
                               afiliasi_min=AFILIASI_MIN)
    except Exception as e:
        if conn:
            conn.execute("ROLLBACK")
            conn.close()
        logging.error(f"Withdrawal transaction failed: {e}", exc_info=True)
        flash('Terjadi kesalahan sistem saat memproses penarikan.','danger')
        return redirect('/withdraw')

# ─── AFILIASI ────────────────────────────────────────────────────────────────
@app.route('/afiliasi')
@login_required
def afiliasi():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    aff  = conn.execute("SELECT * FROM affiliates WHERE user_id=?",(session['user_id'],)).fetchone()
    logs = conn.execute("""SELECT al.*,p.caption as barang FROM affiliate_logs al
                           JOIN rekber_rooms r ON al.room_id=r.id
                           JOIN posts p ON r.post_id=p.id
                           WHERE al.affiliate_id=? ORDER BY al.id DESC LIMIT 20""",(aff['id'],)).fetchall() if aff else []
    referred = conn.execute("SELECT username,created_at FROM users WHERE referred_by=? ORDER BY id DESC",(session['user_id'],)).fetchall()
    conn.close()
    return render_template('afiliasi.html', user=user, aff=aff, logs=logs,
                           referred=referred, base_url=BASE_URL,
                           fee_afiliasi=FEE_AFILIASI*100)

# ─── DASBOR ──────────────────────────────────────────────────────────────────
@app.route('/dasbor')
@login_required
def dasbor():
    conn  = get_db()
    rooms = conn.execute("""SELECT r.*,p.caption as barang,p.media_url,p.product_kind,
                                   u1.username as buyer_name,u2.username as seller_name
                            FROM rekber_rooms r JOIN posts p ON r.post_id=p.id
                            JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                            WHERE r.buyer_id=? OR r.seller_id=?
                            ORDER BY r.id DESC""",(session['user_id'],session['user_id'])).fetchall()
    stats = {
        'total': len(rooms),
        'selesai': sum(1 for r in rooms if r['status']=='selesai'),
        'aktif': sum(1 for r in rooms if r['status'] in ['dibayar','dikirim']),
        'komplain': sum(1 for r in rooms if r['status']=='komplain'),
    }

    # Chart Data (Last 7 Days Sales)
    income_data = conn.execute("""
        SELECT date(updated_at) as d, SUM(price_deal) as total 
        FROM rekber_rooms 
        WHERE seller_id=? AND status='selesai' 
        AND updated_at >= date('now', '-7 days')
        GROUP BY d ORDER BY d ASC
    """, (session['user_id'],)).fetchall()
    
    chart_labels = [row['d'] for row in income_data]
    chart_values = [row['total'] for row in income_data]

    conn.close()
    return render_template('dasbor.html', rooms=rooms, stats=stats, 
                           chart_labels=chart_labels, chart_values=chart_values)

# ─── NOTIFIKASI ──────────────────────────────────────────────────────────────
@app.route('/notifikasi')
@login_required
def notifikasi():
    conn   = get_db()
    notifs = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",(session['user_id'],)).fetchall()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(session['user_id'],))
    conn.commit(); conn.close()
    return render_template('notifikasi.html', notifs=notifs)

@app.route('/toggle_data_saver', methods=['POST'])
def toggle_data_saver():
    session['data_saver'] = not session.get('data_saver', False)
    return jsonify({"status": "ok", "data_saver": session['data_saver']})

# ─── MULTI LANGUAGE ─────────────────────────────────────────────────────────
@app.route('/set_lang/<lang>')
def set_lang(lang):
    if lang in ['id', 'en']:
        session['lang'] = lang
    return redirect(request.referrer or '/')

@app.context_processor
def inject_lang():
    lang = session.get('lang', 'id')
    cart_count = 0
    user_avatar = None
    if 'user_id' in session:
        conn = get_db()
        res = conn.execute("SELECT SUM(quantity) FROM carts WHERE user_id=?", (session['user_id'],)).fetchone()
        cart_count = res[0] if res and res[0] else 0
        
        u = conn.execute("SELECT avatar_url FROM users WHERE id=?", (session['user_id'],)).fetchone()
        user_avatar = u['avatar_url'] if u else None
        conn.close()
    
    texts = {
        'id': {
            'home': 'Beranda', 'store': 'Toko', 'post': 'Posting', 'messages': 'Pesan',
            'rekber': 'Rekber', 'profile': 'Profil', 'login': 'Masuk', 'register': 'Daftar',
            'welcome': 'Selamat datang di Socrow'
        },
        'en': {
            'home': 'Home', 'store': 'Store', 'post': 'Post', 'messages': 'Messages',
            'rekber': 'Escrow', 'profile': 'Profile', 'login': 'Login', 'register': 'Register',
            'welcome': 'Welcome to Socrow'
        }
    }
    return {'t': texts[lang], 'cur_lang': lang, 'admin_email': ADMIN_EMAIL, 'cart_count': cart_count, 'user_avatar': user_avatar}

# ─── USER DASHBOARD ──────────────────────────────────────────────────────────
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    
    # Seller stats
    total_earned = conn.execute("SELECT SUM(price_deal) FROM rekber_rooms WHERE seller_id=? AND status='selesai'", (session['user_id'],)).fetchone()[0] or 0
    active_sales = conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE seller_id=? AND status IN ('dibayar','dikirim','sampai')", (session['user_id'],)).fetchone()[0]
    
    # Buyer stats
    total_spent = conn.execute("SELECT SUM(price_deal) FROM rekber_rooms WHERE buyer_id=? AND status='selesai'", (session['user_id'],)).fetchone()[0] or 0
    orders_arriving = conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE buyer_id=? AND status IN ('dikirim','sampai')", (session['user_id'],)).fetchone()[0]
    wishlist_count = conn.execute("SELECT COUNT(*) FROM wishlists WHERE user_id=?", (session['user_id'],)).fetchone()[0]
    
    # Recent Activities (simulasi)
    activities = conn.execute("""SELECT action, detail, created_at FROM audit_logs 
                                 WHERE user_id=? ORDER BY id DESC LIMIT 5""", (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('user_dashboard.html', user=user, 
                           seller_stats={'earned': total_earned, 'active': active_sales},
                           buyer_stats={'spent': total_spent, 'arriving': orders_arriving, 'wish': wishlist_count},
                           activities=activities)

# ─── PROFIL PUBLIK ───────────────────────────────────────────────────────────
@app.route('/user/<username>')
def user_profile(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=? AND is_banned=0",(username,)).fetchone()
    if not user: conn.close(); abort(404)
    
    # Social Posts (is_for_sale=0)
    social_posts = conn.execute("SELECT * FROM posts WHERE user_id=? AND is_for_sale=0 AND is_active=1 ORDER BY id DESC", (user['id'],)).fetchall()
    
    # Store Posts (is_for_sale=1)
    store_posts = conn.execute("SELECT * FROM posts WHERE user_id=? AND is_for_sale=1 AND is_active=1 ORDER BY id DESC", (user['id'],)).fetchall()
    
    # Rating & Review
    reviews = conn.execute("""SELECT r.*, u.username as reviewer FROM ratings r
                              JOIN users u ON r.reviewer_id=u.id
                              WHERE r.reviewed_id=? ORDER BY r.id DESC LIMIT 10""",(user['id'],)).fetchall()
    
    # Follow status
    is_following = False
    if 'user_id' in session:
        ex = conn.execute("SELECT id FROM follows WHERE follower_id=? AND following_id=?",
                          (session['user_id'], user['id'])).fetchone()
        is_following = True if ex else False
        
    followers_count = conn.execute("SELECT COUNT(*) FROM follows WHERE following_id=?",(user['id'],)).fetchone()[0]
    following_count = conn.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?",(user['id'],)).fetchone()[0]
    total_likes = conn.execute("SELECT COUNT(*) FROM likes l JOIN posts p ON l.post_id=p.id WHERE p.user_id=?", (user['id'],)).fetchone()[0]
    
    conn.close()
    return render_template('user_profile.html', user=user, social_posts=social_posts, store_posts=store_posts,
                           reviews=reviews, is_following=is_following, followers=followers_count, following=following_count, total_likes=total_likes)

@app.route('/follow/<target>', methods=['POST'])
@login_required
def follow(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        u = conn.execute("SELECT id FROM users WHERE id=?", (target,)).fetchone()
    else:
        u = conn.execute("SELECT id FROM users WHERE uuid=?", (target,)).fetchone()
        
    if not u: conn.close(); return jsonify({"status":"err"}), 404
    uid = u['id']
    
    if uid == session['user_id']: conn.close(); return jsonify({"status":"err"}), 400
    
    ex = conn.execute("SELECT id FROM follows WHERE follower_id=? AND following_id=?",(session['user_id'],uid)).fetchone()
    if ex:
        conn.execute("DELETE FROM follows WHERE follower_id=? AND following_id=?",(session['user_id'],uid))
        followed = False
    else:
        conn.execute("INSERT INTO follows(follower_id,following_id) VALUES(?,?)",(session['user_id'],uid))
        followed = True
        notif(uid, '👤 Follower Baru!', f'{session["username"]} mulai mengikutimu!', f'/user/{session["username"]}', 'info')
    conn.commit(); conn.close()
    return jsonify({"followed":followed})

# ─── AKUN / PROFIL ───────────────────────────────────────────────────────────
@app.route('/keamanan')
@login_required
def keamanan():
    conn = get_db()
    logs = conn.execute("""SELECT * FROM audit_logs 
                           WHERE user_id=? AND (action LIKE 'LOGIN%' OR action LIKE 'WITHDRAW%')
                           ORDER BY id DESC LIMIT 20""", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('keamanan.html', logs=logs)

@app.route('/api/search_suggestions')
def search_suggestions():
    q = request.args.get('q', '').strip()
    if len(q) < 2: return jsonify([])
    
    conn = get_db()
    # Search users
    users = conn.execute("SELECT username, uuid FROM users WHERE username LIKE ? LIMIT 3", (f'%{q}%',)).fetchall()
    # Search hashtags from posts
    tags = conn.execute("SELECT DISTINCT caption FROM posts WHERE caption LIKE ? LIMIT 3", (f'%#{q}%',)).fetchall()
    conn.close()
    
    results = []
    for u in users:
        results.append({'type': 'user', 'text': u['username'], 'link': f'/user/{u["username"]}'})
    
    import re
    for t in tags:
        found = re.findall(r'#(\w+)', t['caption'])
        for f in found:
            if q.lower() in f.lower():
                results.append({'type': 'tag', 'text': f'#{f}', 'link': f'/explore?q=%23{f}'})
    
    return jsonify(results[:6])

@app.route('/akun', methods=['GET','POST'])
@login_required
def akun():
    conn = get_db()
    if request.method == 'POST':
        ft = request.form.get('form_type')
        if ft == 'finance':
            fk = request.files.get('file_ktp'); fs = request.files.get('file_selfie')
            if not fk or not fs: flash('Upload KTP dan Selfie.','danger')
            elif not (allowed_file(fk) and allowed_file(fs)): flash('Format file tidak didukung.','danger')
            else:
                nk = f"kyc_{session['user_id']}_{secure_filename(fk.filename)}"
                ns = f"kyc_{session['user_id']}_{secure_filename(fs.filename)}"
                fk.save(os.path.join(UPLOAD_FOLDER,nk)); fs.save(os.path.join(UPLOAD_FOLDER,ns))
                conn.execute("""UPDATE users SET store_name=?,kyc_name=?,bank_name=?,bank_account=?,
                                kyc_status='pending',file_ktp=?,file_selfie=? WHERE id=?""",
                             (request.form['store_name'],request.form['kyc_name'].upper(),
                              request.form['bank_name'],request.form['bank_account'],nk,ns,session['user_id']))
                conn.commit(); flash('Data KYC terkirim! Proses 1-2 hari kerja.','success')
        elif ft == 'password':
            old = request.form.get('old_password','')
            new = request.form.get('new_password','')
            uc  = conn.execute("SELECT password FROM users WHERE id=?",(session['user_id'],)).fetchone()
            
            # Check old password (Argon2 or PBKDF2)
            is_old_valid = False
            if uc['password'].startswith('$argon2'):
                try:
                    ph.verify(uc['password'], old)
                    is_old_valid = True
                except VerifyMismatchError: pass
            else:
                is_old_valid = check_password_hash(uc['password'], old)

            if not is_old_valid: flash('Password lama salah.','danger')
            elif not validate_password(new): flash('Password baru minimal 8 karakter.','danger')
            else:
                conn.execute("UPDATE users SET password=? WHERE id=?",(ph.hash(new),session['user_id']))
                conn.commit(); flash('Password berhasil diubah.','success')
        elif ft == 'profile':
            bio  = request.form.get('bio','').strip()[:200]
            site = request.form.get('website','').strip()[:100]
            
            # Avatar Upload
            avatar = request.files.get('avatar')
            avatar_fn = None
            if avatar and avatar.filename and allowed_file(avatar):
                avatar_fn = f"avatar_{session['user_id']}_{random.randint(1000,9999)}.{avatar.filename.rsplit('.',1)[1].lower()}"
                fpath = os.path.join(UPLOAD_FOLDER, avatar_fn)
                avatar.save(fpath)
                optimize_image(fpath, max_width=400)
                conn.execute("UPDATE users SET avatar_url=? WHERE id=?", (avatar_fn, session['user_id']))

            # Cover Upload
            cover = request.files.get('cover')
            cover_fn = None
            if cover and cover.filename and allowed_file(cover):
                cover_fn = f"cover_{session['user_id']}_{random.randint(1000,9999)}.{cover.filename.rsplit('.',1)[1].lower()}"
                fpath = os.path.join(UPLOAD_FOLDER, cover_fn)
                cover.save(fpath)
                optimize_image(fpath, max_width=1200)
                conn.execute("UPDATE users SET cover_url=? WHERE id=?", (cover_fn, session['user_id']))

            conn.execute("UPDATE users SET bio=?, website=? WHERE id=?", (bio, site, session['user_id']))
            conn.commit(); flash('Profil berhasil diperbarui.','success')

    user    = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    aff     = conn.execute("SELECT * FROM affiliates WHERE user_id=?",(session['user_id'],)).fetchone()
    p_rev   = conn.execute("SELECT total_revenue,total_transactions,total_users FROM platform_stats WHERE id=1").fetchone() \
              if session.get('email')==ADMIN_EMAIL else None
    platform_revenue = p_rev['total_revenue'] if p_rev else 0
    ratings = conn.execute("SELECT r.*,u.username as reviewer FROM ratings r JOIN users u ON r.reviewer_id=u.id WHERE r.reviewed_id=? ORDER BY r.id DESC LIMIT 5",(session['user_id'],)).fetchall()
    
    # Login Activity
    activities = conn.execute("SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 10", (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('akun.html', user=user, aff=aff, p_rev=p_rev, 
                           platform_revenue=platform_revenue, ratings=ratings, 
                           activities=activities, base_url=BASE_URL)

@app.route('/user/<username>/followers')
def followers_list(username):
    conn = get_db()
    user = conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
    if not user: conn.close(); abort(404)
    
    followers = conn.execute('''SELECT u.id, u.username, u.bio, u.avatar_url 
                                FROM follows f JOIN users u ON f.follower_id=u.id 
                                WHERE f.followed_id=?''', (user['id'],)).fetchall()
    conn.close()
    return render_template('follow_list.html', user=user, list=followers, title='Pengikut')

@app.route('/user/<username>/following')
def following_list(username):
    conn = get_db()
    user = conn.execute("SELECT id, username FROM users WHERE username=?", (username,)).fetchone()
    if not user: conn.close(); abort(404)
    
    following = conn.execute('''SELECT u.id, u.username, u.bio, u.avatar_url 
                                FROM follows f JOIN users u ON f.follower_id=u.id 
                                WHERE f.follower_id=?''', (user['id'],)).fetchall()
    conn.close()
    return render_template('follow_list.html', user=user, list=following, title='Mengikuti')

# ─── ADMIN ───────────────────────────────────────────────────────────────────
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    stats = conn.execute("SELECT * FROM platform_stats WHERE id=1").fetchone()
    if not stats:
        # Fallback if platform_stats is empty
        stats = {'total_revenue': 0, 'total_transactions': 0, 'total_users': 0}
    
    # Data untuk Chart (6 bulan terakhir simulasi)
    chart_data = {
        'labels': ['Okt', 'Nov', 'Des', 'Jan', 'Feb', 'Mar'],
        'revenue': [120000, 450000, 890000, 1200000, 2100000, stats['total_revenue']]
    }
    
    # Top 5 Affiliates
    top_aff = conn.execute("""SELECT u.username, a.total_referred, a.total_earned
                              FROM affiliates a JOIN users u ON a.user_id=u.id
                              ORDER BY a.total_earned DESC LIMIT 5""").fetchall()
    
    # Dispute vs Selesai
    txn_stats = {
        'selesai': conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE status='selesai'").fetchone()[0],
        'dispute': conn.execute("SELECT COUNT(*) FROM disputes").fetchone()[0],
        'pending': conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE status IN ('dibayar','dikirim')").fetchone()[0]
    }
    
    conn.close()
    return render_template('admin_dashboard.html', stats=stats, chart_data=chart_data, 
                           top_aff=top_aff, txn_stats=txn_stats)

@app.route('/admin/kyc')
@login_required
@admin_required
def admin_kyc():
    conn   = get_db()
    users  = conn.execute("SELECT * FROM users WHERE kyc_status='pending' ORDER BY id").fetchall()
    stats  = conn.execute("SELECT * FROM platform_stats WHERE id=1").fetchone()
    if not stats:
        stats = {'total_revenue': 0, 'total_transactions': 0, 'total_users': 0}
    tu     = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    txn    = conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE status='selesai'").fetchone()[0]
    conn.close()
    return render_template('admin_kyc.html', users=users, stats=stats, total_users=tu, total_txn=txn)


@app.route('/admin/verify/<int:uid>/<action>', methods=['POST'])
@login_required
@admin_required
def verify_user(uid, action):
    status = 'verified' if action=='approve' else 'rejected'
    conn   = get_db()
    conn.execute("UPDATE users SET kyc_status=? WHERE id=?",(status,uid))
    conn.commit(); conn.close()
    msg = 'KYC kamu disetujui! Sekarang bisa berjualan.' if action=='approve' else 'KYC ditolak. Silakan upload ulang dokumen.'
    notif(uid, ('✅ KYC Disetujui' if action=='approve' else '❌ KYC Ditolak'), msg, '/akun')
    audit('KYC_VERDICT', f'user={uid} action={action}')
    flash(f'User berhasil {"diverifikasi" if action=="approve" else "ditolak"}.','success')
    return redirect('/admin/kyc')

@app.route('/admin/disputes')
@login_required
@admin_required
def admin_disputes():
    conn = get_db()
    disputes = conn.execute("""SELECT d.*,r.price_deal,p.caption as barang,
                                      u1.username as buyer_name,u2.username as seller_name
                               FROM disputes d JOIN rekber_rooms r ON d.room_id=r.id
                               JOIN posts p ON r.post_id=p.id
                               JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                               ORDER BY d.status='open' DESC,d.id DESC""").fetchall()
    conn.close()
    return render_template('admin_disputes.html', disputes=disputes)

@app.route('/admin/withdrawals')
@login_required
@admin_required
def admin_withdrawals():
    conn = get_db()
    wds  = conn.execute("""SELECT w.*,u.username FROM withdrawals w JOIN users u ON w.user_id=u.id
                           ORDER BY w.status='pending' DESC,w.id DESC""").fetchall()
    conn.close()
    return render_template('admin_withdrawals.html', wds=wds)

@app.route('/admin/withdrawal/<int:wid>/<action>', methods=['POST'])
@login_required
@admin_required
def process_withdrawal(wid, action):
    note = request.form.get('admin_note','')
    conn = get_db()
    wd   = conn.execute("SELECT * FROM withdrawals WHERE id=?",(wid,)).fetchone()
    if not wd or wd['status']!='pending': conn.close(); flash('Tidak valid.','danger'); return redirect('/admin/withdrawals')

    if action == 'approve':
        conn.execute("UPDATE withdrawals SET status='approved',admin_note=?,processed_by=?,processed_at=CURRENT_TIMESTAMP WHERE id=?",
                     (note, session['user_id'], wid))
        notif(wd['user_id'],'✅ Penarikan Disetujui!',f'Penarikan {rupiah(wd["net_amount"])} sedang diproses ke rekeningmu.','/withdraw','success')
    else:
        # Kembalikan saldo
        if wd['source'] == 'afiliasi':
            conn.execute("UPDATE users SET saldo_afiliasi=saldo_afiliasi+? WHERE id=?",(wd['amount'],wd['user_id']))
        else:
            conn.execute("UPDATE users SET saldo=saldo+? WHERE id=?",(wd['amount'],wd['user_id']))
        
        conn.execute("UPDATE withdrawals SET status='rejected',admin_note=?,processed_by=?,processed_at=CURRENT_TIMESTAMP WHERE id=?",
                     (note, session['user_id'], wid))
        notif(wd['user_id'],'❌ Penarikan Ditolak',f'Penarikan ditolak. Alasan: {note or "-"}. Saldo dikembalikan.','/withdraw','danger')

    audit('WITHDRAWAL_VERDICT', f'wd={wid} action={action}')
    conn.commit(); conn.close()
    flash(f'Penarikan berhasil {"disetujui" if action=="approve" else "ditolak"}.','success')
    return redirect('/admin/withdrawals')

# ─── INVOICE GENERATOR ──────────────────────────────────────────────────────
@app.route('/invoice/<target>')
@login_required
def download_invoice(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        room = conn.execute("""SELECT r.*, p.caption, p.product_category,
                                      u1.username as buyer_name, u2.username as seller_name
                               FROM rekber_rooms r 
                               JOIN posts p ON r.post_id=p.id
                               JOIN users u1 ON r.buyer_id=u1.id
                               JOIN users u2 ON r.seller_id=u2.id
                               WHERE r.id=?""", (target,)).fetchone()
    else:
        room = conn.execute("""SELECT r.*, p.caption, p.product_category,
                                      u1.username as buyer_name, u2.username as seller_name
                               FROM rekber_rooms r 
                               JOIN posts p ON r.post_id=p.id
                               JOIN users u1 ON r.buyer_id=u1.id
                               JOIN users u2 ON r.seller_id=u2.id
                               WHERE r.uuid=?""", (target,)).fetchone()
    conn.close()
    
    if not room: abort(404)
    if session['user_id'] not in [room['buyer_id'], room['seller_id']]: abort(403)

    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_font("Helvetica", 'B', 24)
    pdf.set_text_color(108, 99, 255) # Socrow Accent
    pdf.cell(0, 20, "SOCROW INVOICE", ln=True, align='C')
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"ID Transaksi: {room['uuid']}", ln=True, align='C')
    pdf.ln(10)

    # Info Table
    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(0)
    pdf.set_fill_color(240, 240, 245)
    pdf.cell(95, 10, "Informasi Pembeli", 1, 0, 'L', True)
    pdf.cell(95, 10, "Informasi Penjual", 1, 1, 'L', True)
    
    pdf.set_font("Helvetica", size=10)
    pdf.cell(95, 10, f"Username: {room['buyer_name']}", 1, 0)
    pdf.cell(95, 10, f"Username: {room['seller_name']}", 1, 1)
    pdf.cell(95, 10, f"Tanggal: {room['created_at'][:10]}", 1, 0)
    pdf.cell(95, 10, f"Status: SELESAI", 1, 1)
    pdf.ln(10)

    # Details
    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(0, 10, "Detail Produk", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 10, f"Nama Produk: {room['caption'][:100]}...", border=1)
    pdf.cell(140, 10, "Harga Satuan", 1, 0)
    pdf.cell(50, 10, f"{rupiah(room['price_deal'])}", 1, 1)
    pdf.cell(140, 10, "Biaya Admin Rekber", 1, 0)
    pdf.cell(50, 10, "Rp 2.500", 1, 1)
    
    pdf.set_font("Helvetica", 'B', 14)
    pdf.set_fill_color(34, 211, 160) # Green
    pdf.set_text_color(255)
    pdf.cell(140, 15, "TOTAL PEMBAYARAN", 1, 0, 'L', True)
    pdf.cell(50, 15, f"{rupiah(room['price_deal'] + 2500)}", 1, 1, 'C', True)

    pdf.ln(20)
    pdf.set_text_color(150)
    pdf.set_font("Helvetica", 'I', 8)
    pdf.multi_cell(0, 5, "Ini adalah bukti pembayaran yang sah dari platform Socrow. Dana telah berhasil diteruskan kepada penjual melalui sistem rekening bersama kami.", align='C')

    # Output to browser
    response = make_response(pdf.output())
    response.headers.set('Content-Type', 'application/pdf')
    response.headers.set('Content-Disposition', 'attachment', filename=f"Invoice-Socrow-{room['uuid'][:8]}.pdf")
    return response

# ─── AUTO TRACKING SIMULATION ───────────────────────────────────────────────
@app.route('/admin/simulate_tracking')
@login_required
@admin_required
def simulate_tracking():
    conn = get_db()
    # Cari yang statusnya 'dikirim'
    rooms = conn.execute("SELECT * FROM rekber_rooms WHERE status='dikirim'").fetchall()
    count = 0
    for r in rooms:
        # Simulasi 50% kemungkinan barang sampai
        if random.random() > 0.5:
            conn.execute("UPDATE rekber_rooms SET status='sampai', updated_at=CURRENT_TIMESTAMP WHERE id=?", (r['id'],))
            conn.execute("UPDATE shipment_tracking SET status='delivered' WHERE room_id=?", (r['id'],))
            notif(r['buyer_id'], '📦 Barang Sampai!', f'Kurir melaporkan barang sudah sampai di tujuan.', f'/ruang/{r["uuid"]}', 'success')
            sys_msg(r['id'], '📦 SISTEM: Kurir melaporkan barang sudah diterima oleh pembeli. Transaksi akan otomatis selesai dalam 24 jam jika tidak ada komplain.')
            count += 1
    conn.commit(); conn.close()
    flash(f'Simulasi selesai. {count} paket berhasil di-update menjadi "Sampai".','info')
    return redirect('/admin/dashboard')

@app.route('/admin/auto_release')
@login_required
@admin_required
def auto_release_task():
    conn = get_db()
    # Cari yang 'sampai' tapi sudah lebih dari 24 jam (simulasi 1 jam saja biar cepat ditest)
    rooms = conn.execute("""SELECT * FROM rekber_rooms 
                            WHERE status='sampai' 
                            AND datetime(updated_at, '+1 hours') < datetime('now')""").fetchall()
    count = 0
    for r in rooms:
        _internal_complete_transaction(r['id'], conn)
        sys_msg(r['id'],'🤖 SISTEM: Transaksi diselesaikan otomatis oleh sistem (Auto-Release).')
        audit('AUTO_RELEASE', f'room={r["id"]}', 0)
        count += 1
    conn.commit(); conn.close()
    flash(f'Auto-release selesai. {count} transaksi berhasil diselesaikan otomatis.','success')
    return redirect('/admin/dashboard')

# ─── FINANCIAL LOGIC (ATOMIC) ────────────────────────────────────────────────
def _internal_complete_transaction(room_id, conn):
    # Using explicit locking for SQLite in high concurrency.
    conn.execute("BEGIN IMMEDIATE")
    try:
        r = conn.execute("""SELECT r.*,p.price,p.user_id as s_id,p.product_kind,p.digital_file
                            FROM rekber_rooms r JOIN posts p ON r.post_id=p.id WHERE r.id=?""",(room_id,)).fetchone()
        if not r or r['status'] == 'selesai': 
            return None, 0

        fee_plat = r['price'] * FEE_PERSEN
        fee_aff  = 0
        
        # Bayar afiliasi
        aff_user_id = None
        aff_id = None
        if r['affiliate_code']:
            aff = conn.execute("SELECT * FROM affiliates WHERE code=?",(r['affiliate_code'],)).fetchone()
            if aff:
                fee_aff  = r['price'] * FEE_AFILIASI
                aff_user_id = aff['user_id']
                aff_id = aff['id']
        
        bersih = r['price'] - fee_plat - fee_aff

        if fee_aff > 0 and aff_user_id:
            conn.execute("UPDATE users SET saldo_afiliasi=saldo_afiliasi+? WHERE id=?",(fee_aff, aff_user_id))
            conn.execute("UPDATE affiliates SET total_earned=total_earned+? WHERE id=?",(fee_aff, aff_id))
            conn.execute("INSERT INTO affiliate_logs(affiliate_id,room_id,transaction_amount,commission,status,paid_at) VALUES(?,?,?,?,'paid',CURRENT_TIMESTAMP)",
                         (aff_id, room_id, r['price'], fee_aff))
            notif(aff_user_id,'💸 Komisi Afiliasi!',f'Kamu dapat komisi {rupiah(fee_aff)} dari transaksi rekber!','/akun','success')

        conn.execute("UPDATE users SET saldo=saldo+?,total_sales=total_sales+1 WHERE id=?",(bersih, r['s_id']))
        conn.execute("UPDATE platform_stats SET total_revenue=total_revenue+?,total_transactions=total_transactions+1 WHERE id=1",(fee_plat,))
        conn.execute("UPDATE rekber_rooms SET status='selesai',updated_at=CURRENT_TIMESTAMP WHERE id=?",(room_id,))
        
        # Kirim file digital otomatis
        if r['product_kind']=='digital' and r['digital_file']:
            sys_msg(room_id, f'✅ SISTEM: Transaksi selesai! File digital tersedia di bawah chat.')
        
        notif(r['s_id'],'✅ Transaksi Selesai!',f'Dana {rupiah(bersih)} masuk ke saldomu!',f'/ruang/{r["uuid"]}','success')
        return r, bersih
    except Exception as e:
        conn.execute("ROLLBACK")
        logging.error(f"Transaction failed: {e}")
        raise e
@app.route('/komentar/<target>', methods=['POST'])
@login_required
def tambah_komentar(target):
    teks = request.form.get('komentar','').strip()[:500]
    conn = get_db()
    
    # Resolve target
    if str(target).isdigit():
        post = conn.execute("SELECT id FROM posts WHERE id=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT id FROM posts WHERE uuid=?", (target,)).fetchone()
        
    if not post: conn.close(); abort(404)
    post_id = post['id']

    if not teks: 
        if request.is_json or request.headers.get('Accept') == 'application/json':
            conn.close(); return jsonify({"error":"Komentar kosong"}), 400
        conn.close(); return redirect(f'/?q={target}')
    
    conn.execute("INSERT INTO comments(post_id, user_id, comment_text) VALUES(?,?,?)",
                 (post_id, session['user_id'], teks))
    comment_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    
    # Mention Detection (@username)
    process_mentions(teks, post_uuid=target, comment_id=comment_id)
    
    if request.is_json or request.headers.get('Accept') == 'application/json':
        return jsonify({"status":"ok","username":session['username'],"text":teks})
    
    return redirect(request.referrer or '/')

@app.route('/api/comments/<target>')
def api_comments(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        post = conn.execute("SELECT id FROM posts WHERE id=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT id FROM posts WHERE uuid=?", (target,)).fetchone()
        
    if not post: conn.close(); return jsonify([]), 404
    post_id = post['id']

    comments = conn.execute('''SELECT c.*, u.username FROM comments c 
                               JOIN users u ON c.user_id=u.id 
                               WHERE c.post_id=? ORDER BY c.id ASC''', (post_id,)).fetchall()
    conn.close()
    return jsonify([dict(c) for c in comments])

@app.route('/like/<target>', methods=['POST'])
@login_required
def like(target):
    conn = get_db()
    # Resolve target
    if str(target).isdigit():
        post = conn.execute("SELECT id FROM posts WHERE id=?", (target,)).fetchone()
    else:
        post = conn.execute("SELECT id FROM posts WHERE uuid=?", (target,)).fetchone()
        
    if not post: conn.close(); return jsonify({"status":"err"}), 404
    post_id = post['id']

    ex   = conn.execute("SELECT id FROM likes WHERE post_id=? AND user_id=?",(post_id,session['user_id'])).fetchone()
    if ex: conn.execute("DELETE FROM likes WHERE post_id=? AND user_id=?",(post_id,session['user_id'])); liked=False
    else:  conn.execute("INSERT INTO likes(post_id,user_id) VALUES(?,?)",(post_id,session['user_id'])); liked=True
    cnt  = conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?",(post_id,)).fetchone()[0]
    conn.commit(); conn.close()
    return jsonify({"liked":liked,"count":cnt})

@app.route('/ping')
def ping(): return jsonify({"status":"ok","app":APP_NAME}),200

@app.route('/syarat-ketentuan')
def syarat(): return render_template('syarat.html')

@socketio.on('join')
def on_join(data):
    uid = data.get('user_id')
    if uid:
        join_room(f"user_{uid}")
        logging.info(f"User {uid} joined notification room.")

@app.route('/tentang')
def tentang(): return render_template('tentang.html')

# ─── ERROR HANDLING ─────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, msg="Halaman tidak ditemukan."), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, msg="Kamu tidak memiliki akses ke halaman ini."), 403

@app.errorhandler(500)
def server_error(e):
    logging.error(f"Internal Server Error: {e}")
    return render_template('error.html', code=500, msg="Terjadi kesalahan internal pada server."), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', code=429, msg="Terlalu banyak permintaan. Silakan tunggu beberapa saat."), 429

if __name__ == '__main__':
    socketio.run(app, debug=DEBUG, host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT', '5000')))
