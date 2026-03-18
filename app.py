from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import sqlite3, os, random, string, re
from datetime import datetime
import xendit
from xendit.apis import InvoiceApi

# =====================================================================
# KONFIGURASI APLIKASI
# =====================================================================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16MB upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- CONFIG XENDIT (Gunakan .env di production) ---
X_KEY = os.environ.get('XENDIT_SECRET_KEY', 'xnd_development_...')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'bisnisanda@gmail.com')
BASE_URL = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
FEE_PERSEN = 0.02
APP_NAME = "Socrow"

try:
    api_client = xendit.ApiClient(configuration=xendit.Configuration(api_key={'XENDIT_API_KEY': X_KEY}))
    invoice_api = InvoiceApi(api_client)
except:
    invoice_api = None

# =====================================================================
# HELPER FUNCTIONS
# =====================================================================
def get_db():
    conn = sqlite3.connect('sosmed_rekber.db')
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu.', 'warning')
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('email') != ADMIN_EMAIL:
            abort(403)
        return f(*args, **kwargs)
    return decorated

def get_notif_count():
    if 'user_id' not in session:
        return 0
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (session['user_id'],)).fetchone()[0]
    conn.close()
    return count

def format_rupiah(value):
    try:
        return "Rp {:,.0f}".format(float(value)).replace(",", ".")
    except:
        return "Rp 0"

app.jinja_env.filters['rupiah'] = format_rupiah
app.jinja_env.globals['get_notif_count'] = get_notif_count

def validate_password(pw):
    """Minimal 8 karakter, ada huruf dan angka"""
    return len(pw) >= 8 and re.search(r'[A-Za-z]', pw) and re.search(r'[0-9]', pw)

# =====================================================================
# UTILITY ROUTES
# =====================================================================
@app.route('/ping')
def ping():
    return jsonify({"status": "ok", "app": APP_NAME}), 200

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message="Akses Ditolak"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message="Halaman Tidak Ditemukan"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message="Terjadi Kesalahan Server"), 500

# =====================================================================
# WEBHOOK XENDIT
# =====================================================================
@app.route('/xendit_webhook', methods=['POST'])
def xendit_webhook():
    # Verifikasi callback token Xendit di production
    # token = request.headers.get('X-Callback-Token')
    # if token != os.environ.get('XENDIT_WEBHOOK_TOKEN'): abort(403)

    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400

    if data.get('status') in ['PAID', 'SETTLED']:
        ext_id = data.get('external_id', '')
        conn = get_db()
        try:
            room = conn.execute("SELECT * FROM rekber_rooms WHERE xendit_id = ?", (ext_id,)).fetchone()
            if room:
                conn.execute("UPDATE rekber_rooms SET status = 'dibayar' WHERE xendit_id = ?", (ext_id,))
                conn.execute("""INSERT INTO notifications (user_id, title, message, link)
                    VALUES (?, '💰 Pembayaran Masuk!', 'Pesanan telah dibayar! Segera kirim barang dalam 1x24 jam.', ?)""",
                    (room['seller_id'], f"/ruang/{room['id']}"))
                conn.execute("""INSERT INTO messages (room_id, sender_id, message_text)
                    VALUES (?, 0, '🛡️ SISTEM SOCROW: Pembayaran berhasil dikonfirmasi. Dana aman disimpan Socrow. Penjual harap kirim barang secepatnya.')""",
                    (room['id'],))
                conn.commit()
        finally:
            conn.close()
    return jsonify({"status": "success"}), 200

# =====================================================================
# AUTENTIKASI
# =====================================================================
@app.route('/daftar', methods=['GET', 'POST'])
def daftar():
    if 'user_id' in session:
        return redirect('/')

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        # Validasi input
        errors = []
        if not username or len(username) < 3:
            errors.append("Username minimal 3 karakter.")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username hanya boleh huruf, angka, dan underscore.")
        if not email or '@' not in email:
            errors.append("Email tidak valid.")
        if not validate_password(password):
            errors.append("Password minimal 8 karakter, mengandung huruf dan angka.")
        if password != confirm:
            errors.append("Konfirmasi password tidak cocok.")

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('daftar.html')

        hashed_pw = generate_password_hash(password)
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, email, phone, password) VALUES (?,?,?,?)",
                         (username, email, phone, hashed_pw))
            conn.commit()
            flash('Akun berhasil dibuat! Silakan login.', 'success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username atau email sudah terdaftar.', 'danger')
        finally:
            conn.close()

    return render_template('daftar.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect('/')

    if request.method == 'POST':
        identifier = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower())
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session.permanent = True
            flash(f'Selamat datang kembali, {user["username"]}! 👋', 'success')
            return redirect(request.args.get('next', '/'))
        else:
            flash('Username/email atau password salah.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Kamu berhasil logout.', 'info')
    return redirect('/')

# =====================================================================
# HALAMAN UTAMA & FEED
# =====================================================================
@app.route('/')
def home():
    conn = get_db()
    posts = conn.execute('''
        SELECT p.*, u.username, u.kyc_status, u.store_name,
               (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as like_count,
               (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comment_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC
        LIMIT 30
    ''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

# =====================================================================
# TRANSAKSI REKBER
# =====================================================================
@app.route('/bayar_xendit/<int:id_post>', methods=['POST'])
@login_required
def bayar_xendit(id_post):
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id=? AND is_for_sale=1", (id_post,)).fetchone()
    if not post:
        conn.close()
        flash('Produk tidak ditemukan.', 'danger')
        return redirect('/')

    if post['user_id'] == session['user_id']:
        conn.close()
        flash('Kamu tidak bisa membeli produkmu sendiri.', 'warning')
        return redirect('/')

    if post['stock'] < 1:
        conn.close()
        flash('Stok habis.', 'warning')
        return redirect('/')

    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    ext_id = f"SOCROW-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(1000,9999)}"
    biaya_admin = 2500
    total_bayar = float(post['price']) + biaya_admin

    try:
        inv_req = {
            "external_id": ext_id,
            "amount": total_bayar,
            "payer_email": user['email'],
            "description": f"[{APP_NAME}] {post['caption'][:50]}",
            "success_redirect_url": f"{BASE_URL}/dasbor",
            "failure_redirect_url": f"{BASE_URL}/",
        }
        if invoice_api:
            inv = invoice_api.create_invoice(create_invoice_request=inv_req)
            invoice_url = inv.invoice_url
        else:
            # Mode demo tanpa Xendit
            invoice_url = f"{BASE_URL}/demo_bayar/{ext_id}"

        conn.execute("""INSERT INTO rekber_rooms (post_id, buyer_id, seller_id, status, price_deal, xendit_id)
            VALUES (?,?,?,?,?,?)""",
            (id_post, session['user_id'], post['user_id'], 'menunggu_pembayaran', post['price'], ext_id))
        conn.commit()
        conn.close()
        return redirect(invoice_url)
    except Exception as e:
        conn.close()
        flash(f'Gagal membuat invoice: {str(e)}', 'danger')
        return redirect('/')


@app.route('/aksi_rekber/<int:room_id>/<aksi>', methods=['POST'])
@login_required
def aksi_rekber(room_id, aksi):
    conn = get_db()
    r = conn.execute("""
        SELECT r.*, p.price, p.user_id as s_id, p.caption as barang
        FROM rekber_rooms r
        JOIN posts p ON r.post_id = p.id
        WHERE r.id=?
    """, (room_id,)).fetchone()

    if not r:
        conn.close()
        abort(404)

    # Pastikan hanya buyer yang bisa konfirmasi
    if aksi == 'barang_diterima' and r['buyer_id'] != session['user_id']:
        conn.close()
        abort(403)

    if aksi == 'barang_diterima' and r['status'] == 'dibayar':
        fee = r['price'] * FEE_PERSEN
        bersih = r['price'] - fee
        conn.execute("UPDATE users SET saldo = saldo + ?, total_sales = total_sales + 1 WHERE id=?", (bersih, r['s_id']))
        conn.execute("UPDATE platform_stats SET total_revenue = total_revenue + ? WHERE id=1", (fee,))
        conn.execute("UPDATE rekber_rooms SET status='selesai' WHERE id=?", (room_id,))
        conn.execute("""INSERT INTO notifications (user_id, title, message, link)
            VALUES (?, '✅ Transaksi Selesai!', 'Dana sebesar Rp {:,.0f} telah masuk ke saldo kamu.', ?)""".format(bersih, f"/ruang/{room_id}"),
            (r['s_id'],))
        conn.execute("""INSERT INTO messages (room_id, sender_id, message_text)
            VALUES (?, 0, '✅ SISTEM SOCROW: Pembeli mengkonfirmasi barang diterima. Dana telah diteruskan ke penjual. Transaksi SELESAI!')""",
            (room_id,))
        flash('Transaksi selesai! Terima kasih sudah berbelanja.', 'success')

    elif aksi == 'komplain':
        conn.execute("UPDATE rekber_rooms SET status='komplain' WHERE id=?", (room_id,))
        conn.execute("""INSERT INTO messages (room_id, sender_id, message_text)
            VALUES (?, 0, '⚠️ SISTEM SOCROW: Pembeli mengajukan komplain. Admin akan meninjau dalam 1x24 jam.')""",
            (room_id,))
        flash('Komplain berhasil diajukan. Tim kami akan segera meninjau.', 'warning')

    conn.commit()
    conn.close()
    return redirect(f'/ruang/{room_id}')

# =====================================================================
# PROFIL & PENGATURAN AKUN
# =====================================================================
@app.route('/akun', methods=['GET', 'POST'])
@login_required
def pengaturan_akun():
    pesan = ""
    conn = get_db()

    if request.method == 'POST':
        ft = request.form.get('form_type')

        if ft == 'finance':
            f_ktp = request.files.get('file_ktp')
            f_selfie = request.files.get('file_selfie')

            if not f_ktp or not f_selfie:
                flash('Upload KTP dan Selfie wajib diisi.', 'danger')
            elif not (allowed_file(f_ktp.filename) and allowed_file(f_selfie.filename)):
                flash('Format file tidak didukung. Gunakan JPG/PNG.', 'danger')
            else:
                nk = f"kyc_{session['user_id']}_{secure_filename(f_ktp.filename)}"
                ns = f"slf_{session['user_id']}_{secure_filename(f_selfie.filename)}"
                f_ktp.save(os.path.join(app.config['UPLOAD_FOLDER'], nk))
                f_selfie.save(os.path.join(app.config['UPLOAD_FOLDER'], ns))
                conn.execute("""UPDATE users SET store_name=?, kyc_name=?, bank_name=?, bank_account=?,
                    kyc_status='pending', file_ktp=?, file_selfie=? WHERE id=?""",
                    (request.form['store_name'], request.form['kyc_name'].upper(),
                     request.form['bank_name'], request.form['bank_account'],
                     nk, ns, session['user_id']))
                conn.commit()
                flash('Data KYC berhasil dikirim! Akan diverifikasi dalam 1-2 hari kerja.', 'success')

        elif ft == 'password':
            old_pw = request.form.get('old_password', '')
            new_pw = request.form.get('new_password', '')
            user_check = conn.execute("SELECT password FROM users WHERE id=?", (session['user_id'],)).fetchone()
            if not check_password_hash(user_check['password'], old_pw):
                flash('Password lama salah.', 'danger')
            elif not validate_password(new_pw):
                flash('Password baru minimal 8 karakter, mengandung huruf dan angka.', 'danger')
            else:
                conn.execute("UPDATE users SET password=? WHERE id=?",
                             (generate_password_hash(new_pw), session['user_id']))
                conn.commit()
                flash('Password berhasil diubah.', 'success')

    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    p_rev = conn.execute("SELECT total_revenue FROM platform_stats WHERE id=1").fetchone()[0] \
        if session.get('email') == ADMIN_EMAIL else 0
    my_rooms = conn.execute("""
        SELECT r.*, p.caption as barang FROM rekber_rooms r
        JOIN posts p ON r.post_id = p.id
        WHERE r.buyer_id=? OR r.seller_id=?
        ORDER BY r.id DESC LIMIT 5
    """, (session['user_id'], session['user_id'])).fetchall()
    conn.close()

    return render_template('akun.html', user=user, pesan=pesan,
                           admin_email=ADMIN_EMAIL, platform_revenue=p_rev, my_rooms=my_rooms)

# =====================================================================
# DASBOR TRANSAKSI
# =====================================================================
@app.route('/dasbor')
@login_required
def dasbor():
    conn = get_db()
    rooms = conn.execute('''
        SELECT r.*, p.caption as barang, p.media_url,
               u1.username as buyer_name, u2.username as seller_name
        FROM rekber_rooms r
        JOIN posts p ON r.post_id = p.id
        JOIN users u1 ON r.buyer_id = u1.id
        JOIN users u2 ON r.seller_id = u2.id
        WHERE r.buyer_id = ? OR r.seller_id = ?
        ORDER BY r.id DESC
    ''', (session['user_id'], session['user_id'])).fetchall()
    conn.close()
    return render_template('dasbor.html', rooms=rooms)

# =====================================================================
# RUANG CHAT REKBER
# =====================================================================
@app.route('/ruang/<int:room_id>')
@login_required
def ruang_chat(room_id):
    conn = get_db()
    room = conn.execute('''
        SELECT r.*, p.caption as barang, p.price, p.media_url,
               u1.username as buyer_name, u2.username as seller_name,
               u1.id as b_id, u2.id as s_id
        FROM rekber_rooms r
        JOIN posts p ON r.post_id = p.id
        JOIN users u1 ON r.buyer_id = u1.id
        JOIN users u2 ON r.seller_id = u2.id
        WHERE r.id = ?
    ''', (room_id,)).fetchone()

    if not room:
        conn.close()
        abort(404)

    # Hanya buyer, seller, atau admin yang bisa akses
    if session['user_id'] not in [room['buyer_id'], room['seller_id']] \
            and session.get('email') != ADMIN_EMAIL:
        conn.close()
        abort(403)

    msg = conn.execute('''
        SELECT m.*, u.username as sender_name
        FROM messages m
        LEFT JOIN users u ON m.sender_id = u.id
        WHERE m.room_id = ?
        ORDER BY m.id ASC
    ''', (room_id,)).fetchall()
    conn.close()

    return render_template('ruang_rekber.html', room=room, pesan=msg,
                           user_id=session['user_id'], admin_email=ADMIN_EMAIL)


@app.route('/kirim_pesan/<int:room_id>', methods=['POST'])
@login_required
def kirim_pesan(room_id):
    teks = request.form.get('teks_pesan', '').strip()
    if not teks:
        return redirect(f'/ruang/{room_id}')
    if len(teks) > 1000:
        flash('Pesan terlalu panjang (max 1000 karakter).', 'warning')
        return redirect(f'/ruang/{room_id}')

    conn = get_db()
    # Verifikasi akses
    room = conn.execute("SELECT * FROM rekber_rooms WHERE id=?", (room_id,)).fetchone()
    if room and session['user_id'] in [room['buyer_id'], room['seller_id']]:
        conn.execute("INSERT INTO messages (room_id, sender_id, message_text) VALUES (?,?,?)",
                     (room_id, session['user_id'], teks))
        conn.commit()
    conn.close()
    return redirect(f'/ruang/{room_id}')

# =====================================================================
# TAMBAH POST / PRODUK
# =====================================================================
@app.route('/tambah', methods=['GET', 'POST'])
@login_required
def tambah_post():
    if request.method == 'POST':
        is_sale = request.form.get('is_for_sale') == 'on'
        caption = request.form.get('caption', '').strip()

        if not caption:
            flash('Caption wajib diisi.', 'danger')
            return render_template('tambah.html')

        # Handle media upload
        media = request.files.get('media_file')
        filename, pt = "", "text"
        if media and media.filename and allowed_file(media.filename):
            ext = media.filename.rsplit('.', 1)[1].lower()
            filename = f"post_{session['user_id']}_{random.randint(10000,99999)}.{ext}"
            media.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            pt = 'video' if ext == 'mp4' else 'image'

        conn = get_db()
        if is_sale:
            kyc_status = 'verified' if session.get('email') == ADMIN_EMAIL \
                else conn.execute("SELECT kyc_status FROM users WHERE id=?", (session['user_id'],)).fetchone()['kyc_status']
            if kyc_status != 'verified':
                conn.close()
                flash('Untuk berjualan, kamu wajib verifikasi KYC terlebih dahulu.', 'warning')
                return redirect('/akun')

            try:
                price = float(request.form.get('price', 0))
                stock = int(request.form.get('stock', 1))
            except ValueError:
                conn.close()
                flash('Harga dan stok harus berupa angka.', 'danger')
                return render_template('tambah.html')

            conn.execute("""INSERT INTO posts (user_id, post_type, media_url, caption, is_for_sale, price, stock)
                VALUES (?,?,?,?,1,?,?)""",
                (session['user_id'], pt, filename, caption, price, stock))
        else:
            conn.execute("""INSERT INTO posts (user_id, post_type, media_url, caption, is_for_sale)
                VALUES (?,?,?,?,0)""",
                (session['user_id'], pt, filename, caption))

        conn.commit()
        conn.close()
        flash('Post berhasil dipublikasikan! 🎉', 'success')
        return redirect('/')

    return render_template('tambah.html')

# =====================================================================
# NOTIFIKASI
# =====================================================================
@app.route('/notifikasi')
@login_required
def notifikasi():
    conn = get_db()
    notifs = conn.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    # Mark as read
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (session['user_id'],))
    conn.commit()
    conn.close()
    return render_template('notifikasi.html', notifs=notifs)

# =====================================================================
# HALAMAN STATIS
# =====================================================================
@app.route('/syarat-ketentuan')
def syarat():
    return render_template('syarat.html')

@app.route('/tentang')
def tentang():
    return render_template('tentang.html')

# =====================================================================
# ADMIN PANEL
# =====================================================================
@app.route('/admin/kyc')
@login_required
@admin_required
def admin_kyc():
    conn = get_db()
    users = conn.execute("SELECT * FROM users WHERE kyc_status='pending'").fetchall()
    stats = conn.execute("SELECT total_revenue FROM platform_stats WHERE id=1").fetchone()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_txn = conn.execute("SELECT COUNT(*) FROM rekber_rooms").fetchone()[0]
    conn.close()
    return render_template('admin_kyc.html', users=users, stats=stats,
                           total_users=total_users, total_txn=total_txn)


@app.route('/admin/verify/<int:user_id>/<action>')
@login_required
@admin_required
def verify_user(user_id, action):
    status = 'verified' if action == 'approve' else 'rejected'
    conn = get_db()
    conn.execute("UPDATE users SET kyc_status=? WHERE id=?", (status, user_id))
    # Kirim notifikasi ke user
    msg = 'Selamat! KYC kamu telah diverifikasi. Kamu kini bisa berjualan.' if action == 'approve' \
        else 'Maaf, KYC kamu ditolak. Silakan upload ulang dokumen yang valid.'
    title = '✅ KYC Disetujui' if action == 'approve' else '❌ KYC Ditolak'
    conn.execute("INSERT INTO notifications (user_id, title, message, link) VALUES (?,?,?,?)",
                 (user_id, title, msg, '/akun'))
    conn.commit()
    conn.close()
    flash(f'User berhasil {"diverifikasi" if action == "approve" else "ditolak"}.', 'success')
    return redirect('/admin/kyc')


# =====================================================================
# LIKE & KOMENTAR (AJAX)
# =====================================================================
@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def toggle_like(post_id):
    conn = get_db()
    existing = conn.execute("SELECT id FROM likes WHERE post_id=? AND user_id=?",
                            (post_id, session['user_id'])).fetchone()
    if existing:
        conn.execute("DELETE FROM likes WHERE post_id=? AND user_id=?", (post_id, session['user_id']))
        liked = False
    else:
        conn.execute("INSERT INTO likes (post_id, user_id) VALUES (?,?)", (post_id, session['user_id']))
        liked = True
    count = conn.execute("SELECT COUNT(*) FROM likes WHERE post_id=?", (post_id,)).fetchone()[0]
    conn.commit()
    conn.close()
    return jsonify({"liked": liked, "count": count})


@app.route('/komentar/<int:post_id>', methods=['POST'])
@login_required
def tambah_komentar(post_id):
    teks = request.form.get('teks', '').strip()
    if teks and len(teks) <= 500:
        conn = get_db()
        conn.execute("INSERT INTO comments (post_id, user_id, comment_text) VALUES (?,?,?)",
                     (post_id, session['user_id'], teks))
        conn.commit()
        conn.close()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG', 'True') == 'True')
