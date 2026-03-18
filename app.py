from flask import Flask, render_template, request, redirect, session, jsonify, flash, abort, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta
import sqlite3, os, random, string, re, json

# ─── KONFIGURASI ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key      = os.environ.get('SECRET_KEY', os.urandom(32))
app.permanent_session_lifetime = timedelta(days=7)

UPLOAD_FOLDER   = 'static/uploads'
ALLOWED_EXT     = {'png','jpg','jpeg','gif','webp','mp4','pdf'}
MAX_UPLOAD_MB   = 16
ADMIN_EMAIL     = os.environ.get('ADMIN_EMAIL', 'admin@socrow.com')
BASE_URL        = os.environ.get('BASE_URL', 'http://127.0.0.1:5000')
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
try:
    import xendit
    from xendit.apis import InvoiceApi
    X_KEY = os.environ.get('XENDIT_SECRET_KEY','')
    if X_KEY and not X_KEY.startswith('xnd_development_...'):
        api_client = xendit.ApiClient(configuration=xendit.Configuration(
            api_key={'XENDIT_API_KEY': X_KEY}))
        invoice_api = InvoiceApi(api_client)
except Exception:
    pass

# ─── HELPERS ────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect('sosmed_rekber.db')
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def allowed_file(fn):
    return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED_EXT

def gen_ref_code(n=8):
    return ''.join(random.choices(string.ascii_uppercase+string.digits, k=n))

def validate_password(pw):
    return len(pw)>=8 and re.search(r'[A-Za-z]',pw) and re.search(r'[0-9]',pw)

def rupiah(v):
    try: return "Rp {:,.0f}".format(float(v)).replace(",",".")
    except: return "Rp 0"

def audit(action, detail=None, user_id=None):
    try:
        conn = get_db()
        uid  = user_id or session.get('user_id')
        ip   = request.remote_addr
        conn.execute("INSERT INTO audit_logs(user_id,action,detail,ip_address) VALUES(?,?,?,?)",
                     (uid, action, detail, ip))
        conn.commit(); conn.close()
    except: pass

def notif(user_id, title, message, link='/', ntype='info'):
    try:
        conn = get_db()
        conn.execute("INSERT INTO notifications(user_id,title,message,notif_type,link) VALUES(?,?,?,?,?)",
                     (user_id, title, message, ntype, link))
        conn.commit(); conn.close()
    except: pass

def sys_msg(room_id, text):
    try:
        conn = get_db()
        conn.execute("INSERT INTO messages(room_id,sender_id,message_text,message_type) VALUES(?,0,?,'system')",
                     (room_id, text))
        conn.commit(); conn.close()
    except: pass

def get_notif_count():
    if 'user_id' not in session: return 0
    try:
        conn = get_db()
        n = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",
                         (session['user_id'],)).fetchone()[0]
        conn.close(); return n
    except: return 0

app.jinja_env.filters['rupiah'] = rupiah
app.jinja_env.globals.update(get_notif_count=get_notif_count, app_name=APP_NAME,
                              admin_email=ADMIN_EMAIL, now=datetime.now)

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
        if '@' not in e: errs.append("Email tidak valid.")
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

            conn.execute("""INSERT INTO users(username,email,phone,password,referral_code,referred_by)
                            VALUES(?,?,?,?,?,?)""",
                         (u, e, p, generate_password_hash(pw), code, referrer_id))
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

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session: return redirect('/')
    if request.method == 'POST':
        ident = request.form.get('username','').strip()
        pw    = request.form.get('password','')
        conn  = get_db()
        user  = conn.execute("SELECT * FROM users WHERE (username=? OR email=?) AND is_banned=0",
                             (ident, ident.lower())).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], pw):
            session.clear(); session.permanent = True
            session.update({'user_id':user['id'],'username':user['username'],'email':user['email']})
            audit('LOGIN', f'user={user["username"]}', user['id'])
            flash(f'Selamat datang, {user["username"]}! 👋','success')
            return redirect(request.args.get('next','/'))
        flash('Username/email atau password salah.','danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    flash('Berhasil logout.','info')
    return redirect('/')

# ─── HOME / FEED ─────────────────────────────────────────────────────────────
@app.route('/')
def home():
    q    = request.args.get('q','')
    cat  = request.args.get('cat','')
    kind = request.args.get('kind','')
    conn = get_db()
    sql  = '''SELECT p.*, u.username, u.kyc_status, u.store_name, u.rating_avg,
                     (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as like_count,
                     (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comment_count,
                     (SELECT image_url FROM post_images WHERE post_id=p.id ORDER BY sort_order LIMIT 1) as extra_img
              FROM posts p JOIN users u ON p.user_id=u.id
              WHERE p.is_active=1 AND u.is_banned=0'''
    params = []
    if q:    sql += " AND (p.caption LIKE ? OR u.username LIKE ?)"; params+=[f'%{q}%',f'%{q}%']
    if cat:  sql += " AND p.product_category=?"; params.append(cat)
    if kind: sql += " AND p.product_kind=?";     params.append(kind)
    sql += " ORDER BY p.id DESC LIMIT 40"
    posts = conn.execute(sql, params).fetchall()
    conn.close()
    cats = ['umum','elektronik','fashion','makanan','digital','jasa','otomotif','hobi']
    return render_template('index.html', posts=posts, q=q, cat=cat, kind=kind, cats=cats)

# ─── POST / PRODUK ──────────────────────────────────────────────────────────
@app.route('/tambah', methods=['GET','POST'])
@login_required
def tambah_post():
    if request.method == 'POST':
        caption  = request.form.get('caption','').strip()
        is_sale  = request.form.get('is_for_sale') == 'on'
        cat      = request.form.get('product_category','umum')
        kind     = request.form.get('product_kind','fisik')
        if not caption:
            flash('Caption wajib diisi.','danger')
            return render_template('tambah.html')

        media = request.files.get('media_file')
        filename, pt = '', 'text'
        if media and media.filename and allowed_file(media.filename):
            ext = media.filename.rsplit('.',1)[1].lower()
            filename = f"post_{session['user_id']}_{random.randint(10000,99999)}.{ext}"
            media.save(os.path.join(UPLOAD_FOLDER, filename))
            pt = 'video' if ext=='mp4' else 'image'

        conn = get_db()
        if is_sale:
            kyc = 'verified' if session.get('email')==ADMIN_EMAIL else \
                  conn.execute("SELECT kyc_status FROM users WHERE id=?",(session['user_id'],)).fetchone()['kyc_status']
            if kyc != 'verified':
                conn.close()
                flash('Wajib verifikasi KYC sebelum berjualan.','warning')
                return redirect('/akun')
            try:
                price  = float(request.form.get('price',0))
                stock  = int(request.form.get('stock',1))
                weight = int(request.form.get('weight_gram',0))
            except ValueError:
                conn.close(); flash('Harga/stok/berat harus angka.','danger')
                return render_template('tambah.html')

            # Upload file digital
            dig_file = None
            if kind == 'digital':
                df = request.files.get('digital_file')
                if df and df.filename and allowed_file(df.filename):
                    dext = df.filename.rsplit('.',1)[1].lower()
                    dig_file = f"digital_{session['user_id']}_{random.randint(10000,99999)}.{dext}"
                    df.save(os.path.join(UPLOAD_FOLDER,'digital',dig_file))

            conn.execute("""INSERT INTO posts(user_id,post_type,product_category,product_kind,
                            media_url,caption,is_for_sale,price,stock,weight_gram,digital_file)
                            VALUES(?,?,?,?,?,?,1,?,?,?,?)""",
                         (session['user_id'],pt,cat,kind,filename,caption,price,stock,weight,dig_file))
        else:
            conn.execute("""INSERT INTO posts(user_id,post_type,product_category,media_url,caption,is_for_sale)
                            VALUES(?,?,?,?,?,0)""",(session['user_id'],pt,cat,filename,caption))

        post_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Multiple images
        for f in request.files.getlist('extra_images'):
            if f and f.filename and allowed_file(f.filename):
                ext2 = f.filename.rsplit('.',1)[1].lower()
                fn2  = f"extra_{post_id}_{random.randint(1000,9999)}.{ext2}"
                f.save(os.path.join(UPLOAD_FOLDER, fn2))
                conn.execute("INSERT INTO post_images(post_id,image_url) VALUES(?,?)",(post_id,fn2))

        conn.commit(); conn.close()
        flash('Post berhasil dipublikasikan! 🎉','success')
        return redirect('/')
    return render_template('tambah.html')

# ─── TRANSAKSI REKBER ────────────────────────────────────────────────────────
@app.route('/bayar/<int:post_id>', methods=['POST'])
@login_required
def bayar(post_id):
    conn = get_db()
    post = conn.execute("SELECT * FROM posts WHERE id=? AND is_for_sale=1 AND is_active=1",(post_id,)).fetchone()
    if not post:          conn.close(); flash('Produk tidak ditemukan.','danger');  return redirect('/')
    if post['user_id']==session['user_id']: conn.close(); flash('Tidak bisa beli produk sendiri.','warning'); return redirect('/')
    if post['stock']<1:   conn.close(); flash('Stok habis.','warning');            return redirect('/')

    user    = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    ext_id  = f"SCR-{datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(1000,9999)}"
    aff_code= request.form.get('affiliate_code','').strip().upper()
    total   = float(post['price']) + 2500

    # Validasi kode afiliasi
    valid_aff = None
    if aff_code:
        ar = conn.execute("SELECT * FROM affiliates WHERE code=? AND is_active=1",(aff_code,)).fetchone()
        if ar and ar['user_id'] != session['user_id']:
            valid_aff = aff_code

    try:
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

        conn.execute("""INSERT INTO rekber_rooms(post_id,buyer_id,seller_id,status,price_deal,xendit_id,affiliate_code)
                        VALUES(?,?,?,'menunggu_pembayaran',?,?,?)""",
                     (post_id, session['user_id'], post['user_id'], post['price'], ext_id, valid_aff))
        conn.commit(); conn.close()
        audit('BAYAR_INIT', f'post={post_id} ext={ext_id}')
        return redirect(invoice_url)
    except Exception as ex:
        conn.close(); flash(f'Gagal buat invoice: {ex}','danger'); return redirect('/')

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
    conn.close()
    notif(room['seller_id'],'💰 Pembayaran Masuk!','Pesanan dibayar! Segera kirim barang dalam 1×24 jam.',f'/ruang/{rid}','success')
    sys_msg(rid, f'🛡️ SISTEM: Pembayaran via {metode} dikonfirmasi. Dana aman di Socrow. Penjual harap kirim secepatnya.')
    audit('BAYAR_DEMO', f'room={rid} metode={metode}')
    flash('✅ Pembayaran berhasil! Dana disimpan aman oleh Socrow.','success')
    return redirect(f'/ruang/{rid}')

# ─── WEBHOOK XENDIT ─────────────────────────────────────────────────────────
@app.route('/xendit_webhook', methods=['POST'])
def xendit_webhook():
    data = request.json or {}
    if data.get('status') in ['PAID','SETTLED']:
        ext_id = data.get('external_id','')
        conn   = get_db()
        room   = conn.execute("SELECT * FROM rekber_rooms WHERE xendit_id=?",(ext_id,)).fetchone()
        if room and room['status']=='menunggu_pembayaran':
            conn.execute("UPDATE rekber_rooms SET status='dibayar',payment_method=?,updated_at=CURRENT_TIMESTAMP WHERE xendit_id=?",
                         (data.get('payment_channel','Xendit'), ext_id))
            conn.commit()
            notif(room['seller_id'],'💰 Pembayaran Masuk!','Pesanan dibayar!',f'/ruang/{room["id"]}','success')
            sys_msg(room['id'],'🛡️ SISTEM: Pembayaran dikonfirmasi Xendit. Dana aman di Socrow.')
        conn.close()
    return jsonify({"status":"ok"}),200

# ─── AKSI REKBER ─────────────────────────────────────────────────────────────
@app.route('/aksi_rekber/<int:room_id>/<aksi>', methods=['POST'])
@login_required
def aksi_rekber(room_id, aksi):
    conn = get_db()
    r = conn.execute("""SELECT r.*,p.price,p.user_id as s_id,p.product_kind,p.digital_file
                        FROM rekber_rooms r JOIN posts p ON r.post_id=p.id WHERE r.id=?""",(room_id,)).fetchone()
    if not r: conn.close(); abort(404)

    if aksi == 'barang_diterima':
        if r['buyer_id'] != session['user_id']: conn.close(); abort(403)
        if r['status'] != 'dibayar': conn.close(); flash('Status tidak sesuai.','warning'); return redirect(f'/ruang/{room_id}')

        fee_plat = r['price'] * FEE_PERSEN
        fee_aff  = 0
        bersih   = r['price'] - fee_plat

        # Bayar afiliasi
        if r['affiliate_code']:
            aff = conn.execute("SELECT * FROM affiliates WHERE code=?",(r['affiliate_code'],)).fetchone()
            if aff:
                fee_aff  = r['price'] * FEE_AFILIASI
                fee_plat = r['price'] * FEE_PERSEN
                bersih   = r['price'] - fee_plat - fee_aff
                conn.execute("UPDATE users SET saldo_afiliasi=saldo_afiliasi+? WHERE id=?",(fee_aff, aff['user_id']))
                conn.execute("UPDATE affiliates SET total_earned=total_earned+? WHERE id=?",(fee_aff, aff['id']))
                conn.execute("INSERT INTO affiliate_logs(affiliate_id,room_id,transaction_amount,commission,status,paid_at) VALUES(?,?,?,?,'paid',CURRENT_TIMESTAMP)",
                             (aff['id'], room_id, r['price'], fee_aff))
                notif(aff['user_id'],'💸 Komisi Afiliasi!',f'Kamu dapat komisi {rupiah(fee_aff)} dari transaksi rekber!','/akun','success')

        conn.execute("UPDATE users SET saldo=saldo+?,total_sales=total_sales+1 WHERE id=?",(bersih, r['s_id']))
        conn.execute("UPDATE platform_stats SET total_revenue=total_revenue+?,total_transactions=total_transactions+1 WHERE id=1",(fee_plat,))
        conn.execute("UPDATE rekber_rooms SET status='selesai',updated_at=CURRENT_TIMESTAMP WHERE id=?",(room_id,))

        # Kirim file digital otomatis
        if r['product_kind']=='digital' and r['digital_file']:
            sys_msg(room_id, f'✅ SISTEM: Transaksi selesai! File digital tersedia di bawah chat.')

        notif(r['s_id'],'✅ Transaksi Selesai!',f'Dana {rupiah(bersih)} masuk ke saldomu!',f'/ruang/{room_id}','success')
        sys_msg(room_id,'✅ SISTEM: Pembeli konfirmasi barang diterima. Dana dikirim ke penjual. Terima kasih!')
        audit('SELESAI', f'room={room_id}')
        flash('Transaksi selesai! Terima kasih sudah belanja di Socrow.','success')

    elif aksi == 'input_resi':
        if r['seller_id'] != session['user_id']: conn.close(); abort(403)
        resi    = request.form.get('resi_number','').strip()
        courier = request.form.get('courier_name','').strip()
        if not resi: conn.close(); flash('Nomor resi wajib diisi.','danger'); return redirect(f'/ruang/{room_id}')
        conn.execute("UPDATE rekber_rooms SET resi_number=?,courier_name=?,status='dikirim',updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (resi, courier, room_id))
        conn.execute("INSERT INTO shipment_tracking(room_id,courier,resi,status) VALUES(?,?,?,'in_transit')",
                     (room_id, courier, resi))
        notif(r['buyer_id'],'📦 Barang Dikirim!',f'Penjual kirim via {courier}. Resi: {resi}',f'/ruang/{room_id}','info')
        sys_msg(room_id, f'📦 SISTEM: Penjual input resi pengiriman. Kurir: {courier} | No. Resi: {resi}')
        flash('Resi berhasil diinput!','success')

    conn.commit(); conn.close()
    return redirect(f'/ruang/{room_id}')

# ─── RUANG CHAT ──────────────────────────────────────────────────────────────
@app.route('/ruang/<int:room_id>')
@login_required
def ruang_chat(room_id):
    conn = get_db()
    room = conn.execute("""SELECT r.*,p.caption as barang,p.price,p.media_url,p.product_kind,p.digital_file,
                                  u1.username as buyer_name,u2.username as seller_name
                           FROM rekber_rooms r JOIN posts p ON r.post_id=p.id
                           JOIN users u1 ON r.buyer_id=u1.id JOIN users u2 ON r.seller_id=u2.id
                           WHERE r.id=?""",(room_id,)).fetchone()
    if not room: conn.close(); abort(404)
    if session['user_id'] not in [room['buyer_id'],room['seller_id']] and session.get('email')!=ADMIN_EMAIL:
        conn.close(); abort(403)

    msgs  = conn.execute("""SELECT m.*,u.username as sender_name FROM messages m
                            LEFT JOIN users u ON m.sender_id=u.id
                            WHERE m.room_id=? ORDER BY m.id ASC""",(room_id,)).fetchall()
    dispute = conn.execute("SELECT * FROM disputes WHERE room_id=?",(room_id,)).fetchone()
    rating  = conn.execute("SELECT * FROM ratings WHERE room_id=?",(room_id,)).fetchone()
    conn.close()
    return render_template('ruang_rekber.html', room=room, pesan=msgs,
                           dispute=dispute, rating=rating,
                           user_id=session['user_id'])

@app.route('/kirim_pesan/<int:room_id>', methods=['POST'])
@login_required
def kirim_pesan(room_id):
    teks = request.form.get('teks_pesan','').strip()[:1000]
    if not teks: return redirect(f'/ruang/{room_id}')
    conn = get_db()
    room = conn.execute("SELECT * FROM rekber_rooms WHERE id=?",(room_id,)).fetchone()
    if room and session['user_id'] in [room['buyer_id'],room['seller_id']]:
        conn.execute("INSERT INTO messages(room_id,sender_id,message_text) VALUES(?,?,?)",
                     (room_id,session['user_id'],teks))
        conn.commit()
    conn.close()
    return redirect(f'/ruang/{room_id}')

# ─── DOWNLOAD FILE DIGITAL ──────────────────────────────────────────────────
@app.route('/download_digital/<int:room_id>')
@login_required
def download_digital(room_id):
    conn = get_db()
    room = conn.execute("""SELECT r.*,p.digital_file FROM rekber_rooms r
                           JOIN posts p ON r.post_id=p.id WHERE r.id=?""",(room_id,)).fetchone()
    if not room or room['buyer_id']!=session['user_id'] or room['status']!='selesai':
        conn.close(); abort(403)
    fn = room['digital_file']
    conn.close()
    if not fn: abort(404)
    return send_from_directory(os.path.join(UPLOAD_FOLDER,'digital'), fn, as_attachment=True)

# ─── DISPUTE / MEDIASI ───────────────────────────────────────────────────────
@app.route('/dispute/<int:room_id>', methods=['GET','POST'])
@login_required
def dispute(room_id):
    conn = get_db()
    room = conn.execute("SELECT * FROM rekber_rooms WHERE id=?",(room_id,)).fetchone()
    if not room: conn.close(); abort(404)
    if session['user_id'] not in [room['buyer_id'],room['seller_id']]: conn.close(); abort(403)
    if room['status'] not in ['dibayar','dikirim']: conn.close(); flash('Tidak bisa komplain di status ini.','warning'); return redirect(f'/ruang/{room_id}')

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
            if f and f.filename and allowed_file(f.filename):
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
        if f and f.filename and allowed_file(f.filename):
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
@app.route('/rating/<int:room_id>', methods=['POST'])
@login_required
def beri_rating(room_id):
    conn = get_db()
    room = conn.execute("SELECT * FROM rekber_rooms WHERE id=? AND status='selesai'",(room_id,)).fetchone()
    if not room or room['buyer_id']!=session['user_id']: conn.close(); abort(403)
    existing = conn.execute("SELECT id FROM ratings WHERE room_id=?",(room_id,)).fetchone()
    if existing: conn.close(); flash('Sudah pernah memberi rating.','warning'); return redirect(f'/ruang/{room_id}')

    score = int(request.form.get('score',5))
    text  = request.form.get('review_text','').strip()[:500]
    conn.execute("INSERT INTO ratings(room_id,reviewer_id,reviewed_id,score,review_text) VALUES(?,?,?,?,?)",
                 (room_id, session['user_id'], room['seller_id'], score, text))
    # Update rata-rata
    avg = conn.execute("SELECT AVG(score),COUNT(*) FROM ratings WHERE reviewed_id=?",(room['seller_id'],)).fetchone()
    conn.execute("UPDATE users SET rating_avg=?,rating_count=? WHERE id=?",(avg[0],avg[1],room['seller_id']))
    conn.commit(); conn.close()
    flash('Rating berhasil dikirim. Terima kasih! ⭐','success')
    return redirect(f'/ruang/{room_id}')

# ─── WITHDRAWAL ──────────────────────────────────────────────────────────────
@app.route('/withdraw', methods=['GET','POST'])
@login_required
def withdraw():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    history = conn.execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 20",(session['user_id'],)).fetchall()

    if request.method == 'POST':
        source  = request.form.get('source','saldo')  # 'saldo' or 'afiliasi'
        try:   amount = float(request.form.get('amount',0))
        except: amount = 0

        bal = float(user['saldo']) if source=='saldo' else float(user['saldo_afiliasi'])
        min_wd = WITHDRAW_MIN if source=='saldo' else AFILIASI_MIN

        if amount < min_wd:
            flash(f'Minimum penarikan {rupiah(min_wd)}.','danger')
        elif amount > bal:
            flash('Saldo tidak mencukupi.','danger')
        elif not user['bank_account']:
            flash('Lengkapi data bank di halaman akun terlebih dahulu.','warning')
            conn.close(); return redirect('/akun')
        else:
            net = amount - WITHDRAW_FEE
            conn.execute("""INSERT INTO withdrawals(user_id,amount,fee,net_amount,bank_name,bank_account,account_name,source)
                            VALUES(?,?,?,?,?,?,?,?)""",
                         (session['user_id'], amount, WITHDRAW_FEE, net,
                          user['bank_name'], user['bank_account'], user['kyc_name'] or user['username'], source))
            if source == 'saldo':
                conn.execute("UPDATE users SET saldo=saldo-? WHERE id=?",(amount, session['user_id']))
            else:
                conn.execute("UPDATE users SET saldo_afiliasi=saldo_afiliasi-? WHERE id=?",(amount, session['user_id']))
            conn.commit()
            audit('WITHDRAW_REQUEST', f'amount={amount} source={source}')
            flash(f'Permintaan penarikan {rupiah(net)} (setelah biaya) berhasil diajukan! Diproses 1-2 hari kerja.','success')
            conn.close(); return redirect('/withdraw')

    conn.close()
    return render_template('withdraw.html', user=user, history=history,
                           withdraw_fee=WITHDRAW_FEE, withdraw_min=WITHDRAW_MIN,
                           afiliasi_min=AFILIASI_MIN)

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
    conn.close()
    return render_template('dasbor.html', rooms=rooms, stats=stats)

# ─── NOTIFIKASI ──────────────────────────────────────────────────────────────
@app.route('/notifikasi')
@login_required
def notifikasi():
    conn   = get_db()
    notifs = conn.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC",(session['user_id'],)).fetchall()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",(session['user_id'],))
    conn.commit(); conn.close()
    return render_template('notifikasi.html', notifs=notifs)

# ─── AKUN / PROFIL ───────────────────────────────────────────────────────────
@app.route('/akun', methods=['GET','POST'])
@login_required
def akun():
    conn = get_db()
    if request.method == 'POST':
        ft = request.form.get('form_type')
        if ft == 'finance':
            fk = request.files.get('file_ktp'); fs = request.files.get('file_selfie')
            if not fk or not fs: flash('Upload KTP dan Selfie.','danger')
            elif not (allowed_file(fk.filename) and allowed_file(fs.filename)): flash('Format file tidak didukung.','danger')
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
            if not check_password_hash(uc['password'],old): flash('Password lama salah.','danger')
            elif not validate_password(new): flash('Password baru minimal 8 karakter.','danger')
            else:
                conn.execute("UPDATE users SET password=? WHERE id=?",(generate_password_hash(new),session['user_id']))
                conn.commit(); flash('Password berhasil diubah.','success')

    user    = conn.execute("SELECT * FROM users WHERE id=?",(session['user_id'],)).fetchone()
    aff     = conn.execute("SELECT * FROM affiliates WHERE user_id=?",(session['user_id'],)).fetchone()
    p_rev   = conn.execute("SELECT total_revenue,total_transactions,total_users FROM platform_stats WHERE id=1").fetchone() \
              if session.get('email')==ADMIN_EMAIL else None
    ratings = conn.execute("SELECT r.*,u.username as reviewer FROM ratings r JOIN users u ON r.reviewer_id=u.id WHERE r.reviewed_id=? ORDER BY r.id DESC LIMIT 5",(session['user_id'],)).fetchall()
    conn.close()
    return render_template('akun.html', user=user, aff=aff, p_rev=p_rev, ratings=ratings, base_url=BASE_URL)

# ─── ADMIN ───────────────────────────────────────────────────────────────────
@app.route('/admin/kyc')
@login_required
@admin_required
def admin_kyc():
    conn   = get_db()
    users  = conn.execute("SELECT * FROM users WHERE kyc_status='pending' ORDER BY id").fetchall()
    stats  = conn.execute("SELECT * FROM platform_stats WHERE id=1").fetchone()
    tu     = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    txn    = conn.execute("SELECT COUNT(*) FROM rekber_rooms WHERE status='selesai'").fetchone()[0]
    conn.close()
    return render_template('admin_kyc.html', users=users, stats=stats, total_users=tu, total_txn=txn)

@app.route('/admin/verify/<int:uid>/<action>')
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
        col = 'saldo' if wd['source']=='saldo' else 'saldo_afiliasi'
        conn.execute(f"UPDATE users SET {col}={col}+? WHERE id=?",(wd['amount'],wd['user_id']))
        conn.execute("UPDATE withdrawals SET status='rejected',admin_note=?,processed_by=?,processed_at=CURRENT_TIMESTAMP WHERE id=?",
                     (note, session['user_id'], wid))
        notif(wd['user_id'],'❌ Penarikan Ditolak',f'Penarikan ditolak. Alasan: {note or "-"}. Saldo dikembalikan.','/withdraw','danger')

    audit('WITHDRAWAL_VERDICT', f'wd={wid} action={action}')
    conn.commit(); conn.close()
    flash(f'Penarikan berhasil {"disetujui" if action=="approve" else "ditolak"}.','success')
    return redirect('/admin/withdrawals')

# ─── MISC ────────────────────────────────────────────────────────────────────
@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like(post_id):
    conn = get_db()
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

@app.route('/tentang')
def tentang(): return render_template('tentang.html')

if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG','True')=='True')
