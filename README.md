# 🛡️ Socrow — Platform Sosial Rekber

> Platform sosial media dengan sistem rekening bersama (rekber) terintegrasi. Jual beli aman, transparan, dan terpercaya.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Xendit](https://img.shields.io/badge/Payment-Xendit-purple)

---

## ✨ Fitur Utama

| Fitur | Deskripsi |
|-------|-----------|
| 🔒 Rekber Otomatis | Dana pembeli disimpan sampai barang diterima |
| 💳 Payment Gateway | Terintegrasi Xendit (transfer, QRIS, dll) |
| 🪪 KYC Penjual | Verifikasi identitas sebelum berjualan |
| 💬 Chat Room | Komunikasi buyer & seller per transaksi |
| 🔔 Notifikasi | Alert real-time setiap update transaksi |
| 👑 Admin Panel | Kelola KYC, sengketa, dan statistik platform |
| ❤️ Feed Sosial | Post foto/video + like & komentar |

---

## 🚀 Cara Menjalankan

### 1. Clone & Setup

```bash
git clone https://github.com/username/sosmed-rekber.git
cd sosmed-rekber
```

### 2. Buat Virtual Environment

```bash
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Konfigurasi Environment

```bash
cp .env.example .env
# Edit .env dan isi nilai yang diperlukan
```

### 5. Inisialisasi Database

```bash
python database.py
```

### 6. Jalankan Aplikasi

```bash
python app.py
```

Buka: **http://127.0.0.1:5000**

---

## 🗂️ Struktur Project

```
sosmed-rekber/
├── app.py              # Backend Flask utama
├── database.py         # Schema & inisialisasi DB
├── requirements.txt    # Dependencies Python
├── .env.example        # Template konfigurasi
├── .gitignore          # File yang dikecualikan dari Git
├── static/
│   ├── style.css       # Global styles tambahan
│   └── uploads/        # Upload foto/video (auto-created)
└── templates/
    ├── base.html        # Layout dasar (navbar, footer)
    ├── index.html       # Halaman beranda / feed
    ├── login.html       # Halaman login
    ├── daftar.html      # Halaman registrasi
    ├── tambah.html      # Buat post / produk
    ├── dasbor.html      # Dashboard transaksi
    ├── ruang_rekber.html # Chat room per transaksi
    ├── akun.html        # Profil & pengaturan akun
    ├── notifikasi.html  # Pusat notifikasi
    ├── admin_kyc.html   # Panel admin KYC
    ├── syarat.html      # Syarat & ketentuan
    ├── tentang.html     # Halaman tentang kami
    └── error.html       # Halaman error (403/404/500)
```

---

## 🔐 Keamanan yang Diterapkan

- ✅ **Password hashing** — Werkzeug `pbkdf2:sha256`
- ✅ **Secret key dari environment** — tidak hardcoded
- ✅ **Decorator login_required & admin_required** — proteksi route
- ✅ **Validasi input** — username, email, password strength
- ✅ **Proteksi IDOR** — cek kepemilikan sebelum aksi
- ✅ **File upload validation** — whitelist ekstensi
- ✅ **Error handler** — 403, 404, 500
- ✅ **WAL mode SQLite** — performa & keamanan DB
- ✅ **`.gitignore`** — `.env`, `*.db`, `uploads/` tidak ter-commit

---

## 💡 Konfigurasi Xendit

1. Daftar di [dashboard.xendit.co](https://dashboard.xendit.co)
2. Copy **Secret Key** dari Settings → Developers
3. Daftarkan **Webhook URL**: `https://domainmu.com/xendit_webhook`
4. Copy **Callback Token** dan simpan di `.env`

---

## 📦 Dependencies

```
Flask>=3.0.0
Werkzeug>=3.0.0
xendit-python>=3.0.0
python-dotenv>=1.0.0
```

---

## 🚀 Deploy ke Production

### Gunicorn + Nginx (disarankan)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Variabel Environment Production

```env
SECRET_KEY=random_string_sangat_panjang
XENDIT_SECRET_KEY=xnd_production_...
DEBUG=False
BASE_URL=https://domainmu.com
```

---

## 📄 Lisensi

MIT License — bebas digunakan dan dimodifikasi.

---

<p align="center">Made with ❤️ — <strong>Socrow</strong></p>
