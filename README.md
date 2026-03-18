# 🛡️ Socrow v2.0 — Platform Sosial Rekber

> Platform sosial media dengan sistem rekening bersama (rekber), afiliasi, dispute mediasi, dan withdrawal terintegrasi.

---

## ✨ Fitur Phase 1 (v2.0)

| Fitur | Status |
|-------|--------|
| 🔒 Rekber otomatis | ✅ |
| 💸 Withdrawal saldo penjualan | ✅ |
| 🤝 Program afiliasi (fee-share 0.5%) | ✅ |
| ⚖️ Dispute room + mediasi admin | ✅ |
| 📸 Upload bukti sengketa | ✅ |
| ⭐ Rating & review penjual | ✅ |
| 📦 Produk fisik (resi) & digital (file) | ✅ |
| 📂 Download file digital setelah transaksi | ✅ |
| 👑 Panel admin: KYC, dispute, withdrawal | ✅ |
| 🔔 Notifikasi real-time | ✅ |
| 📊 Audit log semua aksi | ✅ |
| 🛡️ Mode demo tanpa Xendit | ✅ |

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Init database
python database.py

# 3. Buat akun demo
python seed.py

# 4. Konfigurasi .env
cp .env.example .env
# Edit .env: ADMIN_EMAIL=admin@socrow.com

# 5. Jalankan
python app.py
```

Buka: **http://127.0.0.1:5000**

---

## 🔑 Akun Demo

| Username | Email | Password | Role |
|----------|-------|----------|------|
| admin | admin@socrow.com | admin123 | Admin |
| penjual | penjual@socrow.com | penjual123 | Penjual |
| pembeli | pembeli@socrow.com | pembeli123 | Pembeli |

---

## 💡 Alur Afiliasi

```
Fee normal Socrow = 2% dari transaksi

Dengan afiliasi:
  → Platform dapat: 1.5%
  → Afiliator dapat: 0.5% → masuk saldo_afiliasi
  → Bisa ditarik min Rp 10.000
```

**Tidak ada modal keluar** — platform hanya berbagi sebagian fee yang sudah diterima.

---

## ⚖️ Alur Dispute

```
1. Pembeli klik "Komplain" → status = 'komplain'
2. Kedua pihak upload bukti di dispute room
3. Admin tinjau dalam 24 jam
4. Admin putuskan: buyer / seller / split 50-50
5. Dana disalurkan otomatis sesuai keputusan
```

---

## 💸 Alur Withdrawal

```
1. Penjual ajukan withdrawal (min Rp 50.000)
2. Biaya admin Rp 2.500 dipotong
3. Admin approve → dana ditransfer manual
4. Jika ditolak → saldo dikembalikan otomatis
```

---

## 🗂️ Struktur Project

```
sosmed-rekber-v2/
├── app.py                    # Backend Flask (semua route)
├── database.py               # Schema database v2
├── seed.py                   # Akun demo
├── requirements.txt
├── .env.example
├── static/
│   ├── style.css
│   └── uploads/
│       ├── digital/          # File produk digital (private)
│       └── evidence/         # Bukti dispute
└── templates/
    ├── base.html             # Layout + navbar
    ├── index.html            # Feed utama
    ├── login.html / daftar.html
    ├── dasbor.html           # Dashboard transaksi
    ├── ruang_rekber.html     # Chat + aksi transaksi
    ├── withdraw.html         # ✨ Penarikan saldo
    ├── afiliasi.html         # ✨ Program afiliasi
    ├── dispute_form.html     # ✨ Form komplain
    ├── dispute_detail.html   # ✨ Detail + bukti + verdict
    ├── admin_disputes.html   # ✨ Admin kelola dispute
    ├── admin_withdrawals.html# ✨ Admin kelola penarikan
    ├── admin_kyc.html        # Admin verifikasi KYC
    ├── akun.html             # Profil + KYC + password
    ├── notifikasi.html
    ├── demo_bayar.html       # Simulasi Xendit
    ├── syarat.html / tentang.html / error.html
```

---

## 🔐 Keamanan

- Password hashing (Werkzeug pbkdf2)
- Secret key dari environment
- `@login_required` & `@admin_required` decorator
- Validasi kepemilikan sebelum aksi (anti IDOR)
- File upload whitelist extension
- Audit log semua aksi penting
- File digital hanya bisa didownload pembeli setelah `status=selesai`
- Bukti dispute disimpan terpisah di `/uploads/evidence/`
