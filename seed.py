"""
seed.py — Buat akun demo untuk testing Socrow
Jalankan: python seed.py
"""
import os, secrets
import sqlite3, uuid
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('sosmed_rekber.db')
conn.row_factory = sqlite3.Row

admin_pw = os.environ.get('SEED_ADMIN_PASSWORD') or secrets.token_urlsafe(12)
seller_pw = os.environ.get('SEED_SELLER_PASSWORD') or secrets.token_urlsafe(12)
buyer_pw = os.environ.get('SEED_BUYER_PASSWORD') or secrets.token_urlsafe(12)

accounts = [
    ('admin',   'admin@socrow.com',   '081111111111', admin_pw,   'verified', 'ADMIN01'),
    ('penjual', 'penjual@socrow.com', '082222222222', seller_pw,  'verified', 'JUAL888'),
    ('pembeli', 'pembeli@socrow.com', '083333333333', buyer_pw,   'none',     'BELI999'),
]

for u in accounts:
    try:
        conn.execute("""INSERT INTO users(uuid,username,email,phone,password,kyc_status,referral_code,
                        kyc_name,bank_name,bank_account,store_name)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                     (str(uuid.uuid4()), u[0], u[1], u[2], generate_password_hash(u[3]), u[4], u[5],
                      u[0].upper(), 'BCA', f'12345678{accounts.index(u)}', f'Toko {u[0].title()}'))
        uid = conn.execute("SELECT id FROM users WHERE email=?",(u[1],)).fetchone()[0]
        conn.execute("INSERT OR IGNORE INTO affiliates(user_id,code) VALUES(?,?)",(uid, u[5]))
        print(f"{u[0]:10} | {u[1]:25} | password: {u[3]}")
    except sqlite3.IntegrityError as e:
        print(f"{u[0]} gagal dibuat: {e}")
    except sqlite3.Error as e:
        print(f"Database error saat membuat user {u[0]}: {e}")
    except Exception as e:
        print(f"Error tak terduga saat membuat user {u[0]}: {e}")

# Demo post produk fisik
try:
    seller = conn.execute("SELECT id FROM users WHERE username='penjual'").fetchone()
    if seller:
        conn.execute("""INSERT INTO posts(uuid,user_id,post_type,product_category,product_kind,
                        caption,is_for_sale,price,stock,weight_gram)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (str(uuid.uuid4()), seller['id'],'image','elektronik','fisik',
                      'HP Samsung Galaxy A55 5G - Mulus, Garansi Resmi, Lengkap Dus',
                      1, 4500000, 3, 200))
        conn.execute("""INSERT INTO posts(uuid,user_id,post_type,product_category,product_kind,
                        caption,is_for_sale,price,stock)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                     (str(uuid.uuid4()), seller['id'],'text','digital','digital',
                      'Template Website Toko Online - HTML/CSS/JS - Responsif - Siap Pakai',
                      1, 150000, 999))
        print("Demo posts dibuat")
except Exception as e:
    print(f"Posts: {e}")

conn.commit()
conn.close()

print("\n" + "="*50)
print("AKUN DEMO SOCROW")
print("="*50)
print(f"Admin  : admin@socrow.com    | {admin_pw}")
print(f"Penjual: penjual@socrow.com  | {seller_pw}")
print(f"Pembeli: pembeli@socrow.com  | {buyer_pw}")
print("="*50)
print("\nSet di .env:")
print("   ADMIN_EMAIL=admin@socrow.com")
print("\nJalankan: python app.py")
