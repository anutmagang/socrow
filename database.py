import sqlite3
import os

def init_db(force=False):
    db_path = 'sosmed_rekber.db'
    if force and os.path.exists(db_path):
        os.remove(db_path)
        print("Database lama dihapus.")

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password TEXT NOT NULL,
        bio TEXT,
        avatar_url TEXT,
        cover_url TEXT,
        website TEXT,
        kyc_status TEXT DEFAULT 'none', -- none, pending, verified
        kyc_name TEXT,
        bank_name TEXT,
        bank_account TEXT,
        saldo REAL DEFAULT 0,
        saldo_afiliasi REAL DEFAULT 0,
        total_sales INTEGER DEFAULT 0,
        referral_code TEXT UNIQUE,
        referred_by INTEGER,
        last_seen TIMESTAMP,
        is_active INTEGER DEFAULT 1,
        is_banned INTEGER DEFAULT 0,
        otp_code TEXT,
        otp_expiry TIMESTAMP,
        rating_avg REAL DEFAULT 0,
        rating_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        post_type TEXT DEFAULT 'image', -- text, image, video
        product_category TEXT, -- elektronik, fashion, dll
        product_kind TEXT, -- fisik, digital
        media_url TEXT,
        caption TEXT,
        is_for_sale INTEGER DEFAULT 0,
        price REAL DEFAULT 0,
        stock INTEGER DEFAULT 1,
        weight_gram INTEGER DEFAULT 0,
        digital_file TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS post_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        image_url TEXT NOT NULL,
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS rekber_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        xendit_id TEXT UNIQUE,
        affiliate_code TEXT,
        buyer_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        price_deal REAL NOT NULL,
        status TEXT DEFAULT 'menunggu_pembayaran', -- menunggu_pembayaran, dibayar, dikirim, sampai, komplain, selesai
        payment_method TEXT,
        resi_number TEXT,
        courier_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(buyer_id) REFERENCES users(id),
        FOREIGN KEY(seller_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS chat_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE NOT NULL,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        last_message TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user1_id) REFERENCES users(id),
        FOREIGN KEY(user2_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        message_text TEXT,
        file_url TEXT,
        message_type TEXT DEFAULT 'text',
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES chat_rooms(id),
        FOREIGN KEY(sender_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,
        followed_id INTEGER NOT NULL,
        UNIQUE(follower_id, followed_id),
        FOREIGN KEY(follower_id) REFERENCES users(id),
        FOREIGN KEY(followed_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT,
        message TEXT,
        link TEXT,
        type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        media_url TEXT NOT NULL,
        media_type TEXT DEFAULT 'image',
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        detail TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        quantity INTEGER DEFAULT 1,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS wishlists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS affiliates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT UNIQUE NOT NULL,
        is_active INTEGER DEFAULT 1,
        total_referred INTEGER DEFAULT 0,
        total_earned REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS affiliate_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        affiliate_id INTEGER NOT NULL,
        room_id INTEGER NOT NULL,
        transaction_amount REAL NOT NULL,
        commission REAL NOT NULL,
        status TEXT DEFAULT 'paid',
        paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(affiliate_id) REFERENCES affiliates(id),
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        message_text TEXT,
        message_type TEXT DEFAULT 'text',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id),
        FOREIGN KEY(sender_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        reviewer_id INTEGER NOT NULL,
        reviewed_id INTEGER NOT NULL,
        score INTEGER NOT NULL,
        review_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id),
        FOREIGN KEY(reviewer_id) REFERENCES users(id),
        FOREIGN KEY(reviewed_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS vouchers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        discount_amount REAL NOT NULL,
        min_purchase REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(seller_id, code),
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        fee REAL NOT NULL,
        net_amount REAL NOT NULL,
        bank_name TEXT,
        bank_account TEXT,
        account_name TEXT,
        source TEXT DEFAULT 'saldo',
        status TEXT DEFAULT 'pending',
        admin_note TEXT,
        processed_by INTEGER,
        processed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(processed_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        reason TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(reporter_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS disputes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        opened_by INTEGER NOT NULL,
        reason TEXT NOT NULL,
        detail TEXT,
        status TEXT DEFAULT 'open',
        deadline TIMESTAMP,
        verdict TEXT,
        verdict_note TEXT,
        resolved_by INTEGER,
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id),
        FOREIGN KEY(opened_by) REFERENCES users(id),
        FOREIGN KEY(resolved_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS dispute_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dispute_id INTEGER NOT NULL,
        uploaded_by INTEGER NOT NULL,
        file_url TEXT NOT NULL,
        file_type TEXT,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(dispute_id) REFERENCES disputes(id),
        FOREIGN KEY(uploaded_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS shipment_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        courier TEXT,
        resi TEXT,
        status TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS platform_stats (
        id INTEGER PRIMARY KEY,
        total_revenue REAL DEFAULT 0,
        total_transactions INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute("INSERT OR IGNORE INTO platform_stats(id,total_revenue,total_transactions,total_users) VALUES(1,0,0,0)")

    conn.commit()
    conn.close()
    print("Database Berhasil Diinisialisasi.")

if __name__ == '__main__':
    import sys
    force = '--force' in sys.argv
    init_db(force=force)
