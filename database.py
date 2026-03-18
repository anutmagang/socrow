import sqlite3

def init_db():
    conn = sqlite3.connect('sosmed_rekber.db')
    c = conn.cursor()

    tables = [
        'users', 'posts', 'post_images', 'comments', 'likes',
        'rekber_rooms', 'messages', 'message_files',
        'notifications', 'platform_stats',
        'withdrawals', 'disputes', 'dispute_evidence',
        'ratings', 'affiliates', 'affiliate_logs',
        'shipment_tracking', 'blacklist', 'audit_logs'
    ]
    for t in tables:
        c.execute(f'DROP TABLE IF EXISTS {t}')

    c.execute('''CREATE TABLE platform_stats (
        id INTEGER PRIMARY KEY,
        total_revenue REAL DEFAULT 0.0,
        total_transactions INTEGER DEFAULT 0,
        total_users INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute("INSERT INTO platform_stats VALUES (1, 0.0, 0, 0, CURRENT_TIMESTAMP)")

    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password TEXT NOT NULL,
        saldo REAL DEFAULT 0.0,
        saldo_afiliasi REAL DEFAULT 0.0,
        account_type TEXT DEFAULT 'individu',
        kyc_name TEXT,
        store_name TEXT,
        bank_name TEXT,
        bank_account TEXT,
        kyc_status TEXT DEFAULT 'none',
        file_ktp TEXT,
        file_selfie TEXT,
        total_sales INTEGER DEFAULT 0,
        rating_avg REAL DEFAULT 0.0,
        rating_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        is_banned INTEGER DEFAULT 0,
        ban_reason TEXT,
        referral_code TEXT UNIQUE,
        referred_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(referred_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_type TEXT DEFAULT 'text',
        product_category TEXT DEFAULT 'umum',
        product_kind TEXT DEFAULT 'fisik',
        media_url TEXT DEFAULT '',
        caption TEXT NOT NULL,
        is_for_sale INTEGER DEFAULT 0,
        price REAL DEFAULT 0,
        stock INTEGER DEFAULT 0,
        weight_gram INTEGER DEFAULT 0,
        digital_file TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE post_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        image_url TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        FOREIGN KEY(post_id) REFERENCES posts(id)
    )''')

    c.execute('''CREATE TABLE rekber_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        buyer_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        status TEXT DEFAULT 'menunggu_pembayaran',
        price_deal REAL NOT NULL,
        xendit_id TEXT UNIQUE,
        payment_method TEXT,
        resi_number TEXT,
        courier_name TEXT,
        auto_release_at TIMESTAMP,
        affiliate_code TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(buyer_id) REFERENCES users(id),
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        sender_id INTEGER,
        message_text TEXT NOT NULL,
        message_type TEXT DEFAULT 'text',
        file_url TEXT,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    c.execute('''CREATE TABLE notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        notif_type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        link TEXT DEFAULT '/',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        fee REAL DEFAULT 2500,
        net_amount REAL NOT NULL,
        bank_name TEXT NOT NULL,
        bank_account TEXT NOT NULL,
        account_name TEXT NOT NULL,
        source TEXT DEFAULT 'saldo',
        status TEXT DEFAULT 'pending',
        admin_note TEXT,
        processed_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE disputes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL UNIQUE,
        opened_by INTEGER NOT NULL,
        reason TEXT NOT NULL,
        detail TEXT,
        status TEXT DEFAULT 'open',
        verdict TEXT,
        verdict_note TEXT,
        resolved_by INTEGER,
        deadline TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id),
        FOREIGN KEY(opened_by) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE dispute_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dispute_id INTEGER NOT NULL,
        uploaded_by INTEGER NOT NULL,
        file_url TEXT NOT NULL,
        file_type TEXT DEFAULT 'image',
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(dispute_id) REFERENCES disputes(id)
    )''')

    c.execute('''CREATE TABLE ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL UNIQUE,
        reviewer_id INTEGER NOT NULL,
        reviewed_id INTEGER NOT NULL,
        score INTEGER NOT NULL CHECK(score BETWEEN 1 AND 5),
        review_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    c.execute('''CREATE TABLE affiliates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        code TEXT NOT NULL UNIQUE,
        total_referred INTEGER DEFAULT 0,
        total_earned REAL DEFAULT 0.0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE affiliate_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        affiliate_id INTEGER NOT NULL,
        room_id INTEGER NOT NULL,
        transaction_amount REAL NOT NULL,
        commission REAL NOT NULL,
        status TEXT DEFAULT 'pending',
        paid_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(affiliate_id) REFERENCES affiliates(id)
    )''')

    c.execute('''CREATE TABLE shipment_tracking (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        courier TEXT NOT NULL,
        resi TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        last_status_text TEXT,
        estimated_arrival TEXT,
        last_checked TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    c.execute('''CREATE TABLE blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        reason TEXT,
        added_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        detail TEXT,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(post_id, user_id)
    )''')

    c.execute('''CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    for idx in [
        'CREATE INDEX idx_posts_user ON posts(user_id)',
        'CREATE INDEX idx_posts_sale ON posts(is_for_sale)',
        'CREATE INDEX idx_rooms_buyer ON rekber_rooms(buyer_id)',
        'CREATE INDEX idx_rooms_seller ON rekber_rooms(seller_id)',
        'CREATE INDEX idx_rooms_status ON rekber_rooms(status)',
        'CREATE INDEX idx_messages_room ON messages(room_id)',
        'CREATE INDEX idx_notif_user ON notifications(user_id, is_read)',
        'CREATE INDEX idx_withdrawals_user ON withdrawals(user_id)',
        'CREATE INDEX idx_disputes_room ON disputes(room_id)',
        'CREATE INDEX idx_ratings_reviewed ON ratings(reviewed_id)',
        'CREATE INDEX idx_affiliate_code ON affiliates(code)',
    ]:
        c.execute(idx)

    conn.commit()
    conn.close()
    print("✅ Database Socrow v2 berhasil!")
    print("⚡ Jalankan: python seed.py untuk akun demo")

if __name__ == '__main__':
    init_db()
