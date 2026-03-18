import sqlite3

def init_db():
    conn = sqlite3.connect('sosmed_rekber.db')
    cursor = conn.cursor()

    tables = ['users', 'posts', 'comments', 'likes', 'rekber_rooms',
              'messages', 'notifications', 'platform_stats']
    for t in tables:
        cursor.execute(f'DROP TABLE IF EXISTS {t}')

    # Platform Stats
    cursor.execute('''CREATE TABLE platform_stats (
        id INTEGER PRIMARY KEY,
        total_revenue REAL DEFAULT 0.0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute("INSERT INTO platform_stats (id, total_revenue) VALUES (1, 0.0)")

    # Users — password sekarang HASHED
    cursor.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password TEXT NOT NULL,
        saldo REAL DEFAULT 0.0,
        account_type TEXT DEFAULT 'individu',
        kyc_name TEXT,
        store_name TEXT,
        bank_name TEXT,
        bank_account TEXT,
        kyc_status TEXT DEFAULT 'none',
        file_ktp TEXT,
        file_selfie TEXT,
        total_sales INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # Posts
    cursor.execute('''CREATE TABLE posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_type TEXT DEFAULT 'text',
        media_url TEXT DEFAULT '',
        caption TEXT NOT NULL,
        is_for_sale INTEGER DEFAULT 0,
        price REAL DEFAULT 0,
        stock INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Rekber Rooms
    cursor.execute('''CREATE TABLE rekber_rooms (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        buyer_id INTEGER NOT NULL,
        seller_id INTEGER NOT NULL,
        status TEXT DEFAULT 'menunggu_pembayaran',
        price_deal REAL NOT NULL,
        xendit_id TEXT UNIQUE,
        rating INTEGER DEFAULT 0,
        review_text TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(buyer_id) REFERENCES users(id),
        FOREIGN KEY(seller_id) REFERENCES users(id)
    )''')

    # Messages
    cursor.execute('''CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id INTEGER NOT NULL,
        sender_id INTEGER,
        message_text TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(room_id) REFERENCES rekber_rooms(id)
    )''')

    # Notifications
    cursor.execute('''CREATE TABLE notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        link TEXT DEFAULT '/',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Likes
    cursor.execute('''CREATE TABLE likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(post_id, user_id),
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Comments
    cursor.execute('''CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')

    # Index untuk performa
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rooms_buyer ON rekber_rooms(buyer_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rooms_seller ON rekber_rooms(seller_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id)')

    conn.commit()
    conn.close()
    print("✅ Database Socrow berhasil dibangun!")
    print("⚠️  PENTING: Jalankan app.py — password sekarang menggunakan hash bcrypt.")

if __name__ == '__main__':
    init_db()
