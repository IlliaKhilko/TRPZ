import sqlite3

class DatabaseManager:
    def __init__(self, database_factory):
        self.database_factory = database_factory
        self.conn = None
        self.cursor = None

    def __enter__(self):
        self.conn = self.database_factory.create_connection()
        self.cursor = self.database_factory.create_cursor(self.conn)
        return self.cursor

    def __exit__(self, exc_type, exc_value, traceback):
        if self.conn:
            self.conn.commit()
            self.conn.close()


def main():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            group_id INTEGER PRIMARY KEY,
            group_name TEXT NOT NULL,
            creator_id INTEGER,
            FOREIGN KEY (creator_id) REFERENCES users(user_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            item_id INTEGER PRIMARY KEY,
            item_name TEXT NOT NULL,
            estimated_price REAL,
            purchased_price REAL,  
            receipt_path TEXT,      
            group_id INTEGER,
            assigned_username TEXT,
            FOREIGN KEY (group_id) REFERENCES groups(group_id)
        )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS wishlists (
        wishlist_id INTEGER PRIMARY KEY,
        wishlist_name TEXT NOT NULL,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS wishlist_visibility (
        wishlist_id INTEGER,
        friend_id INTEGER,
        PRIMARY KEY (wishlist_id, friend_id),
        FOREIGN KEY (wishlist_id) REFERENCES wishlists(wishlist_id),
        FOREIGN KEY (friend_id) REFERENCES users(user_id)
    )
    ''')


    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wishlist_items (
            wishlist_item_id INTEGER PRIMARY KEY,
            wishlist_id INTEGER,
            item_name TEXT NOT NULL,
            estimated_price REAL,
            FOREIGN KEY (wishlist_id) REFERENCES wishlists(wishlist_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(group_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS friends (
        user_id INTEGER,
        friend_id INTEGER,
        PRIMARY KEY (user_id, friend_id),
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (friend_id) REFERENCES users(user_id)
    )
    ''')

    conn.commit()
    conn.close()