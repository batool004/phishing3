# threat_db.py - Thread-safe database for multi-threading support

import sqlite3
from datetime import datetime
import threading


class ThreatDatabase:
    def __init__(self, db_path='threats.db'):
        self.db_path = db_path
        self.local = threading.local()
        self.create_tables()

    def get_connection(self):
        """Get a thread-local database connection"""
        if not hasattr(self.local, 'connection'):
            self.local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False
            )
            self.local.connection.row_factory = sqlite3.Row
        return self.local.connection

    def create_tables(self):
        """Create required database tables"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Threats table (malicious URLs)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                domain TEXT,
                threat_score INTEGER,
                reports_count INTEGER DEFAULT 1,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP
            )
        ''')

        # Scan logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                result TEXT,
                threat_score INTEGER,
                created_at TIMESTAMP
            )
        ''')

        conn.commit()

    def add_threat(self, url, threat_score):
        """Add a malicious URL to the database"""
        conn = self.get_connection()
        cursor = conn.cursor()

        try:
            domain = url.split('/')[2] if '://' in url else url.split('/')[0]
        except:
            domain = url

        now = datetime.now()

        try:
            cursor.execute('''
                INSERT INTO threats (url, domain, threat_score, reports_count, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?)
            ''', (url, domain, threat_score, now, now))

        except sqlite3.IntegrityError:
            # If URL already exists, update it
            cursor.execute('''
                UPDATE threats
                SET reports_count = reports_count + 1,
                    threat_score = (threat_score + ?) // 2,
                    last_seen = ?
                WHERE url = ?
            ''', (threat_score, now, url))

        conn.commit()

    def check_threat(self, url):
        """Check if a URL is already known as a threat"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            'SELECT threat_score, reports_count FROM threats WHERE url = ?',
            (url,)
        )
        result = cursor.fetchone()

        if result:
            return {
                'is_threat': True,
                'threat_score': result[0],
                'reports_count': result[1]
            }

        return {'is_threat': False}

    def add_scan(self, url, result, threat_score):
        """Log a new scan result"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scans (url, result, threat_score, created_at)
            VALUES (?, ?, ?, ?)
        ''', (url, result, threat_score, datetime.now()))

        conn.commit()

    def get_stats(self):
        """Retrieve general statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM threats')
        total_threats = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM scans WHERE result = "phishing"')
        phishing_count = cursor.fetchone()[0]

        return {
            'total_threats': total_threats,
            'total_scans': total_scans,
            'phishing_detected': phishing_count,
            'success_rate': (
                (phishing_count / total_scans * 100)
                if total_scans > 0 else 0
            )
        }

    def get_recent_threats(self, limit=10):
        """Get the most recently detected threats"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT url, threat_score, reports_count, last_seen
            FROM threats
            ORDER BY last_seen DESC
            LIMIT ?
        ''', (limit,))

        threats = []
        for row in cursor.fetchall():
            threats.append({
                'url': row[0],
                'threat_score': row[1],
                'reports_count': row[2],
                'last_seen': row[3]
            })

        return threats

    def close(self):
        """Close the database connection (for current thread)"""
        if hasattr(self.local, 'connection'):
            self.local.connection.close()


# Initialize database on import
threat_db = ThreatDatabase()


if __name__ == "__main__":
    print("✅ Database is ready (multi-threading compatible)!")
    stats = threat_db.get_stats()
    print(f"📊 Stats: {stats}")