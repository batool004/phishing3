# threat_db.py - Thread-safe database for multi-threading support + Global Threat Network

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

        # ============= NEW: Global Threats Tables =============
        self._create_global_threats_table(cursor)
        self._create_reporter_reputation_table(cursor)
        # ======================================================

        conn.commit()

    def _create_global_threats_table(self, cursor):
        """Create global threats table for crowdsourced intelligence"""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS global_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_score INTEGER DEFAULT 0,
                reports_count INTEGER DEFAULT 0,
                trusted_reports INTEGER DEFAULT 0,
                status TEXT DEFAULT 'pending',
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                verified_by_ml BOOLEAN DEFAULT FALSE
            )
        ''')

    def _create_reporter_reputation_table(self, cursor):
        """Create reporter reputation table for anti-abuse"""
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reporter_reputation (
                user_id TEXT PRIMARY KEY,
                reputation_score INTEGER DEFAULT 0,
                total_reports INTEGER DEFAULT 0,
                accurate_reports INTEGER DEFAULT 0,
                false_reports INTEGER DEFAULT 0,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

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

    # ============= GLOBAL THREAT NETWORK METHODS =============

    def get_reporter_reputation(self, user_id):
        """Get reporter reputation score"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT reputation_score, total_reports, accurate_reports, false_reports 
            FROM reporter_reputation WHERE user_id = ?
        ''', (user_id,))
        result = cursor.fetchone()
        
        if result:
            return {
                'reputation_score': result[0],
                'total_reports': result[1],
                'accurate_reports': result[2],
                'false_reports': result[3]
            }
        return {'reputation_score': 0, 'total_reports': 0, 'accurate_reports': 0, 'false_reports': 0}

    def update_reporter_reputation(self, user_id, was_accurate):
        """Update reporter reputation after verification"""
        current = self.get_reporter_reputation(user_id)
        
        if was_accurate:
            new_score = min(100, current['reputation_score'] + 10)
            accurate = current['accurate_reports'] + 1
            false = current['false_reports']
        else:
            new_score = max(-50, current['reputation_score'] - 20)
            accurate = current['accurate_reports']
            false = current['false_reports'] + 1
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO reporter_reputation 
            (user_id, reputation_score, total_reports, accurate_reports, false_reports, last_active)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user_id, new_score, current['total_reports'] + 1, accurate, false))
        conn.commit()

    def add_global_threat(self, url, url_hash, domain, threat_score, user_id, ml_score=0):
        """Add a new threat to the global network"""
        from datetime import datetime, timedelta
        
        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.now()
        expires_at = now + timedelta(days=7)
        
        # Calculate weight based on reporter reputation
        reputation = self.get_reporter_reputation(user_id)
        report_weight = 1 if reputation['reputation_score'] > 50 else 0.5
        trusted_reports = 1 if report_weight == 1 else 0
        
        cursor.execute('''
            INSERT INTO global_threats 
            (url_hash, url, domain, threat_score, reports_count, trusted_reports, 
             status, first_detected, last_updated, expires_at, verified_by_ml)
            VALUES (?, ?, ?, ?, 1, ?, 'pending', ?, ?, ?, ?)
        ''', (url_hash, url, domain, threat_score, trusted_reports, now, now, expires_at, ml_score > 70))
        
        conn.commit()
        return self.get_threat_by_hash(url_hash)

    def increment_report_count(self, url_hash, report_weight=0.5):
        """Increment report count for an existing threat"""
        conn = self.get_connection()
        cursor = conn.cursor()
        trusted_increment = 1 if report_weight == 1 else 0
        
        cursor.execute('''
            UPDATE global_threats 
            SET reports_count = reports_count + 1,
                trusted_reports = trusted_reports + ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE url_hash = ?
        ''', (trusted_increment, url_hash))
        conn.commit()

    def confirm_threat(self, url_hash):
        """Confirm a threat after reaching threshold"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE global_threats 
            SET status = 'confirmed',
                threat_score = CASE 
                    WHEN threat_score < 80 THEN 80 
                    ELSE threat_score 
                END
            WHERE url_hash = ?
        ''', (url_hash,))
        conn.commit()

    def get_threat_by_hash(self, url_hash):
        """Get threat by URL hash"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM global_threats WHERE url_hash = ?', (url_hash,))
        result = cursor.fetchone()
        
        if result:
            columns = ['id', 'url_hash', 'url', 'domain', 'threat_score', 'reports_count', 
                       'trusted_reports', 'status', 'first_detected', 'last_updated', 'expires_at', 'verified_by_ml']
            return dict(zip(columns, result))
        return None

    def get_active_threat_by_hash(self, url_hash):
        """Get active threat (not expired)"""
        from datetime import datetime
        
        threat = self.get_threat_by_hash(url_hash)
        if threat and threat['status'] == 'confirmed' and threat['expires_at'] > datetime.now():
            return threat
        return None

    def get_recent_global_threats(self, limit=10):
        """Get recent confirmed global threats"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT url, threat_score, reports_count, trusted_reports, first_detected
            FROM global_threats 
            WHERE status = 'confirmed'
            ORDER BY threat_score DESC, first_detected DESC
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        return [{'url': r[0], 'threat_score': r[1], 'reports_count': r[2], 
                 'trusted_reports': r[3], 'first_detected': r[4]} for r in results]

    def cleanup_expired_threats(self):
        """Delete expired threats"""
        from datetime import datetime
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM global_threats WHERE expires_at < ? AND status = "confirmed"', (datetime.now(),))
        deleted = cursor.rowcount
        conn.commit()
        return deleted

    def close(self):
        """Close the database connection (for current thread)"""
        if hasattr(self.local, 'connection'):
            self.local.connection.close()


# Initialize database on import
threat_db = ThreatDatabase()


if __name__ == "__main__":
    print("✅ Database is ready (multi-threading compatible + Global Threat Network)!")
    stats = threat_db.get_stats()
    print(f"📊 Stats: {stats}")