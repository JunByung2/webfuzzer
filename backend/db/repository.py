from datetime import datetime
from backend.db.connection import get_server_connection, get_connection, ensure_database_exists


def init_db():
    ensure_database_exists()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    target_url VARCHAR(2083) NOT NULL,
                    start_time DATETIME,
                    end_time DATETIME,
                    duration DOUBLE,
                    page_count INT,
                    status VARCHAR(32),
                    scan_type VARCHAR(50),
                    progress INT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
        conn.commit()
    finally:
        conn.close()


def get_dashboard_metrics() -> dict:
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            # 총 스캔 수
            cursor.execute("SELECT COUNT(*) AS total_scans FROM scans")
            row = cursor.fetchone()
            total_scans = row['total_scans'] if row else 0

            # 최근 스캔일
            cursor.execute("SELECT MAX(created_at) AS recent FROM scans")
            row = cursor.fetchone()
            recent_raw = row['recent'] if row else None
            recent_scan_date = recent_raw.strftime('%Y-%m-%d') if recent_raw else None

            # 오늘 스캔 수
            cursor.execute("SELECT COUNT(*) AS cnt FROM scans WHERE DATE(created_at) = CURDATE()")
            row = cursor.fetchone()
            today_scan_count = row['cnt'] if row else 0

            # 심각도 분포 (results 테이블)
            cursor.execute("SELECT severity, COUNT(*) AS cnt FROM results WHERE severity IS NOT NULL GROUP BY severity")
            severity_counts = {r['severity']: r['cnt'] for r in cursor.fetchall()}

            # 취약점 유형 분포 (results 테이블)
            cursor.execute("SELECT vulnerability AS vuln_type, COUNT(*) AS cnt FROM results WHERE vulnerability IS NOT NULL GROUP BY vulnerability")
            vuln_type_counts = {r['vuln_type']: r['cnt'] for r in cursor.fetchall()}

            # 최근 30일 추이
            cursor.execute("""
                SELECT DATE(created_at) AS day, COUNT(*) AS cnt
                FROM scans
                WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
                GROUP BY DATE(created_at)
                ORDER BY day ASC
            """)
            trend_data = [
                {
                    'day': r['day'].strftime('%m-%d') if r['day'] else '',
                    'count': r['cnt']
                }
                for r in cursor.fetchall()
            ]

        return {
            'total_scans': total_scans,
            'recent_scan_date': recent_scan_date,
            'today_scan_count': today_scan_count,
            'severity_counts': severity_counts,
            'vuln_type_counts': vuln_type_counts,
            'trend_data': trend_data,
        }
    finally:
        conn.close()


def get_latest_scan_result() -> dict | None:
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 1")
            scan = cursor.fetchone()
            if not scan:
                return None

            cursor.execute("SELECT * FROM results WHERE scan_id = %s ORDER BY id ASC", (scan['id'],))
            vuln_rows = cursor.fetchall()

            for v in vuln_rows:
                if v.get('scanned_at'):
                    v['scanned_at'] = str(v['scanned_at'])

        return {
            'scan': {
                'id': scan['id'],
                'target_url': scan['target_url'],
                'start_time': str(scan['start_time']) if scan.get('start_time') else None,
                'end_time': str(scan['end_time']) if scan.get('end_time') else None,
                'duration': scan.get('duration'),
                'page_count': scan.get('page_count'),
                'status': scan.get('status'),
            },
            'results': [
                {
                    'severity': v.get('severity'),
                    'vuln_type': v.get('vulnerability'),
                    'evidence': v.get('evidence'),
                    'url': v.get('url'),
                    'parameter': v.get('parameter'),
                    'payload': v.get('payload'),
                    'source': v.get('source'),
                    'scanned_at': v.get('scanned_at'),
                }
                for v in vuln_rows
            ],
        }
    finally:
        conn.close()