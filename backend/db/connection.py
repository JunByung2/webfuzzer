"""
db/connection.py
"""

import pymysql
from pymysql.cursors import DictCursor
from config.config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME


def get_server_connection():
    """DB 없이 MySQL 서버에만 연결 (DB 생성용)"""
    return pymysql.connect(
        host        = DB_HOST,
        port        = DB_PORT,
        user        = DB_USER,
        password    = DB_PASSWORD,
        charset     = "utf8mb4",
        cursorclass = DictCursor,
    )


def get_connection():
    """vulnerability_scanner DB에 연결"""
    return pymysql.connect(
        host        = DB_HOST,
        port        = DB_PORT,
        user        = DB_USER,
        password    = DB_PASSWORD,
        database    = DB_NAME,
        charset     = "utf8mb4",
        cursorclass = DictCursor,
        autocommit  = True,
    )


def ensure_database_exists():
    conn = get_server_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
                f"DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        conn.commit()
    finally:
        conn.close()