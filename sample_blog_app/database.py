"""
sample_blog_app/database.py
Database helpers — contains SQL injection, resource leaks, and optimisation issues.
"""

import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "blog.db")


# ─── BUG: connection never closed (resource leak) ────────────────────────────
def get_connection():
    """Returns a raw connection — callers rarely close it."""
    return sqlite3.connect(DB_PATH)


def init_db():
    """Create tables. Runs on every import — should be idempotent but isn't guarded."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'viewer'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            author_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author_id INTEGER,
            body TEXT,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (author_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    # BUG: connection not closed here


# ─── SECURITY ISSUE: SQL injection via string formatting ─────────────────────
def find_user_by_email(email: str) -> dict | None:
    conn = get_connection()
    cursor = conn.cursor()
    # Vulnerable to SQL injection — should use parameterised query
    query = f"SELECT id, name, email, role FROM users WHERE email = '{email}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "email": row[2], "role": row[3]}
    return None


# ─── SECURITY ISSUE: SQL injection in search ─────────────────────────────────
def search_posts(keyword: str) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    # Vulnerable: keyword not sanitised
    sql = "SELECT id, title FROM posts WHERE title LIKE '%" + keyword + "%' " \
          "OR body LIKE '%" + keyword + "%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1]} for r in rows]


# ─── OPTIMISATION ISSUE: SELECT * + loading all rows to filter in Python ──────
def get_recent_posts(limit: int = 10) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    # Loads ALL posts then slices in Python — should use LIMIT in SQL
    cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
    all_posts = cursor.fetchall()
    conn.close()
    return all_posts[:limit]


# ─── OPTIMISATION ISSUE: no index on frequently queried column ───────────────
def get_posts_by_author(author_id: int) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    # author_id has no index — full table scan on large datasets
    cursor.execute("SELECT id, title FROM posts WHERE author_id = ?", (author_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1]} for r in rows]


# ─── BUG: delete_post doesn't check ownership — any user can delete any post ──
def delete_post(post_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()


# ─── OPTIMISATION ISSUE: inserting rows one-by-one instead of executemany ─────
def bulk_insert_tags(post_id: int, tags: list):
    conn = get_connection()
    cursor = conn.cursor()
    for tag in tags:
        # One INSERT per tag — should use executemany
        cursor.execute(
            "INSERT INTO post_tags (post_id, tag) VALUES (?, ?)", (post_id, tag)
        )
    conn.commit()
    conn.close()


# ─── BUG: integer overflow not guarded — vote_count can underflow ─────────────
def decrement_vote(post_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    # No check that vote_count > 0 before decrementing
    cursor.execute(
        "UPDATE posts SET vote_count = vote_count - 1 WHERE id = ?", (post_id,)
    )
    conn.commit()
    conn.close()
