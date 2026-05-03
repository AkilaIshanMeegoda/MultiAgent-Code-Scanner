"""
sample_blog_app/app.py
Flask blog application — intentionally contains security, bug, and optimisation issues.
"""

import sqlite3
import os
import hashlib
from flask import Flask, request, render_template_string, redirect, session, jsonify

app = Flask(__name__)

# ─── SECURITY ISSUE: hardcoded secret key ────────────────────────────────────
app.secret_key = "supersecret123"

# ─── SECURITY ISSUE: hardcoded admin credentials ─────────────────────────────
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

DB_PATH = "blog.db"


def get_db():
    return sqlite3.connect(DB_PATH)


# ─── SECURITY ISSUE: SQL injection ────────────────────────────────────────────
@app.route("/search")
def search_posts():
    query = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # Vulnerable: user input directly concatenated into SQL
    sql = "SELECT id, title, body FROM posts WHERE title LIKE '%" + query + "%'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.close()

    # ─── SECURITY ISSUE: reflected XSS ────────────────────────────────────────
    template = f"""
    <html><body>
    <h1>Search results for: {query}</h1>
    <ul>
    """ + "".join(f"<li>{r[1]}: {r[2][:80]}</li>" for r in rows) + """
    </ul></body></html>
    """
    return render_template_string(template)


# ─── SECURITY ISSUE: no CSRF protection on login ──────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # ─── SECURITY ISSUE: timing-unsafe string comparison ──────────────────
        if username == ADMIN_USER and password == ADMIN_PASS:
            session["user"] = username
            return redirect("/admin")
    return """
    <form method="POST">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login">
    </form>
    """


# ─── SECURITY ISSUE: no authentication check on admin route ───────────────────
@app.route("/admin")
def admin_panel():
    # BUG: session is never verified
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    conn.close()
    return jsonify(posts)


# ─── SECURITY ISSUE: insecure file upload (no type/size check) ────────────────
UPLOAD_FOLDER = "/tmp/uploads"

@app.route("/upload", methods=["POST"])
def upload_file():
    f = request.files.get("file")
    if f:
        # Allows uploading .py, .sh, .php — anything
        dest = os.path.join(UPLOAD_FOLDER, f.filename)  # path traversal risk
        f.save(dest)
        return f"Uploaded to {dest}"
    return "No file", 400


# ─── OPTIMISATION ISSUE: N+1 query pattern ────────────────────────────────────
@app.route("/feed")
def feed():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, author_id FROM posts")
    posts = cursor.fetchall()

    result = []
    for post_id, author_id in posts:
        # One extra query per post — should JOIN instead
        cursor.execute("SELECT name FROM users WHERE id = ?", (author_id,))
        author = cursor.fetchone()
        result.append({"post_id": post_id, "author": author[0] if author else "unknown"})

    conn.close()
    return jsonify(result)


# ─── OPTIMISATION ISSUE: loading entire table to count rows ───────────────────
@app.route("/stats")
def stats():
    conn = get_db()
    cursor = conn.cursor()
    # Loads all rows into memory just to count them
    cursor.execute("SELECT * FROM posts")
    posts = cursor.fetchall()
    count = len(posts)
    conn.close()
    return jsonify({"total_posts": count})


# ─── BUG: password hash uses MD5 (weak) and ignores salt ──────────────────────
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# ─── BUG: mutable default argument ────────────────────────────────────────────
def build_tag_list(tags, result=[]):
    for tag in tags:
        result.append(tag.strip().lower())
    return result


# ─── BUG: bare except swallows all errors silently ────────────────────────────
@app.route("/post/<int:post_id>")
def view_post(post_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT title, body FROM posts WHERE id = ?", (post_id,))
        post = cursor.fetchone()
        conn.close()
        if post is None:
            return "Not found", 404
        return jsonify({"title": post[0], "body": post[1]})
    except:  # noqa: E722  — catches KeyboardInterrupt, SystemExit, etc.
        return "Error", 500


# ─── BUG: comparing strings with `is` instead of == ──────────────────────────
@app.route("/role")
def check_role():
    role = request.args.get("role", "")
    if role is "admin":           # identity check, not equality
        return "Admin access"
    return "Regular access"


# ─── OPTIMISATION ISSUE: repeated expensive computation in loop ────────────────
@app.route("/leaderboard")
def leaderboard():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT author_id, body FROM posts")
    rows = cursor.fetchall()
    conn.close()

    scores = {}
    for author_id, body in rows:
        # len(body) called on every iteration; score re-sorted each time
        word_count = len(body.split())
        if author_id not in scores:
            scores[author_id] = 0
        scores[author_id] += word_count

    # O(n log n) sort inside a loop that could be a one-liner
    sorted_scores = []
    for k in scores:
        sorted_scores.append((k, scores[k]))
    sorted_scores.sort(key=lambda x: x[1], reverse=True)

    return jsonify(sorted_scores[:10])


if __name__ == "__main__":
    # ─── SECURITY ISSUE: debug=True exposes interactive debugger ──────────────
    app.run(debug=True, host="0.0.0.0", port=5000)
