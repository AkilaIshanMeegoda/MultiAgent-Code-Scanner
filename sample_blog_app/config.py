"""
sample_blog_app/config.py
Application configuration — hardcoded secrets and insecure defaults.
"""

import os

# ─── SECURITY ISSUE: secrets hardcoded in source — should use env vars ────────
DATABASE_URL      = "sqlite:///blog.db"
SECRET_KEY        = "blog-app-secret-key-2024"
JWT_SECRET        = "jwt-super-secret"
SMTP_PASSWORD     = "smtp_password_plain_text"
AWS_ACCESS_KEY    = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ─── SECURITY ISSUE: debug mode enabled by default ────────────────────────────
DEBUG             = True
TESTING           = False

# ─── SECURITY ISSUE: CORS allows all origins ──────────────────────────────────
CORS_ORIGINS      = "*"

# ─── SECURITY ISSUE: no HTTPS enforcement ────────────────────────────────────
FORCE_HTTPS       = False

# ─── SECURITY ISSUE: overly permissive upload settings ───────────────────────
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif",
                       "php", "py", "sh", "exe", "bat"}   # dangerous extensions
MAX_CONTENT_LENGTH = None   # no upload size limit

# ─── SECURITY ISSUE: session cookies not secured ─────────────────────────────
SESSION_COOKIE_SECURE   = False
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None

# ─── OPTIMISATION ISSUE: tiny connection pool will bottleneck under load ───────
DB_POOL_SIZE    = 1
DB_MAX_OVERFLOW = 0

# ─── BUG: LOG_LEVEL string never validated — invalid values silently ignored ───
LOG_LEVEL = os.environ.get("LOG_LEVEL", "VERBOSE")   # not a valid logging level
