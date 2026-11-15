
import os
import sqlite3
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import joblib
import firebase_admin

from firebase_admin import credentials, auth
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator


# ==========================================
# 1. CONFIGURATION
# ==========================================

MODEL_PATH = "model/phishguard_model.joblib"

FIREBASE_KEY_PATH = os.getenv(
    "FIREBASE_KEY_PATH",
    str(BASE_DIR / "firebase-service-account.json")
)

DATABASE_PATH = "phishguard.db"


# ==========================================
# 2. LOAD MACHINE LEARNING MODEL
# ==========================================

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("Trained model not found.")

model = joblib.load(MODEL_PATH)

classes = list(model.classes_)

if 1 not in classes:
    raise ValueError("Phishing class 1 is missing.")

phishing_index = classes.index(1)


# ==========================================
# 3. FIREBASE ADMIN INITIALIZATION
# ==========================================

if not os.path.exists(FIREBASE_KEY_PATH):
    raise FileNotFoundError(
        "Firebase service account JSON not found. "
        "Place firebase-service-account.json in the project root."
    )

if not firebase_admin._apps:
    firebase_credential = credentials.Certificate(
        FIREBASE_KEY_PATH
    )

    firebase_admin.initialize_app(firebase_credential)


# ==========================================
# 4. FASTAPI APPLICATION
# ==========================================

app = FastAPI(
    title="PhishGuard AI",
    description="AI-powered Phishing URL Detection System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ==========================================
# 5. SQLITE DATABASE
# ==========================================

def get_database():

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def create_database():

    connection = get_database()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_uid TEXT NOT NULL,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            risk_score REAL NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_scans_user
        ON scans(user_uid)
    """)

    connection.commit()
    connection.close()


create_database()


# ==========================================
# 6. FIREBASE TOKEN VERIFICATION
# ==========================================

def get_current_user(
    authorization: str = Header(default=None)
):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authentication token is required."
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format."
        )

    token = authorization.replace("Bearer ", "", 1)

    try:
        decoded_token = auth.verify_id_token(token)

        return {
            "uid": decoded_token["uid"],
            "email": decoded_token.get("email")
        }

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token."
        )


# ==========================================
# 7. URL REQUEST VALIDATION
# ==========================================

class URLRequest(BaseModel):

    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value):

        value = value.strip()

        if not value:
            raise ValueError("URL cannot be empty.")

        if len(value) > 10000:
            raise ValueError("URL is too long.")

        if not value.startswith(("http://", "https://")):
            value = "https://" + value

        parsed = urlparse(value)

        if not parsed.hostname:
            raise ValueError("Invalid URL.")

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are allowed.")

        return value


# ==========================================
# 8. DETECTION EXPLANATIONS
# ==========================================

def get_detection_reasons(url, risk_score):

    reasons = []

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if parsed.scheme != "https":
        reasons.append(
            "This URL does not use HTTPS encryption."
        )

    try:
        ipaddress.ip_address(hostname)

        reasons.append(
            "The website uses an IP address instead of a domain name."
        )

    except ValueError:
        pass

    suspicious_words = [
        "login", "verify", "password",
        "account", "secure", "update",
        "banking", "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        reasons.append(
            "Potentially sensitive keywords found: "
            + ", ".join(found_words)
        )

    if "@" in url:
        reasons.append(
            "URL contains an @ symbol, which can hide its destination."
        )

    if "xn--" in hostname.lower():
        reasons.append(
            "Domain contains encoded international characters."
        )

    if len(hostname.split(".")) >= 5:
        reasons.append(
            "Domain contains an unusually large number of subdomains."
        )

    if len(url) >= 200:
        reasons.append(
            "URL is unusually long and should be inspected carefully."
        )

    elif len(url) >= 100:
        reasons.append(
            "URL is relatively long."
        )

    if risk_score >= 80:
        reasons.append(
            "The ML model detected strong phishing-like URL patterns."
        )

    elif risk_score >= 50:
        reasons.append(
            "The ML model detected some suspicious URL patterns."
        )

    if not reasons:
        reasons.append(
            "No major suspicious URL patterns were identified."
        )

    return reasons


# ==========================================
# 9. SAVE SCAN IN SQLITE
# ==========================================

def save_scan(user_uid, url, prediction, risk_score):

    connection = get_database()

    scanned_at = datetime.now(
        timezone.utc
    ).isoformat()

    connection.execute(
        """
        INSERT INTO scans (
            user_uid,
            url,
            prediction,
            risk_score,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_uid,
            url,
            prediction,
            risk_score,
            scanned_at
        )
    )

    connection.commit()
    connection.close()


# ==========================================
# 10. HEALTH CHECK
# ==========================================

@app.get("/api/health")
def health_check():

    return {
        "status": "online",
        "application": "PhishGuard AI",
        "model_loaded": True,
        "database": "connected"
    }


# ==========================================
# 11. CURRENT USER
# ==========================================

@app.get("/api/me")
def current_user(user=Depends(get_current_user)):

    return {
        "success": True,
        "uid": user["uid"],
        "email": user["email"]
    }


# ==========================================
# 12. ANALYZE URL
# ==========================================

@app.post("/api/analyze")
def analyze_url(
    request: URLRequest,
    user=Depends(get_current_user)
):

    try:

        url = request.url

        probabilities = model.predict_proba([url])[0]

        phishing_probability = float(
            probabilities[phishing_index]
        )

        risk_score = round(
            phishing_probability * 100, 2
        )

        if risk_score >= 80:
            prediction = "Phishing"

        elif risk_score >= 50:
            prediction = "Suspicious"

        else:
            prediction = "Legitimate"

        reasons = get_detection_reasons(
            url,
            risk_score
        )

        # Save scan for authenticated user
        save_scan(
            user["uid"],
            url,
            prediction,
            risk_score
        )

        return {
            "success": True,
            "url": url,
            "prediction": prediction,
            "risk_score": risk_score,
            "reasons": reasons,
            "message": (
                "This URL may be dangerous. Avoid entering personal information."
                if prediction == "Phishing"
                else "This URL has suspicious characteristics. Verify it before proceeding."
                if prediction == "Suspicious"
                else "No strong phishing signal was detected. Still verify the website."
            )
        }

    except HTTPException:
        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"URL analysis failed: {str(error)}"
        )


# ==========================================
# 13. USER SCAN HISTORY
# ==========================================

@app.get("/api/history")
def scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    user=Depends(get_current_user)
):

    connection = get_database()

    rows = connection.execute(
        """
        SELECT id, url, prediction, risk_score, scanned_at
        FROM scans
        WHERE user_uid = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (user["uid"], limit)
    ).fetchall()

    connection.close()

    return {
        "success": True,
        "total_returned": len(rows),
        "history": [dict(row) for row in rows]
    }


# ==========================================
# 14. USER DASHBOARD STATISTICS
# ==========================================

@app.get("/api/dashboard")
def dashboard(user=Depends(get_current_user)):

    connection = get_database()

    stats = connection.execute(
        """
        SELECT
            COUNT(*) AS total_scans,

            SUM(
                CASE WHEN prediction = 'Phishing'
                THEN 1 ELSE 0 END
            ) AS phishing_count,

            SUM(
                CASE WHEN prediction = 'Legitimate'
                THEN 1 ELSE 0 END
            ) AS legitimate_count,

            SUM(
                CASE WHEN prediction = 'Suspicious'
                THEN 1 ELSE 0 END
            ) AS suspicious_count

        FROM scans
        WHERE user_uid = ?
        """,
        (user["uid"],)
    ).fetchone()

    recent = connection.execute(
        """
        SELECT id, url, prediction, risk_score, scanned_at
        FROM scans
        WHERE user_uid = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        (user["uid"],)
    ).fetchall()

    connection.close()

    return {
        "success": True,
        "statistics": {
            "total_scans": stats["total_scans"] or 0,
            "phishing": stats["phishing_count"] or 0,
            "legitimate": stats["legitimate_count"] or 0,
            "suspicious": stats["suspicious_count"] or 0
        },
        "recent_scans": [dict(row) for row in recent]
    }

# Serve frontend files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Main homepage
@app.get("/")
def home():
    return FileResponse("static/index.html")