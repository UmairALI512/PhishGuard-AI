import os
import ipaddress
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
import firebase_admin
import psycopg
from psycopg.rows import dict_row

from firebase_admin import credentials, auth
from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator


# ==========================================
# 1. CONFIGURATION
# ==========================================

MODEL_PATH = "model/phishguard_model.joblib"

FIREBASE_KEY_PATH = os.getenv(
    "FIREBASE_KEY_PATH",
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "firebase-service-account.json"
    )
)

# Set DATABASE_URL in your environment (Neon PostgreSQL connection string).
DATABASE_URL = os.getenv("DATABASE_URL")


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

if not firebase_admin._apps:
    firebase_json = os.getenv("FIREBASE_SERVICE_ACCOUNT")

    if firebase_json:
        firebase_credential = credentials.Certificate(
            json.loads(firebase_json)
        )
    else:
        if not os.path.exists(FIREBASE_KEY_PATH):
            raise FileNotFoundError(
                "Firebase service account JSON not found."
            )

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
# 5. POSTGRESQL DATABASE
# ==========================================

def get_database():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured. Add your Neon PostgreSQL "
            "connection string to the DATABASE_URL environment variable."
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def create_database():
    connection = get_database()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id BIGSERIAL PRIMARY KEY,
                user_uid TEXT NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_user
            ON scans(user_uid)
        """)

        connection.commit()
    finally:
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
# 9. SAVE SCAN IN POSTGRESQL
# ==========================================

def save_scan(user_uid, url, prediction, risk_score):

    connection = get_database()

    scanned_at = datetime.now(
        timezone.utc
    ).isoformat()

    try:
        connection.execute(
            """
            INSERT INTO scans (
                user_uid,
                url,
                prediction,
                risk_score,
                scanned_at
            )
            VALUES (%s, %s, %s, %s, %s)
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
    finally:
        connection.close()


# ==========================================
# 10. HEALTH CHECK
# ==========================================

@app.get("/api/health")
def health_check():

    try:
        connection = get_database()
        connection.execute("SELECT 1")
        connection.close()
        database_status = "connected"
    except Exception:
        database_status = "disconnected"

    return {
        "status": "online",
        "application": "PhishGuard AI",
        "model_loaded": True,
        "database": database_status
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

    try:
        rows = connection.execute(
            """
            SELECT id, url, prediction, risk_score, scanned_at
            FROM scans
            WHERE user_uid = %s
            ORDER BY id DESC
            LIMIT %s
            """,
            (user["uid"], limit)
        ).fetchall()
    finally:
        connection.close()

    return {
        "success": True,
        "total_returned": len(rows),
        "history": rows
    }


# ==========================================
# 14. USER DASHBOARD STATISTICS
# ==========================================

@app.get("/api/dashboard")
def dashboard(user=Depends(get_current_user)):

    connection = get_database()

    try:
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
            WHERE user_uid = %s
            """,
            (user["uid"],)
        ).fetchone()

        recent = connection.execute(
            """
            SELECT id, url, prediction, risk_score, scanned_at
            FROM scans
            WHERE user_uid = %s
            ORDER BY id DESC
            LIMIT 5
            """,
            (user["uid"],)
        ).fetchall()
    finally:
        connection.close()

    return {
        "success": True,
        "statistics": {
            "total_scans": stats["total_scans"] or 0,
            "phishing": stats["phishing_count"] or 0,
            "legitimate": stats["legitimate_count"] or 0,
            "suspicious": stats["suspicious_count"] or 0
        },
        "recent_scans": recent
    }


# ==========================================
# 15. FRONTEND FILES
# ==========================================

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def home():
    return FileResponse("static/index.html")
