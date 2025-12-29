# app.py
"""
Event Ticket Management System (ETMS)
- Flask backend (single-file)
- Flask-Login authentication (session-based)
- MongoDB via PyMongo (mongodb://localhost:27017)
- JSON-only API endpoints
- Serves main.html at "/"
"""
from __future__ import annotations

import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from bson import ObjectId
from flask import Flask, Response, jsonify, make_response, request, send_file
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from pymongo import MongoClient, ASCENDING, DESCENDING, ReturnDocument
from pymongo.errors import DuplicateKeyError, PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash

# -------------------------
# Configuration & Logging
# -------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("etms")

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB", "event_ticket_mgmt")

SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"  # set to 1 behind HTTPS
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")  # "Lax" recommended for SPA
SESSION_COOKIE_HTTPONLY = True

DEFAULT_ADMIN_EMAIL = "admin@example.com"
DEFAULT_ADMIN_PASSWORD = "Admin123!"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def to_oid(value: str) -> ObjectId:
    return ObjectId(value)


def is_iso_datetime(s: str) -> bool:
    """Accept ISO 8601 date or datetime strings.
    Mongo stores dt as ISO string so lexical comparisons work.
    """
    if not isinstance(s, str) or not s.strip():
        return False
    s = s.strip()
    try:
        # datetime.fromisoformat supports many ISO variants
        datetime.fromisoformat(s.replace("Z", "+00:00"))
        return True
    except Exception:
        # Also allow YYYY-MM-DD (date only)
        try:
            datetime.fromisoformat(s)
            return True
        except Exception:
            return False


# -------------------------
# API Error Handling
# -------------------------
@dataclass
class ApiError(Exception):
    message: str
    status: int = 400
    code: str = "bad_request"
    details: Optional[Dict[str, Any]] = None


def ok(payload: Dict[str, Any] | None = None, status: int = 200) -> Tuple[Response, int]:
    data = {"ok": True}
    if payload:
        data.update(payload)
    return jsonify(data), status


def fail(err: ApiError) -> Tuple[Response, int]:
    data = {"ok": False, "error": err.message, "code": err.code}
    if err.details:
        data["details"] = err.details
    return jsonify(data), err.status


def require_json() -> Dict[str, Any]:
    if not request.is_json:
        raise ApiError("Request must be JSON.", 415, "unsupported_media_type")
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError("Invalid JSON payload.", 400, "invalid_json")
    if not isinstance(data, dict):
        raise ApiError("JSON body must be an object.", 400, "invalid_json")
    return data


# -------------------------
# App Init
# -------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
)

# Attach a request id for debugging/traceability.
@app.before_request
def attach_request_id():
    rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    request.environ["request_id"] = rid


@app.after_request
def add_security_headers(resp: Response):
    # Minimal hardening without extra dependencies
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Request-Id"] = request.environ.get("request_id", "")
    return resp


# -------------------------
# MongoDB
# -------------------------
try:
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=3000,
        connectTimeoutMS=3000,
        socketTimeoutMS=5000,
        retryWrites=True,
    )
    # Verify connectivity early (will raise if unreachable)
    client.admin.command("ping")
    db = client[DB_NAME]
except Exception as e:
    logger.exception("MongoDB connection failed")
    raise RuntimeError(f"MongoDB connection failed: {e}") from e

users_col = db["users"]
events_col = db["events"]
ticket_types_col = db["ticket_types"]
purchases_col = db["purchases"]

# Indexes
users_col.create_index([("email", ASCENDING)], unique=True)
events_col.create_index([("organizer_id", ASCENDING), ("dt", ASCENDING)])
events_col.create_index([("title", ASCENDING)])
events_col.create_index([("venue", ASCENDING)])
events_col.create_index([("category", ASCENDING)])
ticket_types_col.create_index([("event_id", ASCENDING), ("name", ASCENDING)], unique=True)
purchases_col.create_index([("event_id", ASCENDING), ("purchased_at", DESCENDING)])
purchases_col.create_index([("user_id", ASCENDING), ("purchased_at", DESCENDING)])


# -------------------------
# Auth (Flask-Login)
# -------------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


class User(UserMixin):
    def __init__(self, doc: Dict[str, Any]):
        self.doc = doc
        self.id = str(doc["_id"])
        self.email = doc.get("email", "")
        self.role = doc.get("role", "attendee")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_organizer(self) -> bool:
        return self.role == "organizer"


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        doc = users_col.find_one({"_id": to_oid(user_id)})
        return User(doc) if doc else None
    except Exception:
        return None


@login_manager.unauthorized_handler
def unauthorized():
    # JSON only
    return jsonify({"ok": False, "error": "Authentication required.", "code": "unauthorized"}), 401


def require_roles(*roles: str):
    def decorator(fn):
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return unauthorized()
            if current_user.role not in roles:
                return jsonify({"ok": False, "error": "Forbidden.", "code": "forbidden"}), 403
            return fn(*args, **kwargs)

        # keep function identity (Flask uses __name__)
        wrapped.__name__ = fn.__name__
        wrapped.__doc__ = fn.__doc__
        return wrapped

    return decorator


def can_edit_event(event_doc: Dict[str, Any]) -> bool:
    if not current_user.is_authenticated:
        return False
    if current_user.is_admin:
        return True
    return str(event_doc.get("organizer_id")) == current_user.id


# -------------------------
# Serialization helpers
# -------------------------
def public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": str(u["_id"]), "email": u.get("email", ""), "role": u.get("role", "attendee")}


def public_event(e: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(e["_id"]),
        "organizer_id": str(e.get("organizer_id")) if e.get("organizer_id") else None,
        "title": e.get("title", ""),
        "description": e.get("description", ""),
        "category": e.get("category", ""),
        "dt": e.get("dt", ""),
        "venue": e.get("venue", ""),
        "capacity": int(e.get("capacity", 0)),
        "created_at": e.get("created_at", ""),
        "updated_at": e.get("updated_at", ""),
    }


def public_ticket_type(t: Dict[str, Any]) -> Dict[str, Any]:
    qty = int(t.get("quantity", 0))
    sold = int(t.get("sold", 0))
    return {
        "id": str(t["_id"]),
        "event_id": str(t.get("event_id")),
        "name": t.get("name", ""),
        "price": float(t.get("price", 0.0)),
        "quantity": qty,
        "sold": sold,
        "available": max(0, qty - sold),
        "created_at": t.get("created_at", ""),
        "updated_at": t.get("updated_at", ""),
    }



def public_purchase(p: Dict[str, Any], event_doc: Optional[Dict[str, Any]] = None,
                    ticket_doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Public-facing purchase record including denormalized event/ticket details."""
    out = {
        "id": str(p.get("_id")),
        "user_id": str(p.get("user_id")) if p.get("user_id") else None,
        "event_id": str(p.get("event_id")) if p.get("event_id") else None,
        "ticket_type_id": str(p.get("ticket_type_id")) if p.get("ticket_type_id") else None,
        "quantity": int(p.get("quantity", 0)),
        "unit_price": float(p.get("unit_price", 0.0)),
        "total_price": float(p.get("total_price", 0.0)),
        "purchased_at": p.get("purchased_at", ""),
    }
    if event_doc:
        out["event"] = public_event(event_doc)
    if ticket_doc:
        out["ticket_type"] = public_ticket_type(ticket_doc)
    return out


def safe_int(value: Any, field: str, min_value: Optional[int] = None) -> int:
    try:
        n = int(value)
    except Exception:
        raise ApiError(f"{field} must be an integer.", 400, "validation_error", {"field": field})
    if min_value is not None and n < min_value:
        raise ApiError(f"{field} must be >= {min_value}.", 400, "validation_error", {"field": field})
    return n


def safe_float(value: Any, field: str, min_value: Optional[float] = None) -> float:
    try:
        n = float(value)
    except Exception:
        raise ApiError(f"{field} must be a number.", 400, "validation_error", {"field": field})
    if min_value is not None and n < min_value:
        raise ApiError(f"{field} must be >= {min_value}.", 400, "validation_error", {"field": field})
    return n


def validate_email(email: str) -> str:
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        raise ApiError("A valid email is required.", 400, "validation_error", {"field": "email"})
    return email


def validate_password(pw: str) -> str:
    pw = pw or ""
    if len(pw) < 6:
        raise ApiError("Password must be at least 6 characters.", 400, "validation_error", {"field": "password"})
    return pw


# -------------------------
# Default Admin Seed
# -------------------------
def ensure_default_admin():
    try:
        existing = users_col.find_one({"email": DEFAULT_ADMIN_EMAIL})
        if existing:
            return
        users_col.insert_one(
            {
                "email": DEFAULT_ADMIN_EMAIL,
                "password_hash": generate_password_hash(DEFAULT_ADMIN_PASSWORD),
                "role": "admin",
                "created_at": iso_now(),
            }
        )
        logger.info("Default admin created: %s", DEFAULT_ADMIN_EMAIL)
    except Exception:
        logger.exception("Failed to ensure default admin user")


ensure_default_admin()

# -------------------------
# Global Error Handlers
# -------------------------
@app.errorhandler(ApiError)
def handle_api_error(err: ApiError):
    return fail(err)


@app.errorhandler(404)
def handle_404(_):
    return jsonify({"ok": False, "error": "Not found.", "code": "not_found"}), 404


@app.errorhandler(405)
def handle_405(_):
    return jsonify({"ok": False, "error": "Method not allowed.", "code": "method_not_allowed"}), 405


@app.errorhandler(Exception)
def handle_exception(e: Exception):
    rid = request.environ.get("request_id", "")
    logger.exception("Unhandled error (request_id=%s): %s", rid, e)
    return (
        jsonify(
            {
                "ok": False,
                "error": "Internal server error.",
                "code": "internal_error",
                "request_id": rid,
            }
        ),
        500,
    )


# -------------------------
# Routes
# -------------------------
@app.get("/")
def root():
    return send_file(os.path.join(APP_DIR, "main.html"))


@app.get("/api/health")
def health():
    return ok({"status": "up"})


@app.get("/api/me")
def me():
    if not current_user.is_authenticated:
        return ok({"user": None})
    # Load from db to avoid stale role/email in session
    u = users_col.find_one({"_id": to_oid(current_user.id)})
    return ok({"user": public_user(u) if u else None})


# -------------------------
# Auth APIs
# -------------------------
@app.post("/api/register")
def register():
    data = require_json()
    email = validate_email(data.get("email", ""))
    password = validate_password(data.get("password", ""))
    role = (data.get("role") or "attendee").strip().lower()
    if role not in ("attendee", "organizer"):
        role = "attendee"

    try:
        doc = {
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": role,
            "created_at": iso_now(),
        }
        res = users_col.insert_one(doc)
        u = users_col.find_one({"_id": res.inserted_id})
        login_user(User(u))
        return ok({"user": public_user(u)}, 201)
    except DuplicateKeyError:
        raise ApiError("Email already registered.", 409, "conflict", {"field": "email"})
    except PyMongoError as e:
        raise ApiError("Database error during registration.", 500, "db_error", {"detail": str(e)})


@app.post("/api/login")
def login():
    data = require_json()
    email = validate_email(data.get("email", ""))
    password = data.get("password") or ""

    u = users_col.find_one({"email": email})
    if not u or not check_password_hash(u.get("password_hash", ""), password):
        raise ApiError("Invalid credentials.", 401, "unauthorized")

    login_user(User(u))
    return ok({"user": public_user(u)})


@app.post("/api/logout")
@login_required
def logout():
    logout_user()
    return ok({})


# -------------------------
# Event APIs
# -------------------------
@app.get("/api/events")
def list_events():
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    venue = (request.args.get("venue") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    ands = []
    if q:
        ands.append(
            {
                "$or": [
                    {"title": {"$regex": re.escape(q), "$options": "i"}},
                    {"description": {"$regex": re.escape(q), "$options": "i"}},
                ]
            }
        )
    if category:
        ands.append({"category": {"$regex": f"^{re.escape(category)}$", "$options": "i"}})
    if venue:
        ands.append({"venue": {"$regex": re.escape(venue), "$options": "i"}})
    if date_from:
        if not is_iso_datetime(date_from):
            raise ApiError("date_from must be ISO format (e.g., 2026-01-01 or 2026-01-01T10:00:00+00:00).", 400, "validation_error", {"field": "date_from"})
        ands.append({"dt": {"$gte": date_from}})
    if date_to:
        if not is_iso_datetime(date_to):
            raise ApiError("date_to must be ISO format (e.g., 2026-01-31 or 2026-01-31T10:00:00+00:00).", 400, "validation_error", {"field": "date_to"})
        ands.append({"dt": {"$lte": date_to}})

    query: Dict[str, Any] = {"$and": ands} if ands else {}
    events = list(events_col.find(query).sort("dt", ASCENDING).limit(200))
    return ok({"events": [public_event(e) for e in events]})


@app.get("/api/events/<event_id>")
def get_event(event_id: str):
    try:
        e = events_col.find_one({"_id": to_oid(event_id)})
        if not e:
            raise ApiError("Event not found.", 404, "not_found")
        tickets = list(ticket_types_col.find({"event_id": to_oid(event_id)}).sort("price", ASCENDING))
        return ok({"event": public_event(e), "ticket_types": [public_ticket_type(t) for t in tickets]})
    except ApiError:
        raise
    except Exception:
        raise ApiError("Invalid event id.", 400, "validation_error", {"field": "event_id"})


@app.post("/api/events")
@require_roles("admin", "organizer")
def create_event():
    data = require_json()
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    category = (data.get("category") or "").strip()
    dt = (data.get("dt") or "").strip()
    venue = (data.get("venue") or "").strip()
    capacity = safe_int(data.get("capacity"), "capacity", min_value=1)

    if not title:
        raise ApiError("Title is required.", 400, "validation_error", {"field": "title"})
    if not dt or not is_iso_datetime(dt):
        raise ApiError("Date/time must be ISO format (e.g., 2026-01-01T10:00:00+00:00).", 400, "validation_error", {"field": "dt"})

    doc = {
        "organizer_id": to_oid(current_user.id),
        "title": title,
        "description": description,
        "category": category,
        "dt": dt,
        "venue": venue,
        "capacity": capacity,
        "created_at": iso_now(),
        "updated_at": iso_now(),
    }
    try:
        res = events_col.insert_one(doc)
        created = events_col.find_one({"_id": res.inserted_id})
        return ok({"event": public_event(created)}, 201)
    except PyMongoError as e:
        raise ApiError("Database error while creating event.", 500, "db_error", {"detail": str(e)})


@app.put("/api/events/<event_id>")
@require_roles("admin", "organizer")
def update_event(event_id: str):
    data = require_json()
    try:
        e = events_col.find_one({"_id": to_oid(event_id)})
        if not e:
            raise ApiError("Event not found.", 404, "not_found")
        if not can_edit_event(e):
            raise ApiError("Forbidden.", 403, "forbidden")

        updates: Dict[str, Any] = {}
        for k in ("title", "description", "category", "venue"):
            if k in data:
                updates[k] = (data.get(k) or "").strip()

        if "dt" in data:
            dt = (data.get("dt") or "").strip()
            if not dt or not is_iso_datetime(dt):
                raise ApiError("dt must be ISO format.", 400, "validation_error", {"field": "dt"})
            updates["dt"] = dt

        if "capacity" in data:
            updates["capacity"] = safe_int(data.get("capacity"), "capacity", min_value=1)

        if "title" in updates and not updates["title"]:
            raise ApiError("Title cannot be empty.", 400, "validation_error", {"field": "title"})

        updates["updated_at"] = iso_now()

        events_col.update_one({"_id": to_oid(event_id)}, {"$set": updates})
        updated = events_col.find_one({"_id": to_oid(event_id)})
        return ok({"event": public_event(updated)})
    except ApiError:
        raise
    except Exception:
        raise ApiError("Invalid event id.", 400, "validation_error", {"field": "event_id"})


@app.delete("/api/events/<event_id>")
@require_roles("admin", "organizer")
def delete_event(event_id: str):
    try:
        e = events_col.find_one({"_id": to_oid(event_id)})
        if not e:
            raise ApiError("Event not found.", 404, "not_found")
        if not can_edit_event(e):
            raise ApiError("Forbidden.", 403, "forbidden")

        ticket_types_col.delete_many({"event_id": to_oid(event_id)})
        purchases_col.delete_many({"event_id": to_oid(event_id)})
        events_col.delete_one({"_id": to_oid(event_id)})
        return ok({})
    except ApiError:
        raise
    except Exception:
        raise ApiError("Invalid event id.", 400, "validation_error", {"field": "event_id"})


# -------------------------
# Ticket Type APIs
# -------------------------
@app.get("/api/events/<event_id>/tickets")
def list_ticket_types(event_id: str):
    try:
        tickets = list(ticket_types_col.find({"event_id": to_oid(event_id)}).sort("price", ASCENDING))
        return ok({"ticket_types": [public_ticket_type(t) for t in tickets]})
    except Exception:
        raise ApiError("Invalid event id.", 400, "validation_error", {"field": "event_id"})


@app.post("/api/events/<event_id>/tickets")
@require_roles("admin", "organizer")
def create_ticket_type(event_id: str):
    data = require_json()
    name = (data.get("name") or "").strip()
    price = safe_float(data.get("price"), "price", min_value=0.0)
    quantity = safe_int(data.get("quantity"), "quantity", min_value=1)

    if not name:
        raise ApiError("Ticket type name is required.", 400, "validation_error", {"field": "name"})

    try:
        e = events_col.find_one({"_id": to_oid(event_id)})
        if not e:
            raise ApiError("Event not found.", 404, "not_found")
        if not can_edit_event(e):
            raise ApiError("Forbidden.", 403, "forbidden")

        doc = {
            "event_id": to_oid(event_id),
            "name": name,
            "price": price,
            "quantity": quantity,
            "sold": 0,
            "created_at": iso_now(),
            "updated_at": iso_now(),
        }
        res = ticket_types_col.insert_one(doc)
        created = ticket_types_col.find_one({"_id": res.inserted_id})
        return ok({"ticket_type": public_ticket_type(created)}, 201)
    except DuplicateKeyError:
        raise ApiError("Ticket type name already exists for this event.", 409, "conflict", {"field": "name"})
    except PyMongoError as e:
        raise ApiError("Database error while creating ticket type.", 500, "db_error", {"detail": str(e)})


@app.put("/api/tickets/<ticket_id>")
@require_roles("admin", "organizer")
def update_ticket_type(ticket_id: str):
    data = require_json()
    try:
        t = ticket_types_col.find_one({"_id": to_oid(ticket_id)})
        if not t:
            raise ApiError("Ticket type not found.", 404, "not_found")

        e = events_col.find_one({"_id": t["event_id"]})
        if not e or not can_edit_event(e):
            raise ApiError("Forbidden.", 403, "forbidden")

        updates: Dict[str, Any] = {}
        if "name" in data:
            new_name = (data.get("name") or "").strip()
            if not new_name:
                raise ApiError("name cannot be empty.", 400, "validation_error", {"field": "name"})
            updates["name"] = new_name
        if "price" in data:
            updates["price"] = safe_float(data.get("price"), "price", min_value=0.0)
        if "quantity" in data:
            new_qty = safe_int(data.get("quantity"), "quantity", min_value=1)
            if new_qty < int(t.get("sold", 0)):
                raise ApiError("Quantity cannot be less than already sold.", 400, "validation_error", {"field": "quantity"})
            updates["quantity"] = new_qty

        if not updates:
            return ok({"ticket_type": public_ticket_type(t)})

        updates["updated_at"] = iso_now()
        updated = ticket_types_col.find_one_and_update(
            {"_id": to_oid(ticket_id)},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        return ok({"ticket_type": public_ticket_type(updated)})
    except DuplicateKeyError:
        raise ApiError("Ticket type name already exists for this event.", 409, "conflict", {"field": "name"})
    except ApiError:
        raise
    except Exception:
        raise ApiError("Invalid ticket id.", 400, "validation_error", {"field": "ticket_id"})


@app.delete("/api/tickets/<ticket_id>")
@require_roles("admin", "organizer")
def delete_ticket_type(ticket_id: str):
    try:
        t = ticket_types_col.find_one({"_id": to_oid(ticket_id)})
        if not t:
            raise ApiError("Ticket type not found.", 404, "not_found")

        e = events_col.find_one({"_id": t["event_id"]})
        if not e or not can_edit_event(e):
            raise ApiError("Forbidden.", 403, "forbidden")

        if int(t.get("sold", 0)) > 0:
            raise ApiError("Cannot delete a ticket type that has sales.", 409, "conflict")

        ticket_types_col.delete_one({"_id": to_oid(ticket_id)})
        return ok({})
    except ApiError:
        raise
    except Exception:
        raise ApiError("Invalid ticket id.", 400, "validation_error", {"field": "ticket_id"})


# -------------------------
# Purchase API (oversell safe)
# -------------------------
@app.post("/api/purchase")
@require_roles("attendee", "organizer", "admin")
def purchase():
    data = require_json()
    ticket_type_id = (data.get("ticket_type_id") or "").strip()
    if not ticket_type_id:
        raise ApiError("ticket_type_id is required.", 400, "validation_error", {"field": "ticket_type_id"})
    qty = safe_int(data.get("quantity"), "quantity", min_value=1)

    try:
        tid = to_oid(ticket_type_id)
    except Exception:
        raise ApiError("Invalid ticket_type_id.", 400, "validation_error", {"field": "ticket_type_id"})

    t = ticket_types_col.find_one({"_id": tid})
    if not t:
        raise ApiError("Ticket type not found.", 404, "not_found")

    e = events_col.find_one({"_id": t["event_id"]})
    if not e:
        raise ApiError("Event not found.", 404, "not_found")

    # Atomic oversell protection: only update if sold+qty <= quantity
    updated = ticket_types_col.find_one_and_update(
        {
            "_id": tid,
            "$expr": {"$lte": [{"$add": ["$sold", qty]}, "$quantity"]},
        },
        {"$inc": {"sold": qty}, "$set": {"updated_at": iso_now()}},
        return_document=ReturnDocument.AFTER,
    )

    if not updated:
        raise ApiError("Not enough tickets available (sold out / insufficient stock).", 409, "conflict")

    unit_price = float(t.get("price", 0.0))
    total = unit_price * qty
    purchase_doc = {
        "user_id": to_oid(current_user.id),
        "event_id": t["event_id"],
        "ticket_type_id": tid,
        "quantity": qty,
        "unit_price": unit_price,
        "total_price": total,
        "purchased_at": iso_now(),
    }

    try:
        purchases_col.insert_one(purchase_doc)
    except PyMongoError as ex:
        # Best-effort rollback if recording purchase fails (rare):
        logger.exception("Failed to record purchase; rolling back sold count")
        ticket_types_col.update_one({"_id": tid}, {"$inc": {"sold": -qty}, "$set": {"updated_at": iso_now()}})
        raise ApiError("Purchase could not be recorded. Please try again.", 500, "db_error", {"detail": str(ex)})

    return ok(
        {
            "message": "Purchase successful.",
            "purchase": {
                "event_id": str(t["event_id"]),
                "ticket_type_id": str(tid),
                "quantity": qty,
                "total_price": round(total, 2),
            },
            "ticket_type": public_ticket_type(updated),
        },
        201,
    )


# -------------------------
# Sales Dashboard
# -------------------------
@app.get("/api/sales")
@require_roles("admin", "organizer")
def sales():
    # organizer: only own events
    if current_user.role == "organizer":
        my_event_ids = [d["_id"] for d in events_col.find({"organizer_id": to_oid(current_user.id)}, {"_id": 1})]
        if not my_event_ids:
            return ok(
                {
                    "summary": {"total_revenue": 0.0, "total_tickets": 0},
                    "per_event": [],
                    "most_popular": [],
                }
            )
        purchases_match: Dict[str, Any] = {"event_id": {"$in": my_event_ids}}
    else:
        purchases_match = {}

    pipeline = [
        {"$match": purchases_match},
        {"$group": {"_id": "$event_id", "tickets": {"$sum": "$quantity"}, "revenue": {"$sum": "$total_price"}}},
        {"$sort": {"revenue": -1}},
    ]

    rows = list(purchases_col.aggregate(pipeline))
    per_event = []
    total_rev = 0.0
    total_tickets = 0

    for r in rows:
        ev = events_col.find_one({"_id": r["_id"]})
        if not ev:
            continue
        tickets_sold = int(r.get("tickets", 0))
        revenue = float(r.get("revenue", 0.0))
        per_event.append({"event": public_event(ev), "tickets_sold": tickets_sold, "revenue": round(revenue, 2)})
        total_rev += revenue
        total_tickets += tickets_sold

    most_popular = sorted(per_event, key=lambda x: x["tickets_sold"], reverse=True)[:5]
    per_event_sorted = sorted(per_event, key=lambda x: x["revenue"], reverse=True)

    return ok(
        {
            "summary": {"total_revenue": round(total_rev, 2), "total_tickets": total_tickets},
            "per_event": per_event_sorted,
            "most_popular": most_popular,
        }
    )


# -------------------------
# Convenience: my events
# -------------------------
@app.get("/api/my/events")
@require_roles("admin", "organizer")
def my_events():
    query: Dict[str, Any] = {} if current_user.role == "admin" else {"organizer_id": to_oid(current_user.id)}
    events = list(events_col.find(query).sort("created_at", DESCENDING).limit(200))
    return ok({"events": [public_event(e) for e in events]})



# -------------------------
# Convenience: my purchases / tickets
# -------------------------
@app.get("/api/my/purchases")
@require_roles("attendee", "organizer", "admin")
def my_purchases():
    """Return purchases for the currently signed-in user (for 'My Tickets' UI)."""
    docs = list(
        purchases_col.find({"user_id": to_oid(current_user.id)})
        .sort("purchased_at", DESCENDING)
        .limit(200)
    )
    if not docs:
        return ok({"purchases": []})

    event_ids = list({d.get("event_id") for d in docs if d.get("event_id")})
    ticket_ids = list({d.get("ticket_type_id") for d in docs if d.get("ticket_type_id")})

    events_map = {e["_id"]: e for e in events_col.find({"_id": {"$in": event_ids}})}
    tickets_map = {t["_id"]: t for t in ticket_types_col.find({"_id": {"$in": ticket_ids}})}

    out = []
    for p in docs:
        ev = events_map.get(p.get("event_id"))
        tk = tickets_map.get(p.get("ticket_type_id"))
        out.append(public_purchase(p, ev, tk))

    return ok({"purchases": out})


if __name__ == "__main__":
    # Production: run behind a WSGI server (gunicorn/uwsgi) and set SECRET_KEY + SESSION_COOKIE_SECURE
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)
