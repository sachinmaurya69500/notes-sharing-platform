import os
import random
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-secret-key")


def _mongo_client() -> MongoClient:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise RuntimeError("MONGO_URI is not configured")
    return MongoClient(mongo_uri)


mongo_client = _mongo_client()
db = mongo_client[os.getenv("MONGO_DB_NAME", "notes_sharing_platform")]
users_collection = db["users"]
notes_collection = db["notes"]


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return users_collection.find_one({"_id": ObjectId(user_id)})


def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapper.__name__ = view_func.__name__
    return wrapper


def send_otp_email(recipient_email: str, otp_code: str) -> None:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", smtp_username)
    smtp_use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

    if not all([smtp_host, smtp_username, smtp_password, smtp_sender]):
        raise RuntimeError("SMTP configuration is incomplete")

    message = EmailMessage()
    message["Subject"] = "Your Notes Sharing Platform OTP"
    message["From"] = smtp_sender
    message["To"] = recipient_email
    message.set_content(
        f"Your verification OTP is {otp_code}. It expires in 10 minutes."
    )

    if smtp_use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_username, smtp_password)
            server.send_message(message)
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls(context=ssl.create_default_context())
            server.login(smtp_username, smtp_password)
            server.send_message(message)


def generate_otp() -> str:
    return f"{random.randint(0, 999999):06d}"


def serialize_note(note: dict) -> dict:
    return {
        "id": str(note["_id"]),
        "title": note.get("title", ""),
        "content": note.get("content", ""),
        "is_public": bool(note.get("is_public", False)),
        "created_at": note.get("created_at"),
        "updated_at": note.get("updated_at"),
        "owner_id": str(note.get("owner_id")) if note.get("owner_id") else None,
    }


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html")

        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        otp_code = generate_otp()
        hashed_password = generate_password_hash(password)

        users_collection.insert_one(
            {
                "email": email,
                "password": hashed_password,
                "is_verified": False,
                "otp_code": otp_code,
                "otp_expires_at": datetime.utcnow().timestamp() + 600,
                "created_at": datetime.utcnow(),
            }
        )

        try:
            send_otp_email(email, otp_code)
        except Exception as exc:
            users_collection.delete_one({"email": email, "is_verified": False})
            flash(f"Could not send OTP email: {exc}", "error")
            return render_template("register.html")

        session["pending_email"] = email
        flash("OTP sent to your email. Verify to activate your account.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    pending_email = session.get("pending_email")
    if not pending_email:
        return redirect(url_for("register"))

    if request.method == "POST":
        otp_input = request.form.get("otp", "").strip()
        user = users_collection.find_one({"email": pending_email})

        if not user:
            flash("No pending account found.", "error")
            return redirect(url_for("register"))

        if user.get("is_verified"):
            flash("Account already verified. Please log in.", "success")
            return redirect(url_for("login"))

        expires_at = user.get("otp_expires_at", 0)
        if datetime.utcnow().timestamp() > expires_at:
            flash("OTP expired. Please register again.", "error")
            return redirect(url_for("register"))

        if otp_input != user.get("otp_code"):
            flash("Invalid OTP.", "error")
            return render_template("verify_otp.html", email=pending_email)

        users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"is_verified": True},
                "$unset": {"otp_code": "", "otp_expires_at": ""},
            },
        )
        session.pop("pending_email", None)
        flash("Account verified. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("verify_otp.html", email=pending_email)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = users_collection.find_one({"email": email})

        if not user or not check_password_hash(user["password"], password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        if not user.get("is_verified"):
            session["pending_email"] = email
            flash("Please verify your OTP before logging in.", "error")
            return redirect(url_for("verify_otp"))

        session["user_id"] = str(user["_id"])
        session["user_email"] = user["email"]
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("logout"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        is_public = request.form.get("is_public") == "on"

        if not title or not content:
            flash("Title and content are required.", "error")
        else:
            notes_collection.insert_one(
                {
                    "owner_id": user["_id"],
                    "title": title,
                    "content": content,
                    "is_public": is_public,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow(),
                }
            )
            flash("Note created.", "success")
        return redirect(url_for("dashboard"))

    user_notes = list(notes_collection.find({"owner_id": user["_id"]}).sort("created_at", -1))
    return render_template(
        "dashboard.html",
        user=user,
        notes=[serialize_note(note) for note in user_notes],
    )


@app.route("/dashboard/edit/<note_id>", methods=["POST"])
@login_required
def edit_note(note_id):
    user = current_user()
    note = notes_collection.find_one({"_id": ObjectId(note_id), "owner_id": user["_id"]})

    if not note:
        flash("Note not found.", "error")
        return redirect(url_for("dashboard"))

    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    is_public = request.form.get("is_public") == "on"

    if not title or not content:
        flash("Title and content are required.", "error")
        return redirect(url_for("dashboard"))

    notes_collection.update_one(
        {"_id": note["_id"]},
        {
            "$set": {
                "title": title,
                "content": content,
                "is_public": is_public,
                "updated_at": datetime.utcnow(),
            }
        },
    )
    flash("Note updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard/delete/<note_id>", methods=["POST"])
@login_required
def delete_note(note_id):
    user = current_user()
    result = notes_collection.delete_one({"_id": ObjectId(note_id), "owner_id": user["_id"]})
    if result.deleted_count == 0:
        flash("Note not found.", "error")
    else:
        flash("Note deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/public-feed")
@login_required
def public_feed():
    notes = list(notes_collection.find({"is_public": True}).sort("created_at", -1))
    users_by_id = {
        str(user["_id"]): user["email"]
        for user in users_collection.find({}, {"email": 1})
    }
    return render_template(
        "public_feed.html",
        notes=[serialize_note(note) for note in notes],
        users_by_id=users_by_id,
    )


@app.route("/api/me")
@login_required
def api_me():
    user = current_user()
    return jsonify({"email": user["email"], "is_verified": user.get("is_verified", False)})


if __name__ == "__main__":
    app.run(debug=True)