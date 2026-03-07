from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config


app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    last_login_user_agent = db.Column(db.String(256))
    last_login_location = db.Column(db.String(120))

    login_attempts = db.relationship("LoginAttempt", backref="user", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    username = db.Column(db.String(64))
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(256))
    was_successful = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Integer)
    risk_reason = db.Column(db.String(255))
    location = db.Column(db.String(120))
    device_type = db.Column(db.String(64))
    is_simulated = db.Column(db.Boolean, default=False)


def _ensure_sqlite_schema() -> None:
    """
    Lightweight migration helper for SQLite.

    Checks for the presence of newer columns and issues ALTER TABLE
    statements to add them if they are missing. This lets the app
    start even if the database file was created before newer fields
    were introduced.
    """
    engine = db.engine
    # Only run this helper for SQLite backends.
    if "sqlite" not in str(engine.url):
        return

    connection = engine.raw_connection()
    try:
        cursor = connection.cursor()

        def columns_for(table_name: str):
            cursor.execute(f"PRAGMA table_info('{table_name}')")
            return {row[1] for row in cursor.fetchall()}

        user_columns = columns_for("user")
        attempt_columns = columns_for("login_attempt")

        statements = []

        # User table: last_login_location
        if "last_login_location" not in user_columns:
            statements.append(
                "ALTER TABLE user ADD COLUMN last_login_location VARCHAR(120)"
            )

        # LoginAttempt table: device_type, location, is_simulated, risk_score, risk_reason
        if "device_type" not in attempt_columns:
            statements.append(
                "ALTER TABLE login_attempt ADD COLUMN device_type VARCHAR(64)"
            )

        if "location" not in attempt_columns:
            statements.append(
                "ALTER TABLE login_attempt ADD COLUMN location VARCHAR(120)"
            )

        if "is_simulated" not in attempt_columns:
            statements.append(
                "ALTER TABLE login_attempt ADD COLUMN is_simulated BOOLEAN DEFAULT 0"
            )

        if "risk_score" not in attempt_columns:
            statements.append(
                "ALTER TABLE login_attempt ADD COLUMN risk_score INTEGER"
            )

        if "risk_reason" not in attempt_columns:
            statements.append(
                "ALTER TABLE login_attempt ADD COLUMN risk_reason VARCHAR(255)"
            )

        for stmt in statements:
            cursor.execute(stmt)

        if statements:
            connection.commit()
    finally:
        connection.close()


def _get_client_ip() -> str:
    # Basic support for proxied setups; falls back to direct remote address.
    forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return request.remote_addr or "unknown"


def calculate_risk_score(
    user,
    ip_address,
    user_agent,
    was_successful,
    attempted_at,
    location=None,
    device_type=None,
    is_simulated=False,
):
    """
    Very simple rule-based risk engine that returns (score, reason).
    Score range is 0-100; higher means more suspicious.
    """
    score = 0
    reasons = []

    if not was_successful:
        score += 40
        reasons.append("Failed password")

    # Time-of-day heuristic: early-morning hours are treated as higher risk.
    hour = attempted_at.hour
    if 2 <= hour < 5:
        score += 25
        reasons.append("Login during high-risk hours (2-5 AM)")

    if user and user.last_login_ip and user.last_login_ip != ip_address:
        score += 20
        reasons.append("New IP address")

    if user and user.last_login_user_agent and user.last_login_user_agent != user_agent:
        score += 20
        reasons.append("New device or browser")

    # Compare location, if we have one stored on the user.
    if location and user and user.last_login_location:
        if user.last_login_location.lower() != location.lower():
            score += 20
            reasons.append("New location or country")

    # Very high-risk device type, commonly associated with security testing.
    if device_type and device_type.lower() == "kali linux":
        score += 40
        reasons.append("High-risk device (Kali Linux)")

    if user and user.last_login_at:
        hour_diff = abs((attempted_at - user.last_login_at).total_seconds()) / 3600.0
        if hour_diff > 8:
            score += 10
            reasons.append("Unusual login time")

    # Check for multiple recent failures from same IP and username.
    if user:
        window_start = attempted_at - timedelta(minutes=30)
        recent_failures_query = LoginAttempt.query.filter(
            LoginAttempt.user_id == user.id,
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.attempted_at >= window_start,
            LoginAttempt.was_successful.is_(False),
        )
        recent_failures = recent_failures_query.count()
        if recent_failures >= 3:
            score += 30
            reasons.append("Multiple recent failed attempts")

    if is_simulated:
        reasons.append("Simulated attack scenario")

    score = max(0, min(score, 100))
    score = int(round(score))
    reason_text = ", ".join(reasons) if reasons else "Normal login pattern"
    return score, reason_text


def login_required(view_func):
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapped.__name__ = view_func.__name__
    return wrapped


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("Username or email already in use.", "danger")
            return render_template("register.html")

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        ip_address = _get_client_ip()
        user_agent = (request.user_agent.string or "")[:255]
        attempted_at = datetime.utcnow()

        was_successful = bool(user and user.check_password(password))

        if user:
            risk_score, risk_reason = calculate_risk_score(
                user,
                ip_address,
                user_agent,
                was_successful,
                attempted_at,
            )
        else:
            risk_score = 60.0
            risk_reason = "Login attempt for unknown user"

        login_attempt = LoginAttempt(
            user=user,
            username=username,
            attempted_at=attempted_at,
            ip_address=ip_address,
            user_agent=user_agent,
            was_successful=was_successful,
            risk_score=risk_score,
            risk_reason=risk_reason,
        )
        db.session.add(login_attempt)

        if was_successful:
            user.last_login_at = attempted_at
            user.last_login_ip = ip_address
            user.last_login_user_agent = user_agent
            db.session.commit()

            session["user_id"] = user.id
            session["username"] = user.username

            flash(
                f"Welcome back, {user.username}! Risk score for this login: {risk_score:.0f}",
                "success",
            )
            return redirect(url_for("dashboard"))

        db.session.commit()
        flash(
            f"Invalid username or password. Risk score for this attempt: {risk_score:.0f}",
            "danger",
        )
        return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id)

    attempts = (
        LoginAttempt.query.filter_by(user_id=user_id)
        .order_by(LoginAttempt.attempted_at.desc())
        .limit(100)
        .all()
    )

    suspicious_attempts = [
        a
        for a in attempts
        if (getattr(a, "risk_score", 0) or 0) >= 60 or not a.was_successful
    ]

    # Prepare data for charts.
    ordered_attempts = list(reversed(attempts))
    labels = [a.attempted_at.strftime("%Y-%m-%d %H:%M") for a in ordered_attempts]
    risk_scores = [float(getattr(a, "risk_score", 0) or 0) for a in ordered_attempts]
    success_flags = ["Success" if a.was_successful else "Failed" for a in ordered_attempts]

    success_count = sum(1 for a in attempts if a.was_successful)
    failure_count = len(attempts) - success_count

    # Build simple terminal-style security log lines based on recent events.
    security_logs = []
    for a in attempts:
        score_value = getattr(a, "risk_score", 0) or 0
        device_type = (getattr(a, "device_type", "") or "")
        is_simulated = bool(getattr(a, "is_simulated", False))
        base = (
            f"[INFO] Login attempt detected at "
            f"{a.attempted_at.strftime('%Y-%m-%d %H:%M')} from {a.ip_address}"
        )
        security_logs.append(base)

        if not a.was_successful:
            security_logs.append("[WARNING] Failed login detected")

        if score_value >= 60:
            security_logs.append(
                f"[ALERT] High risk login detected (score {int(score_value)})"
            )

        if device_type.lower() == "kali linux":
            security_logs.append("[ALERT] Suspicious device detected (Kali Linux)")

        if is_simulated:
            security_logs.append("[INFO] Simulated login scenario recorded")

    # Show only the most recent 50 log lines to keep the UI tidy.
    security_logs = security_logs[-50:]

    return render_template(
        "dashboard.html",
        user=user,
        attempts=attempts,
        suspicious_attempts=suspicious_attempts,
        labels=labels,
        risk_scores=risk_scores,
        success_flags=success_flags,
        success_count=success_count,
        failure_count=failure_count,
        security_logs=security_logs,
    )


@app.route("/simulate_login", methods=["POST"])
@login_required
def simulate_login():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id)
    if not user:
        flash("Unable to find current user for simulation.", "danger")
        return redirect(url_for("dashboard"))

    ip_address = request.form.get("ip_address", "").strip() or "0.0.0.0"
    device_type = request.form.get("device_type", "").strip() or "Unknown"
    location = request.form.get("location", "").strip() or "Unknown"
    login_time_raw = request.form.get("login_time", "").strip()

    attempted_at = datetime.utcnow()
    if login_time_raw:
        # HTML datetime-local input uses an ISO-like format without timezone.
        try:
            attempted_at = datetime.fromisoformat(login_time_raw)
        except ValueError:
            # Fallback to current time if parsing fails.
            attempted_at = datetime.utcnow()

    # Represent the device as a synthetic user agent string for consistency.
    user_agent = f"Simulated-{device_type}"[:255]
    was_successful = True

    risk_score, risk_reason = calculate_risk_score(
        user,
        ip_address,
        user_agent,
        was_successful,
        attempted_at,
        location=location,
        device_type=device_type,
        is_simulated=True,
    )

    login_attempt = LoginAttempt(
        user=user,
        username=user.username,
        attempted_at=attempted_at,
        ip_address=ip_address,
        user_agent=user_agent,
        was_successful=was_successful,
        risk_score=risk_score,
        risk_reason=risk_reason,
        location=location,
        device_type=device_type,
        is_simulated=True,
    )
    db.session.add(login_attempt)

    # Update last known location for future comparisons.
    user.last_login_location = location

    db.session.commit()

    flash(
        f"Simulated login recorded with risk score {risk_score:.0f}.",
        "info" if risk_score < 60 else "danger",
    )
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        _ensure_sqlite_schema()
    app.run(debug=True)

