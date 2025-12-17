from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
from datetime import timedelta
import sqlite3 as sql

import userManagement as dbHandler


app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
app.permanent_session_lifetime = timedelta(days=1)
csrf = CSRFProtect(app)
try:
    dbHandler.getUsers()
    dbHandler.init_2fa_column()
    dbHandler.init_dev_logs_table()
except (sql.Error, OSError) as e:
    app.logger.error("Failed to initialize database: %s", e)


@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)
def index_redirect():
    if "email" in session:
        return redirect("/index.html", 302)
    return redirect("/Login.html", 302)


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


@app.route("/offline.html", methods=["GET"])
def offline():
    return render_template("/offline.html")


@app.route("/index.html", methods=["GET", "POST"])
def index():
    if "email" not in session:
        return redirect("/Login.html", 302)

    if request.method == "POST":
        message = request.form.get("message")
        time_worked = request.form.get("time_worked")
        repo_link = request.form.get("repo_link")
        if message and time_worked and repo_link:
            try:
                time_worked = float(time_worked)
                dbHandler.add_dev_log(message, session["email"], time_worked, repo_link)
            except ValueError:
                pass
        return redirect("/index.html", 302)

    sort_by = request.args.get("sort", "newest")
    logs = dbHandler.get_dev_logs(sort_by)
    return render_template("index.html", logs=logs, current_sort=sort_by)


# example CSRF protected form
@app.route("/Login.html", methods=["POST", "GET"])
def form():
    return render_template("/Login.html")


# Redirect to Index.html
@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return render_template(
            "Login.html", message="Please enter both email and password"
        )

    if dbHandler.authenticate(email, password):
        session.permanent = True
        session["email_pending_2fa"] = email
        return redirect("/verify_2fa", 302)
    else:
        return render_template(
            "Login.html", message="invalid email or password", message_type="danger"
        )


# Redirect to Signup.html
@app.route("/Signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")

        if not email or not password or not password_confirm:
            return render_template(
                "Signup.html", message="Please enter a Email and Password"
            )

        if password != password_confirm:
            return render_template("Signup.html", message="Passwords do not match")

        success, msg = dbHandler.NewUser(email, password)
        if success:
            return render_template("Signup.html", message="Success, Account Created")
        else:
            return render_template("Signup.html", message=msg)
    else:
        return render_template("Signup.html")


# 2FA verification route
@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if "email_pending_2fa" not in session:
        return redirect("/Login.html", 302)

    email = session["email_pending_2fa"]

    if request.method == "POST":
        code = request.form.get("code")

        if not code:
            return render_template(
                "2fa.html", message="Please enter the verification code"
            )

        if dbHandler.verify_2fa_code(email, code):
            session["email"] = email
            session.pop("email_pending_2fa", None)
            return redirect("/index.html", 302)
        else:
            return render_template(
                "2fa.html", message="Invalid verification code", message_type="danger"
            )

    qr_code = dbHandler.get_2fa_qr_code_base64(email)
    secret_key = dbHandler.get_2fa_key(email)
    return render_template(
        "2fa.html", qr_code=qr_code, secret_key=secret_key, email=email
    )


# 2FA setup route
@app.route("/setup_2fa", methods=["GET"])
def setup_2fa():
    if "email" not in session:
        return redirect("/Login.html", 302)

    email = session["email"]
    qr_code = dbHandler.get_2fa_qr_code_base64(email)
    secret_key = dbHandler.get_2fa_key(email)
    return render_template(
        "2fa_setup.html", qr_code=qr_code, secret_key=secret_key, email=email
    )


# Logout route
@app.route("/logout", methods=["GET"])
def logout():
    email = session.get("email", "unknown")
    session.clear()
    app.logger.info("User %s logged out", email)
    return redirect("/Login.html", 302)


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)
