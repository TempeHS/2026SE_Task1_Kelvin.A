from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
from flask import session
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging
from datetime import timedelta

import userManagement as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

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
except Exception as e:
    app.logger.error(f"Failed to initialize database: {e}")


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
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
def open():
    if "email" in session:
        return redirect("/index.html", 302)
    return render_template("/Login.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


@app.route("/index.html", methods=["GET"])
def index():
    if "email" not in session:
        return redirect("/Login.html", 302)
    return render_template("index.html")


# example CSRF protected form
@app.route("/Login.html", methods=["POST", "GET"])
def form():
    if request.method == "POST":
        email = request.form["email"]
        text = request.form["text"]
        return render_template("/Login.html")
    else:
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
        session["email"] = email
        return redirect("/index.html", 302)
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


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
