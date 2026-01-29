


# from flask import Flask, render_template, jsonify, request
# import requests

# app = Flask(__name__)

# @app.route("/")
# def dashboard():
#     return render_template("dashboard.html")

# @app.route("/login", methods=["GET","POST"])
# def login():
#     if request.method == "POST":
#         return "Login logic later"
#     return render_template("login.html")

# @app.route("/register", methods=["GET","POST"])
# def register():
#     if request.method == "POST":
#         return "Register logic later"
#     return render_template("register.html")

# @app.route("/history")
# def history():
#     return render_template("history.html")

# @app.route("/alerts", methods=["GET","POST"])
# def alerts():
#     return render_template("alerts.html")

# @app.route("/api/prices")
# def prices():
#     url = "https://api.coingecko.com/api/v3/simple/price"
#     params = {"ids":"bitcoin,ethereum","vs_currencies":"usd"}
#     data = requests.get(url, params=params).json()
#     return jsonify({
#         "bitcoin": data["bitcoin"]["usd"],
#         "ethereum": data["ethereum"]["usd"]
#     })

# @app.route("/api/history/<coin>")
# def history_api(coin):
#     return jsonify({
#         "dates": ["Day1","Day2","Day3"],
#         "prices": [42000,43000,41000]
#     })

# if __name__ == "__main__":
#     app.run(debug=True)


# Crypto Price Tracker – Flask App (Local Run)
# Dictionary-based storage (template style, project-specific)
# Aligned exactly with given architecture

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = "crypto_secret_key"


users = {}            # {email: password}
alerts = {}           # {email: [{coin, threshold}]}
price_history = {}    # {coin: [{time, price}]}
ADMIN_EMAIL = "admin@crypto.com"


@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role", "user")

        if email in users:
            return render_template(
                "register.html",
                error="User already exists"
            )

        users[email] = {
            "password": password,
            "role": role,
            "is_logged_in": False
        }

        return redirect(url_for("index"))

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if email in users and users[email]["password"] == password:
            session["user"] = email
            users[email]["is_logged_in"] = True
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password"
        )

    return render_template("login.html")



@app.route("/logout")
def logout():
    email = session.get("user")
    if email and email in users:
        users[email]["is_logged_in"] = False

    session.pop("user", None)
    return redirect(url_for("index"))


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["user"],
        users=users
    )

@app.route("/admin")
def admin_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    email = session["user"]

    # role-based access
    if users.get(email, {}).get("role") != "admin":
        return "Unauthorized", 403

    return render_template(
        "admin.html",
        users=users,
        username=email
    )


@app.route("/admin/delete/<email>", methods=["POST"])
def admin_delete_user(email):
    # must be logged in
    if "user" not in session:
        return "Unauthorized", 403

    current_user = session["user"]

    # role-based check (FINAL & CORRECT)
    if users.get(current_user, {}).get("role") != "admin":
        return "Unauthorized", 403

    # admin should not delete himself
    if email == current_user:
        return redirect(url_for("admin_dashboard"))

    # delete user
    if email in users:
        users.pop(email)
        alerts.pop(email, None)

    return redirect(url_for("admin_dashboard"))



@app.route("/prices")
def prices():
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        "ids": "bitcoin,ethereum",
        "vs_currencies": "usd"
    }

    data = requests.get(url, params=params).json()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for coin in data:
        price_history.setdefault(coin, [])
        price_history[coin].append({
            "time": now,
            "price": data[coin]["usd"]
        })

    return jsonify({
        "bitcoin": data["bitcoin"]["usd"],
        "ethereum": data["ethereum"]["usd"]
    })

# =========================
# ALERTS
# =========================
import uuid

@app.route("/alerts")
def alerts_page():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template(
        "alerts.html",
        username=session["user"]
    )


@app.route("/alerts", methods=["GET", "POST"])
def user_alerts():
    if "user" not in session:
        return jsonify([])

    email = session["user"]
    alerts.setdefault(email, [])

    # GET → return JSON alerts
    if request.method == "GET":
        return jsonify(alerts[email])

    # POST → create alert (JSON)
    data = request.get_json()
    alert = {
        "id": str(uuid.uuid4()),
        "coin": data["coin"],
        "condition": data["condition"],
        "price": data["price"]
    }
    alerts[email].append(alert)
    return jsonify({"status": "created"})

@app.route("/alerts/data", methods=["GET", "POST"])
def alerts_data():
    if "user" not in session:
        return jsonify([])

    email = session["user"]
    alerts.setdefault(email, [])

    # GET → send alerts
    if request.method == "GET":
        return jsonify(alerts[email])

    # POST → create alert
    data = request.get_json()
    alerts[email].append({
        "id": str(uuid.uuid4()),
        "coin": data["coin"],
        "condition": data["condition"],
        "price": data["price"]
    })
    return jsonify({"status": "created"})


@app.route("/alerts/data/<alert_id>", methods=["DELETE", "PUT"])
def modify_alert_api(alert_id):
    email = session.get("user")
    if not email:
        return jsonify({"error": "unauthorized"}), 401

    user_alerts = alerts.get(email, [])

    # DELETE
    if request.method == "DELETE":
        alerts[email] = [a for a in user_alerts if a["id"] != alert_id]
        return jsonify({"status": "deleted"})

    # UPDATE
    if request.method == "PUT":
        data = request.get_json()
        for a in user_alerts:
            if a["id"] == alert_id:
                a["price"] = data["price"]
                a["condition"] = data.get("condition", a["condition"])
        return jsonify({"status": "updated"})



@app.route("/history")
def history():

    if "user" not in session:
        return redirect(url_for("login"))
    return render_template(
        "history.html",
        username=session["user"],
        alerts=alerts.get(session["user"], [])
    )
    
@app.route("/history/<coin>")
def history_api(coin):
    history = price_history.get(coin, [])

    return jsonify({
        "times": [h["time"] for h in history],
        "prices": [h["price"] for h in history]
    })


if __name__ == "__main__":
    app.run(debug=True)
