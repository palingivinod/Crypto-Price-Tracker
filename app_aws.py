from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import boto3
import requests
from datetime import datetime
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

app = Flask(__name__)
app.secret_key = "crypto_secret_key"

# =========================
# AWS CONFIG
# =========================
REGION = "us-east-1"

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

USERS_TABLE = dynamodb.Table("Users")
ALERTS_TABLE = dynamodb.Table("Alerts")
HISTORY_TABLE = dynamodb.Table("PriceHistory")

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:crypto_price_alerts"

# =========================
# SNS HELPER
# =========================
def send_sns_alert(subject, message):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print("SNS Error:", e)

# =========================
# AUTH
# =========================
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

        res = USERS_TABLE.get_item(Key={"email": email})
        if "Item" in res:
            return "User already exists!"

        USERS_TABLE.put_item(Item={
            "email": email,
            "password": password
        })

        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        res = USERS_TABLE.get_item(Key={"email": email})
        if "Item" in res and res["Item"]["password"] == password:
            session["user"] = email
            return redirect(url_for("dashboard"))

        return "Invalid credentials!"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("index"))

    res = ALERTS_TABLE.get_item(Key={"email": session["user"]})
    alerts = res.get("Item", {}).get("alerts", [])

    return render_template("dashboard.html", alerts=alerts)

# =========================
# REAL-TIME PRICES
# =========================
@app.route("/api/prices")
def prices():
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {"ids": "bitcoin,ethereum", "vs_currencies": "usd"}

    data = requests.get(url, params=params).json()
    now = datetime.utcnow().isoformat()

    for coin in data:
        price = data[coin]["usd"]

        HISTORY_TABLE.put_item(Item={
            "coin": coin,
            "timestamp": now,
            "price": price
        })

        # Alert check
        res = ALERTS_TABLE.get_item(Key={"email": session.get("user", "")})
        for alert in res.get("Item", {}).get("alerts", []):
            if alert["coin"] == coin and price <= float(alert["threshold"]):
                send_sns_alert(
                    f"{coin.upper()} Price Alert",
                    f"{coin} price dropped to ${price}"
                )

    return jsonify({
        "bitcoin": data["bitcoin"]["usd"],
        "ethereum": data["ethereum"]["usd"]
    })

# =========================
# ALERTS
# =========================
@app.route("/alerts", methods=["GET", "POST"])
def alerts():
    if "user" not in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        coin = request.form["coin"]
        threshold = request.form["price"]

        ALERTS_TABLE.update_item(
            Key={"email": session["user"]},
            UpdateExpression="SET alerts = list_append(if_not_exists(alerts, :e), :a)",
            ExpressionAttributeValues={
                ":a": [{"coin": coin, "threshold": threshold}],
                ":e": []
            }
        )

        return redirect(url_for("dashboard"))

    return render_template("alerts.html")

# =========================
# HISTORY
# =========================
@app.route("/history")
def history():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("history.html")

@app.route("/api/history/<coin>")
def history_api(coin):
    res = HISTORY_TABLE.query(
        KeyConditionExpression=Key("coin").eq(coin)
    )

    items = res.get("Items", [])

    return jsonify({
        "times": [i["timestamp"] for i in items],
        "prices": [i["price"] for i in items]
    })

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
