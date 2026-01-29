from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import boto3
import uuid
import requests
from datetime import datetime
from boto3.dynamodb.conditions import Key

app = Flask(__name__)
app.secret_key = "crypto_secret_key"

REGION = "us-east-1"

dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

USERS_TABLE = dynamodb.Table("Users")
ALERTS_TABLE = dynamodb.Table("Alerts")
HISTORY_TABLE = dynamodb.Table("PriceHistory")

# 🔔 REPLACE WITH YOUR ARN
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:crypto-price-alerts"


def send_sns_alert(subject, message):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except Exception as e:
        print("SNS Error:", e)


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if "user" in session else render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role", "user")

        if "Item" in USERS_TABLE.get_item(Key={"email": email}):
            return render_template("register.html", error="User already exists")

        USERS_TABLE.put_item(Item={
            "email": email,
            "password": password,
            "role": role,
            "is_logged_in": False
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
            USERS_TABLE.update_item(
                Key={"email": email},
                UpdateExpression="SET is_logged_in = :v",
                ExpressionAttributeValues={":v": True}
            )
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")

@app.route("/logout")
def logout():
    email = session.get("user")
    if email:
        USERS_TABLE.update_item(
            Key={"email": email},
            UpdateExpression="SET is_logged_in = :v",
            ExpressionAttributeValues={":v": False}
        )
    session.pop("user", None)
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    users = USERS_TABLE.scan().get("Items", [])
    users_dict = {u["email"]: u for u in users}

    return render_template(
        "dashboard.html",
        username=session["user"],
        users=users_dict
    )

@app.route("/admin")
def admin_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    email = session["user"]
    admin = USERS_TABLE.get_item(Key={"email": email}).get("Item")

    if admin["role"] != "admin":
        return "Unauthorized", 403

    users = USERS_TABLE.scan().get("Items", [])
    users_dict = {u["email"]: u for u in users}

    return render_template(
        "admin.html",
        users=users_dict,
        username=email
    )

@app.route("/admin/delete/<email>", methods=["POST"])
def admin_delete_user(email):
    current = session.get("user")
    if not current:
        return "Unauthorized", 403

    admin = USERS_TABLE.get_item(Key={"email": current}).get("Item")
    if admin["role"] != "admin":
        return "Unauthorized", 403

    if email == current:
        return redirect(url_for("admin_dashboard"))

    USERS_TABLE.delete_item(Key={"email": email})

    alerts = ALERTS_TABLE.query(
        KeyConditionExpression=Key("email").eq(email)
    ).get("Items", [])

    for a in alerts:
        ALERTS_TABLE.delete_item(
            Key={"email": email, "id": a["id"]}
        )

    return redirect(url_for("admin_dashboard"))


@app.route("/prices")
def prices():
    data = requests.get(
        "https://api.coingecko.com/api/v3/simple/price",
        params={"ids": "bitcoin,ethereum", "vs_currencies": "usd"}
    ).json()

    now = datetime.utcnow().isoformat()
    all_alerts = ALERTS_TABLE.scan().get("Items", [])

    for coin in data:
        price = data[coin]["usd"]

        HISTORY_TABLE.put_item(Item={
            "coin": coin,
            "timestamp": now,
            "price": price
        })

        for alert in all_alerts:
            if alert["coin"] != coin:
                continue

            target = float(alert["price"])
            condition = alert["condition"]

            if (condition == "above" and price >= target) or \
               (condition == "below" and price <= target):

                send_sns_alert(
                    f"{coin.upper()} Price Alert",
                    f"{coin.upper()} price is ${price}, target was ${target}"
                )

    return jsonify({
        "bitcoin": data["bitcoin"]["usd"],
        "ethereum": data["ethereum"]["usd"]
    })


@app.route("/alerts")
def alerts_page():
    return redirect(url_for("login")) if "user" not in session else render_template("alerts.html", username=session["user"])

@app.route("/alerts/data", methods=["GET", "POST"])
def alerts_data():
    if "user" not in session:
        return jsonify([])

    email = session["user"]

    if request.method == "GET":
        res = ALERTS_TABLE.query(
            KeyConditionExpression=Key("email").eq(email)
        )
        return jsonify(res.get("Items", []))

    data = request.get_json()
    ALERTS_TABLE.put_item(Item={
        "email": email,
        "id": str(uuid.uuid4()),
        "coin": data["coin"],
        "condition": data["condition"],
        "price": data["price"]
    })
    return jsonify({"status": "created"})

@app.route("/alerts/data/<alert_id>", methods=["DELETE", "PUT"])
def modify_alert(alert_id):
    email = session.get("user")
    if not email:
        return jsonify({"error": "unauthorized"}), 401

    if request.method == "DELETE":
        ALERTS_TABLE.delete_item(
            Key={"email": email, "id": alert_id}
        )
        return jsonify({"status": "deleted"})

    data = request.get_json()
    ALERTS_TABLE.update_item(
        Key={"email": email, "id": alert_id},
        UpdateExpression="SET price=:p, condition=:c",
        ExpressionAttributeValues={
            ":p": data["price"],
            ":c": data["condition"]
        }
    )
    return jsonify({"status": "updated"})

@app.route("/history")
def history():
    return redirect(url_for("login")) if "user" not in session else render_template("history.html", username=session["user"])

@app.route("/history/<coin>")
def history_api(coin):
    res = HISTORY_TABLE.query(
        KeyConditionExpression=Key("coin").eq(coin)
    )
    items = res.get("Items", [])

    return jsonify({
        "times": [i["timestamp"] for i in items],
        "prices": [i["price"] for i in items]
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
