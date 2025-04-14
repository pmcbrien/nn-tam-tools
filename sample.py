from flask import Flask, request, jsonify
from noname.agent import Agent

app = Flask(__name__)
agent = Agent()
agent.instrument(app=app)

# Simulated in-memory database
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user1": {"password": "password", "role": "user"},
    "user2": {"password": "password", "role": "user"}
}

tokens = {}  # Insecure token handling

accounts = {
    "123456": {
        "owner": "user1",
        "balance": 1000.0,
        "transactions": [],
        "credit_card_number": "4111111111111111",
        "ssn": "040-12-1234",
        "bday": "01/01/2020"
    },
    "654321": {
        "owner": "user2",
        "balance": 5000.0,
        "transactions": [],
        "credit_card_number": "5555555555554444",
        "ssn": "123-45-6789",
        "bday": "12/12/1990"
    },
    "789012": {
        "owner": "admin",
        "balance": 99999.0,
        "transactions": [],
        "credit_card_number": "378282246310005",
        "ssn": "999-99-9999",
        "bday": "03/03/1980"
    }
}

# 1. Broken Object Level Authorization (BOLA)
@app.route('/accounts/<account_id>', methods=['GET'])
def get_account(account_id):
    # No check if user owns the account
    return jsonify(accounts.get(account_id, {"error": "Not found"}))

# 2. Broken Authentication
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = data.get("username")
    password = data.get("password")

    if user in users and users[user]["password"] == password:
        token = f"token-{user}"  # Predictable and insecure
        tokens[token] = user
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

# 3. Sensitive Data Exposure / Excessive Data Exposure
@app.route('/users', methods=['GET'])
def list_users():
    return jsonify(users)  # Exposes passwords and roles

# 4. Lack of Rate Limiting
@app.route('/spam', methods=['GET'])
def spam():
    return jsonify({"message": "No rate limit here, spam away!"})

# 5. Broken Function Level Authorization
@app.route('/admin/delete_all', methods=['POST'])
def delete_all_data():
    # No privilege check
    accounts.clear()
    return jsonify({"message": "All accounts deleted!"})

# 6. Mass Assignment
@app.route('/update_user', methods=['POST'])
def update_user():
    data = request.get_json()
    user = data.get("username")
    if user in users:
        users[user].update(data)  # Overwrites anything, including password/role
        return jsonify({"message": "User updated"})
    return jsonify({"error": "User not found"}), 404

# 7. Security Misconfiguration
@app.route('/debug', methods=['POST'])
def debug_mode():
    import os
    cmd = request.json.get("cmd")
    os.system(cmd)  # Command injection vulnerability
    return jsonify({"message": "Command executed"})

# 8. Injection (Simulated SQL Injection)
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get("q")
    return jsonify({"results": f"Simulated SQL: SELECT * FROM users WHERE name = '{query}'"})

# 9. Improper Assets Management
@app.route('/old-api/users', methods=['GET'])
def old_api():
    return jsonify({"message": "Deprecated endpoint. Still active."})

# 10. Unsafe Consumption of 3rd Party APIs
@app.route('/proxy', methods=['POST'])
def proxy_request():
    import requests
    url = request.json.get("url")
    try:
        r = requests.get(url)  # SSRF risk
        return jsonify({"response": r.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
