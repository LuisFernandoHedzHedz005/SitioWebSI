from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os, bcrypt, jwt
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app)

MONGO_URI = os.getenv("MONGO_URI")

#Eliminacion de print de mongoURI
print(f"--- Intentando conectar con URI: ---")
JWT_SECRET = os.getenv("SECRET_KEY", "devsecret")

client = MongoClient(MONGO_URI, tls=True)
db = client.get_default_database()
users = db.users

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if users.find_one({"email": email}):
        return jsonify({"error": "usuario ya existe"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users.insert_one({"email": email, "password": pw_hash, "role": role})
    return jsonify({"ok": True}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = users.find_one({"email": email})

    if not user or not bcrypt.checkpw(password.encode(), user["password"]):
        return jsonify({"error": "credenciales inválidas"}), 400

    token = jwt.encode({"email": email, "role": user.get("role", "user")}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/api/me")
def me():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "no autorizado"}), 401

    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify({"error": "token inválido"}), 401

    return jsonify({"email": payload["email"], "role": payload.get("role", "user")})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)
