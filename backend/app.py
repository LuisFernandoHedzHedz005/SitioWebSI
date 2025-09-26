from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import os, bcrypt, jwt
from dotenv import load_dotenv
import re
import dns.resolver
from datetime import datetime, timedelta, timezone

load_dotenv()
app = Flask(__name__)
origins = [ os.getenv("LOCAL_URL"), os.getenv("PROD_URL") ]
CORS(app, resources={r"/api/*": {"origins": origins}})


MONGO_URI = os.getenv("MONGO_URI")

#Eliminacion de print de mongoURI
print(f"--- Intentando conectar con URI: ---")

#eliminando secret key por defecto en caso de no estar presente en el archivo .env
JWT_SECRET = os.getenv("SECRET_KEY")
if not JWT_SECRET:
    raise ValueError("No se encontró la variable de entorno SECRET_KEY")

client = MongoClient(MONGO_URI, tls=True)
db = client.get_default_database()
users = db.users

blocklist = None

def load_blocklist():
    global blocklist
    if blocklist is None:
        try:
            filepath = os.path.join(os.path.dirname(__file__), 'disposable_email_blocklist.conf')
            with open(filepath, 'r', encoding='utf-8') as f:
                blocklist = [line.strip() for line in f if line.strip()]
                print("lista de dominios cargada con exito")
        except FileNotFoundError:
            print("Archivo de lista de bloqueo no encontrado. No se aplicarán restricciones de correo desechable.")
            blocklist = []
        except Exception as e:
            print(f"Error al obtener la ruta del archivo: {e}")
            blocklist = []
            return
        
def is_disposable_email(email):
    if blocklist is None:
        load_blocklist()
    if "@" not in email:
        return False
    
    domain = email.split('@')[-1]
    return domain in blocklist

def validate_email_estructure(email):
    exp_reg = r"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
    return re.match(exp_reg, email) is not None

def validate_email_domain(email):
   if "@" not in email:
       return False
   
   domain = email.split('@')[1]
   try:
       mx_records = dns.resolver.resolve(domain, 'MX')
       return len(mx_records) > 0
   except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
       return False 
   except Exception as e:
       print(f"Error al validar el dominio del correo: {e}")
       return False
   
with app.app_context():
    load_blocklist()

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    # En vez de recibir el rol de user desde el frontend,, asignarlo automaticamente para evitar escalacion de privilegios
    # role = data.get("role", "user")
    role = "user"

     # Validar que el rol sea 'user' para evitar escalación de privilegios
    if role != "user":
        return jsonify({"error": "rol inválido"}), 400
    
    if not email or not password:
        return jsonify({"error": "email y contraseña son requeridos"}), 400
    
    if not validate_email_estructure(email):
        return jsonify({"error": "estructura de email inválida"}), 400
    
    if is_disposable_email(email):
        return jsonify({"error": "datos incorrectos"}), 400
    
    if not validate_email_domain(email):
        return jsonify({"error": "datos incorrectos"}), 400

    if users.find_one({"email": email}):
        return jsonify({"error": "datos incorrectos"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "la contraseña debe tener al menos 6 caracteres"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users.insert_one({"email": email, "password": pw_hash, "role": role, "intents" : 0})
    return jsonify({"ok": True}), 201

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    user = users.find_one({"email": email})

    if not email or not password:
        return jsonify({"error": "email y contraseña son requeridos"}), 400

    if not user:
        return jsonify({"error": "credenciales inválidas"}), 401
    
    intents = user.get("intents", 0)
    if intents >= 5:
        return jsonify({"error": "cuenta bloqueada por múltiples intentos fallidos. Contacta con un administrador"}), 403
    
    validate_password = bcrypt.checkpw(password.encode(), user["password"])

    if not validate_password:
        users.update_one({"email": email}, {"$inc": {"intents": 1}})
        return jsonify({"error": "credenciales inválidas"}), 401
    
    if intents > 0:
        users.update_one({"email": email}, {"$set": {"intents": 0}})

    token_payload = {
        "email": email,
        "role": user.get("role", "user"),
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "iat": datetime.now(timezone.utc)
    }

    token = jwt.encode(token_payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})

@app.route("/api/me")
def me():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "no autorizado"}), 401

    token = auth.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expirado"}), 401
    except Exception:
        return jsonify({"error": "token inválido"}), 401

    return jsonify({"email": payload["email"], "role": payload.get("role", "user")})

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(debug=True)
