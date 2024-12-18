from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import jwt
import uuid
import sqlite3
import base64
import os
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from collections import defaultdict
import time

app = Flask(__name__)

# Rate limiting configuration
RATE_LIMIT = 10  # maximum requests
WINDOW_SIZE = 1   # in seconds

# Dictionary to track request timestamps for each IP
request_counts = defaultdict(list)

keys = {}


folder_path = "data"
database_name = "totally_not_my_privateKeys.db"# Specify the absolute path to your database file
db_path = os.path.join(os.path.dirname(__file__), folder_path, database_name)

def rate_limiter():
    ip = request.remote_addr
    current_time = time.time()
    
    # Remove timestamps older than the window size
    request_counts[ip] = [timestamp for timestamp in request_counts[ip] if current_time - timestamp < WINDOW_SIZE]
    
    # Check if the limit is exceeded
    if len(request_counts[ip]) >= RATE_LIMIT:
        return False
    
    # Log the current request timestamp
    request_counts[ip].append(current_time)
    return True


def get_encryption_key():
    key = os.environ.get('NOT_MY_KEY')
    if not key:
        raise ValueError("Encryption key not found in environment variables")
    return key.encode()

def encrypt_private_key(private_key_bytes):
    fernet = Fernet(get_encryption_key())
    return fernet.encrypt(private_key_bytes)

def decrypt_private_key(encrypted_private_key):
    fernet = Fernet(get_encryption_key())
    return fernet.decrypt(encrypted_private_key)

def private_key_to_jwk(kid, private_key):
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    
    return {
        "kid": str(kid),
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }

def get_valid_keys_from_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    c.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    rows = c.fetchall()
    conn.close()
    
    valid_keys = []
    for row in rows:
        kid, encrypted_key_bytes, exp = row
        decrypted_key_bytes = decrypt_private_key(encrypted_key_bytes)
        private_key = serialization.load_pem_private_key(decrypted_key_bytes, password=None)
        valid_keys.append((kid, private_key, exp))
    
    return valid_keys

def get_key_from_db(expired=False):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    
    if expired:
        c.execute("SELECT kid, key, exp FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (current_time,))
    else:
        # c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
        c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1", (current_time,))
    row = c.fetchone()
    conn.close()
    
    if row:
        kid, encrypted_key_bytes, exp = row
        decrypted_key_bytes = decrypt_private_key(encrypted_key_bytes)
        private_key = serialization.load_pem_private_key(decrypted_key_bytes, password=None)
        return kid, private_key, exp
    return None, None, None

def init_db(clear_db = False):
    if clear_db:
        if os.path.exists(db_path):
            os.remove(db_path)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (kid INTEGER PRIMARY KEY AUTOINCREMENT,
                  key BLOB NOT NULL,
                  exp INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL,
                 email TEXT UNIQUE,
                 date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 last_login TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 request_ip TEXT NOT NULL,
                 request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 user_id INTEGER,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

def generate_key_pair(expiry_days=30):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
   
    exp = datetime.now(timezone.utc) + timedelta(days=expiry_days)
    exp_int = int(exp.timestamp())
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    encrypted_private_key = encrypt_private_key(private_pem)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
  
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_private_key, exp_int))
    conn.commit()
    kid = c.lastrowid
    
    conn.close()
    
    return kid



def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return jwt.utils.base64url_encode(value_bytes).decode('ascii')


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    valid_keys = get_valid_keys_from_db()
    jwks = {
        "keys": [private_key_to_jwk(kid, private_key) for kid, private_key, _ in valid_keys]
    }
    return jsonify(jwks)


@app.route('/auth', methods=['POST'])
def authenticate():
    if not rate_limiter():
        return jsonify({"error": "Too Many Requests"}), 429
    
    username = request.json.get('username', '')
    use_expired = request.args.get('expired', 'false').lower() == 'true'

    kid, private_key, exp = get_key_from_db(expired=use_expired)
    
    if not private_key:
        return jsonify({"error": "No suitable key found"}), 400

    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": exp,
        "kid": str(kid)  # Include the kid in the payload
    }

    headers = {
        "kid": str(kid)
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers = headers)

    # Log authentication request
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Get user_id
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user_row = c.fetchone()
    user_id = user_row[0] if user_row else None
    
    # Log the request
    c.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
              (request.remote_addr, user_id))
    conn.commit()
    conn.close()


    return jsonify({
        "token": token,
        "expires": payload['exp'],
        "used_expired_key": use_expired
    })


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400

    # Generate a secure password using UUIDv4
    password = str(uuid.uuid4())

    # Hash the password using Argon2
    ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
    password_hash = ph.hash(password)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                  (username, password_hash, email))
        conn.commit()
        conn.close()
        return jsonify({"password": password}), 201  # 201 Created
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  