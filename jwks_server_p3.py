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

# NOT_MY_KEY_var = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
# print(key)

# In-memory key storage (in production, use a secure key management system)
keys = {}
folder_path = "C:\\Users\\salma\\Downloads\\CSCE3550_Windows_x86_64 (1)"
# folder_path = r"C:\Users\salma\OneDrive - UNT System\Documents\project1\py3"
database_name = "totally_not_my_privateKeys.db"# Specify the absolute path to your database file
db_path = os.path.abspath(f"{folder_path}/{database_name}")

def adapt_datetime(dt):
    return dt.isoformat()

def convert_datetime(s):
    return datetime.fromisoformat(s.decode('utf-8'))

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
        c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
    
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
    # exp_int = int(exp)
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    
    # kid = str(kid)
    encrypted_private_key = encrypt_private_key(private_pem)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
  
    # c.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", (kid, private_pem, exp_int))
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_private_key, exp_int))
    conn.commit()
    kid = c.lastrowid
    
    conn.close()
    
    return kid

def get_jwk(kid):
    key_data = keys[kid]
    public_key = key_data['public_key']
    numbers = public_key.public_numbers()
    return {
        "kid": str(kid),
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(numbers.n), #modulus
        "e": int_to_base64(numbers.e), #exponent
        "exp": int(key_data['exp'].timestamp())
    }

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return jwt.utils.base64url_encode(value_bytes).decode('ascii')

# Generate initial keys
# current_kid = generate_key_pair()
# expired_kid = generate_key_pair(-30)  # Generate an expired key

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    valid_keys = get_valid_keys_from_db()
    jwks = {
        "keys": [private_key_to_jwk(kid, private_key) for kid, private_key, _ in valid_keys]
    }
    return jsonify(jwks)
    # current_time = datetime.now(timezone.utc)
    # unexpired_keys = []

    # for kid, key_data in keys.items():
    #     if key_data['exp'] > current_time:
    #         jwk = get_jwk(kid)  # Assuming you have a get_jwk function
    #         unexpired_keys.append(jwk)

    # return jsonify({"keys": unexpired_keys})

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

    # Use parameterized query for insertion
    # conn = get_db_connection()
    # conn = sqlite3.connect(db_path)
    # c = conn.cursor()
    # c.execute("INSERT INTO auth_logs (username, token, exp) VALUES (?, ?, ?)", 
    #           (username, token, exp))
    # conn.commit()
    # conn.close()

    return jsonify({
        "token": token,
        # "expires": payload['exp'].isoformat(),
        "expires": payload['exp'],
        "used_expired_key": use_expired
    })

def load_keys():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # c.execute("SELECT kid, private_key, public_key, exp FROM keys")
    c.execute("SELECT kid, key, exp FROM keys")
    rows = c.fetchall()
    conn.close()

    for row in rows:
        kid, key_bytes, exp = row
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        keys[kid] = {
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "exp": datetime.fromtimestamp(exp, tz=timezone.utc)
        }
        # kid, private_pem, public_pem, exp_str = row
        # private_key = serialization.load_pem_private_key(private_pem, password=None)
        # public_key = serialization.load_pem_public_key(public_pem)
        # exp = datetime.fromisoformat(exp_str)
        # keys[kid] = {
        #     "private_key": private_key,
        #     "public_key": public_key,
        #     "exp": exp
        # }

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

# if __name__ == '__main__':
    # init_db()
    
    #  # Check if we have valid and expired keys
    # valid_kid, _, _ = get_key_from_db(expired=False)
    # expired_kid, _, _ = get_key_from_db(expired=True)
    
    # if not valid_kid:
    #     generate_key_pair(30)  # Generate a valid key (30 days expiry)
    #     print(f"not valid key")
    # if not expired_kid:
    #     generate_key_pair(-30)  # Generate an expired key (30 days in the past)
    #     print(f"valid key")
    # app.run(host='0.0.0.0', port=8080)

if __name__ == '__main__':
    init_db(True)
    
    # Test AES encryption of private keys
    # private_key = rsa.generate_private_key(
    #     public_exponent=65537,
    #     key_size=2048
    # )
    # private_pem = private_key.private_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PrivateFormat.PKCS8,
    #     encryption_algorithm=serialization.NoEncryption()
    # )
    # encrypted_private_key = encrypt_private_key(private_pem)
    # decrypted_private_key = decrypt_private_key(encrypted_private_key)
    # print("AES Encryption Test:", private_pem == decrypted_private_key)

     # Test AES encryption of private keys
    test_kid = generate_key_pair(30)
    kid, private_key, exp = get_key_from_db()
    
    if kid and private_key:
        print("AES Encryption Test:")
        print(f"Generated key with ID: {test_kid}")
        print(f"Retrieved key with ID: {kid}")
        print(f"Keys match: {test_kid == kid}")
        print(f"Private key successfully decrypted: {private_key is not None}")
    else:
        print("Failed to generate or retrieve encrypted key")
    # kid = generate_key_pair(30)
    # retrieved_kid, encrypted_private_key, exp = get_key_from_db()
    # print(f"type: {type(encrypted_private_key)}")
    # if retrieved_kid and encrypted_private_key:
    #     decrypted_private_key = decrypt_private_key(encrypted_private_key)
    #     print("AES Encryption Test:", isinstance(decrypted_private_key, bytes))
    #     print(f"Generated and retrieved key with ID: {retrieved_kid}")
    # else:
    #     print("Failed to generate or retrieve encrypted key")

    # Test user registration
    with app.test_client() as client:
        test_user_name = "uwu_user8"
        test_email = "uwu8@example.com"

        response = client.post('/register', json={
            "username": test_user_name,
            "email": test_email
        })
        print("User Registration Test:", response.status_code == 201)
        print(f"response status code: { response.status_code }")
        print("Generated Password:", response.get_json().get("password"))

        
        # Test authentication logging
        auth_response = client.post('/auth', json={
            "username": f"{test_user_name}"
        })
        print(f"auth status code: {auth_response.status_code }")
        print("Authentication Test:", auth_response.status_code == 200)

        # Verify auth log
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM auth_logs WHERE user_id = (SELECT id FROM users WHERE username = ?)", (test_user_name,))
        log_entry = c.fetchone()
        conn.close()

        print("Auth Log Test:", log_entry is not None)
        if log_entry:
            print("Log Entry:", log_entry)


    app.run(host='0.0.0.0', port=8080)   
    
