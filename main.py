#Daniel Ajayi doa0057 CSCE 3550

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

def init_database():
    conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
init_database()

def generate_and_store_keys():
    conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
    cursor = conn.cursor()

    # Generate keys
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize keys to PEM format
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store valid key (expires in 1 hour)
    valid_exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (valid_pem, valid_exp))

    # Store expired key (expired 1 hour ago)
    expired_exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (expired_pem, expired_exp))

    conn.commit()
    conn.close()


generate_and_store_keys()


def get_key_from_db(expired=False):
    """Retrieve a key from the database based on expiry status."""

    conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
    cursor = conn.cursor()

    current_time = int(datetime.datetime.utcnow().timestamp())

    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1', (current_time,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ? LIMIT 1', (current_time,))

    result = cursor.fetchone()

    if result:
        return {
            'kid': result[0],
            'key': result[1]
        }
    raise ValueError("No suitable key found")


def get_valid_keys():
    """Retrieve all valid keys from the database."""

    conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
    cursor = conn.cursor()

    current_time = int(datetime.datetime.utcnow().timestamp())
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (current_time,))
    keys = []
    for row in cursor.fetchall():
        keys.append({
            'kid': row[0],
            'key': row[1]
        })
    conn.commit()
    conn.close()
    return keys


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            try:
                # Get correct key based on 'expired' parameter
                key_data = get_key_from_db('expired' in params)

                # Create JWT headers and payload
                headers = {
                    "kid": str(key_data['kid'])
                }

                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }

                if 'expired' in params:
                    token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

                # Sign and return the JWT
                encoded_jwt = jwt.encode(token_payload, key_data['key'], algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return

            except Exception as e:
                print(f"Error in POST /auth: {str(e)}")
                self.send_response(500)
                self.end_headers()
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            try:
                # Get all valid keys
                valid_keys = get_valid_keys()

                # Prepare JWKS response
                keys_list = []
                for key_data in valid_keys:
                    # Load the private key
                    private_key = serialization.load_pem_private_key(
                        key_data['key'],
                        password=None
                    )

                    # Get the public key
                    public_key = private_key.public_key()

                    # Get the public numbers (n, e) directly from the public key
                    public_numbers = public_key.public_numbers()

                    keys_list.append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": str(key_data['kid']),
                        "n": int_to_base64(public_numbers.n),
                        "e": int_to_base64(public_numbers.e),
                    })

                response = {"keys": keys_list}

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(response), "utf-8"))
                return

            except Exception as e:
                print(f"Error in GET /.well-known/jwks.json: {str(e)}")
                self.send_response(500)
                self.end_headers()
                return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    # Start the web server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server started at http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()