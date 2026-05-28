import os
import sys
import json
import hashlib
import secrets
import base64
import configparser
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
config = configparser.ConfigParser()
config.read(os.path.join(SERVER_DIR, 'configserver.ini'), encoding='utf-8')

BASE_DIR = config.get('paths', 'base_dir')
FILEAUTH = config.get('security', 'FILEAUTH', fallback='null')
MASTER_KEY = b'ServerManagerMasterKey2024!@#$%^&*()'

def generate_auth_file(filepath, size_kb=10240):
    d = os.path.dirname(filepath)
    if d: os.makedirs(d, exist_ok=True)
    random_data = secrets.token_bytes(size_kb * 1024)
    signature = hashlib.sha256(b'ServerManager2024' + random_data[:1000]).digest()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(MASTER_KEY))
    fernet = Fernet(key)
    data = {'signature': base64.b64encode(signature).decode(), 'created': datetime.now().isoformat(), 'size': size_kb * 1024, 'checksum': hashlib.sha256(random_data).hexdigest()}
    encrypted = fernet.encrypt(random_data + b'|||' + json.dumps(data).encode())
    with open(filepath, 'wb') as f:
        f.write(salt + encrypted)
    print(f"Auth file created: {filepath}")

def generate_guest_key(name="Guest", ip="*", user_agent="*", expires="30d", permissions=None):
    if permissions is None:
        permissions = {
            'files': True, 'edit': True, 'delete': False, 'download': True, 'upload': False,
            'view_logs': False, 'rename': True, 'extract': True, 'archive': True,
            'start_servers': False, 'terminal': False, 'admin_access': False,
            'allowed_paths': '*', 'allowed_files': '*', 'allowed_logs': '*', 'allowed_servers': '*'
        }
    
    token = secrets.token_hex(32)
    created = datetime.now()
    
    if expires == 'never':
        expires_str = 'never'
    else:
        days = 0
        if expires.endswith('d'):
            days = int(expires[:-1])
        elif expires.endswith('h'):
            days = int(expires[:-1]) / 24
        elif expires.endswith('m'):
            days = int(expires[:-1]) / 1440
        else:
            days = 30
        expires_str = (created + timedelta(days=days)).isoformat()
    
    key_data = {
        'token': token, 'name': name, 'ip': ip, 'user_agent': user_agent,
        'created': created.isoformat(), 'expires': expires_str,
        'permissions': permissions
    }
    
    keys_file = os.path.join(SERVER_DIR, 'keys', 'guest_keys.json')
    os.makedirs(os.path.dirname(keys_file), exist_ok=True)
    keys = []
    if os.path.exists(keys_file):
        with open(keys_file, 'r', encoding='utf-8') as f:
            try: keys = json.load(f)
            except: keys = []
    
    keys.append(key_data)
    with open(keys_file, 'w', encoding='utf-8') as f:
        json.dump(keys, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*60}")
    print(f"KEY GENERATED: {name}")
    print(f"Token: {token}")
    print(f"Expires: {expires_str}")
    print(f"{'='*60}")
    return token

def main():
    print("Server Manager Key Generator")
    print("1. Generate Auth File")
    print("2. Generate Key")
    print("0. Exit")
    
    choice = input("Select: ").strip()
    if choice == '1':
        fp = input(f"Path [{FILEAUTH}]: ").strip() or FILEAUTH
        if fp != 'null': generate_auth_file(fp)
    elif choice == '2':
        name = input("Name: ").strip() or "Guest"
        exp = input("Expires (30d/24h/60m/never) [30d]: ").strip() or "30d"
        generate_guest_key(name, expires=exp)

if __name__ == '__main__':
    main()