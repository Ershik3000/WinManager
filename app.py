import os
import sys
import json
import shutil
import subprocess
import threading
import time
import hashlib
import secrets
import zipfile
import tarfile
import re
import ssl
import configparser
import base64
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, send_file, redirect, url_for, abort
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SERVER_DIR, 'configserver.ini')

if not os.path.exists(CONFIG_FILE):
    print(f"ERROR: Config file not found: {CONFIG_FILE}")
    sys.exit(1)

config = configparser.ConfigParser()
config.read(CONFIG_FILE, encoding='utf-8')

PASSWORD = config.get('security', 'PASSWORD')
QUESTION = config.get('security', 'QUESTION')
ANSWER = config.get('security', 'ANSWER')
BLOCK_TIME = config.getint('security', 'BLOCK_TIME')
MAX_ATTEMPTS = config.getint('security', 'MAX_ATTEMPTS')
SCAN_THRESHOLD = config.getint('security', 'SCAN_THRESHOLD')
ADMINPAGE = config.get('security', 'ADMINPAGE', fallback='/admin')
ADMINUserA = config.get('security', 'ADMINUserA', fallback='null')
IPv4ADMIN = config.get('security', 'IPv4ADMIN', fallback='null')
IPADMIN = config.get('security', 'IPADMIN', fallback='null')
FILEAUTH = config.get('security', 'FILEAUTH', fallback='null')

PORTS = [int(p.strip()) for p in config.get('network', 'ports').split(',')]
LIMITS = [l.strip() for l in config.get('network', 'limits').split(',')]
UPLOAD_LIMIT_MB = config.getint('network', 'upload_limit_mb')
BASE_DIR = config.get('paths', 'base_dir')

SERVER_COUNT = config.getint('servers', 'count')
SERVERS = []
for i in range(1, SERVER_COUNT + 1):
    section = f'server_{i}'
    if config.has_section(section):
        SERVERS.append({
            'id': i,
            'name': config.get(section, 'name', fallback=f'Server {i}'),
            'folder': config.get(section, 'folder', fallback=f'server{i}'),
            'command': config.get(section, 'command', fallback='python server.py'),
            'path': config.get(section, 'path', fallback=os.path.join(BASE_DIR, f'server{i}')),
            'enabled': config.getboolean(section, 'enabled', fallback=True)
        })

LOGS_DIR = os.path.join(SERVER_DIR, "logs")
TEMP_DIR = os.path.join(SERVER_DIR, "temp")
KEYS_DIR = os.path.join(SERVER_DIR, "keys")

for d in [LOGS_DIR, TEMP_DIR, KEYS_DIR]:
    os.makedirs(d, exist_ok=True)

app = Flask(__name__, static_folder=os.path.join(SERVER_DIR, 'static'), static_url_path='/static')
app.secret_key = secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_LIMIT_MB * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=LIMITS, storage_uri="memory://")

login_attempts = defaultdict(list)
blocked_ips = set()
blocked_agents = set()

guest_keys = []
GUEST_KEYS_FILE = os.path.join(KEYS_DIR, 'guest_keys.json')
if os.path.exists(GUEST_KEYS_FILE):
    with open(GUEST_KEYS_FILE, 'r') as f:
        guest_keys = json.load(f)

def save_guest_keys():
    with open(GUEST_KEYS_FILE, 'w') as f:
        json.dump(guest_keys, f, indent=2)

active_users = {}
action_log = []
MAX_ACTIONS = 500

def log_action(user, action, details=""):
    entry = {
        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'user': user,
        'action': action,
        'details': details
    }
    action_log.append(entry)
    if len(action_log) > MAX_ACTIONS:
        action_log.pop(0)

OUR_PORTS = set(PORTS)
MASTER_KEY = b'ServerManagerMasterKey2024!@#$%^&*()'

log_files = {}
for s in SERVERS:
    log_files[f'server_{s["id"]}'] = os.path.join(LOGS_DIR, f'server_{s["id"]}.log')
log_files["terminal_cmd"] = os.path.join(LOGS_DIR, "terminal_cmd.log")

for lp in log_files.values():
    if isinstance(lp, str) and not os.path.exists(lp):
        with open(lp, 'w', encoding='utf-8') as f:
            f.write(f"=== {datetime.now()} ===\n")

processes = {}

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

def verify_auth_file(filepath):
    if FILEAUTH == 'null' or not CRYPTO_AVAILABLE:
        return True
    if not os.path.exists(filepath):
        return False
    try:
        with open(filepath, 'rb') as f:
            salt = f.read(16)
            encrypted = f.read()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(MASTER_KEY))
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        parts = decrypted.split(b'|||')
        if len(parts) != 2:
            return False
        random_data, json_data = parts[0], json.loads(parts[1].decode())
        if hashlib.sha256(random_data).hexdigest() != json_data.get('checksum'):
            return False
        expected_sig = hashlib.sha256(b'ServerManager2024' + random_data[:1000]).digest()
        actual_sig = base64.b64decode(json_data.get('signature', ''))
        return expected_sig == actual_sig
    except:
        return False

def check_basic_admin_access():
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')
    
    if IPv4ADMIN != 'null' and ip == IPv4ADMIN:
        return True
    if IPADMIN != 'null' and ip == IPADMIN:
        return True
    if ADMINUserA != 'null' and ua == ADMINUserA:
        return True
    
    if 'guest_token' in session:
        for key in guest_keys:
            if key['token'] == session['guest_token']:
                if key.get('permissions', {}).get('admin_access'):
                    if check_key_valid(key):
                        return True
                break
    
    if 'authenticated' in session:
        return True
    
    return False

def check_admin_full_access():
    if not check_basic_admin_access():
        return False
    if FILEAUTH != 'null':
        if 'admin_file_verified' not in session:
            return 'FILE_REQUIRED'
    return True

def check_key_valid(key):
    if key.get('expires') == 'never':
        return True
    try:
        exp = datetime.fromisoformat(key['expires'])
        return exp > datetime.now()
    except:
        return True

def check_bruteforce(ip):
    now = time.time()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < BLOCK_TIME]
    return len(login_attempts[ip]) < MAX_ATTEMPTS

def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', '')
        if ip in blocked_ips or ua in blocked_agents:
            abort(403)
        if 'authenticated' in session:
            if session.get('ip') == ip and session.get('user_agent') == ua:
                return f(*args, **kwargs)
        if 'guest_token' in session:
            for key in guest_keys:
                if key['token'] == session['guest_token']:
                    if check_key_valid(key):
                        if key['ip'] == '*' or key['ip'] == ip:
                            if key['user_agent'] == '*' or key['user_agent'] == ua:
                                return f(*args, **kwargs)
            session.pop('guest_token', None)
        return jsonify({'error': 'Not authenticated'}), 401
    return decorated_function

def get_permissions():
    if 'authenticated' in session:
        return {'files': True, 'edit': True, 'delete': True, 'download': True, 'upload': True,
                'view_logs': True, 'rename': True, 'extract': True, 'archive': True,
                'start_servers': True, 'terminal': True, 
                'admin_access': check_basic_admin_access(),
                'allowed_paths': '*', 'allowed_files': '*', 'allowed_logs': '*', 'allowed_servers': '*'}
    if 'guest_permissions' in session:
        return session['guest_permissions']
    return {'files': False, 'edit': False, 'delete': False, 'download': False, 'upload': False,
            'view_logs': False, 'rename': False, 'extract': False, 'archive': False,
            'start_servers': False, 'terminal': False, 'admin_access': False,
            'allowed_paths': [], 'allowed_files': [], 'allowed_logs': [], 'allowed_servers': []}

def check_file_access(path):
    perms = get_permissions()
    if perms.get('allowed_paths') == '*':
        return True
    allowed = perms.get('allowed_paths', [])
    if not allowed:
        return False
    for ap in allowed:
        try:
            if os.path.realpath(path).startswith(os.path.realpath(ap)):
                return True
        except:
            pass
    return False

def validate_path(path):
    try:
        real = os.path.realpath(os.path.normpath(path))
        base = os.path.realpath(BASE_DIR)
        if not real.startswith(base):
            return False
        if 'authenticated' in session:
            return True
        return check_file_access(real)
    except:
        return False

def write_log(log_name, message, log_type="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{log_type}] {message}\n"
    log_path = log_files.get(log_name)
    if log_path and isinstance(log_path, str):
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_entry)

def read_logs(log_name, lines=100):
    log_path = log_files.get(log_name)
    if not log_path or not isinstance(log_path, str) or not os.path.exists(log_path):
        return []
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()[-lines:]
    except:
        return []

def clear_logs(log_name):
    log_path = log_files.get(log_name)
    if log_path and isinstance(log_path, str):
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(f"=== Cleared {datetime.now()} ===\n")

def get_system_metrics():
    if not PSUTIL_AVAILABLE:
        return {'error': 'psutil not installed'}
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage(BASE_DIR)
        net = psutil.net_io_counters()
        return {
            'cpu': {'total': cpu, 'count': psutil.cpu_count()},
            'memory': {'total': mem.total, 'used': mem.used, 'percent': mem.percent},
            'swap': {'total': swap.total, 'used': swap.used, 'percent': swap.percent},
            'disk': {'total': disk.total, 'used': disk.used, 'percent': disk.percent},
            'network': {'bytes_sent': net.bytes_sent, 'bytes_recv': net.bytes_recv}
        }
    except:
        return {'error': 'Failed'}

def get_network_connections():
    if not PSUTIL_AVAILABLE:
        return {'connections': [], 'server_connections': []}
    try:
        all_conn, server_conn = [], []
        for conn in psutil.net_connections(kind='inet'):
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                pname = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                info = {'type': 'TCP' if conn.type == 1 else 'UDP', 'local': laddr, 'remote': raddr, 'status': conn.status, 'pid': conn.pid, 'process': pname}
                all_conn.append(info)
                if conn.laddr and conn.laddr.port in OUR_PORTS:
                    server_conn.append(info)
            except:
                continue
        return {'connections': all_conn, 'server_connections': server_conn}
    except:
        return {'connections': [], 'server_connections': []}

@app.before_request
def before_request():
    if 'authenticated' in session or 'guest_token' in session:
        user_key = session.get('guest_token') or session.get('session_token') or 'admin'
        if user_key in active_users:
            active_users[user_key]['last_activity'] = datetime.now().strftime("%H:%M:%S")

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(403)
def forbidden(e): return render_template('403.html'), 403
@app.errorhandler(404)
def not_found(e): return render_template('404.html'), 404
@app.errorhandler(429)
def too_many(e): return render_template('429.html'), 429

@app.route('/')
def index():
    if 'authenticated' in session:
        return render_template('file_manager.html', servers=SERVERS, config=config)
    if 'guest_token' in session:
        for key in guest_keys:
            if key['token'] == session['guest_token']:
                if check_key_valid(key):
                    return render_template('file_manager.html', servers=SERVERS, config=config, permissions=key.get('permissions', {}))
        session.pop('guest_token', None)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    ip = request.remote_addr
    if ip in blocked_ips:
        abort(403)
    
    if request.method == 'POST':
        data = request.json
        if not data:
            return jsonify({'success': False, 'message': 'Invalid request'}), 400
        
        login_type = data.get('type', 'password')
        
        if login_type == 'guest':
            token = data.get('token', '').strip()
            for key in guest_keys:
                if key['token'] == token:
                    if check_key_valid(key):
                        if key['ip'] == '*' or key['ip'] == ip:
                            ua = request.headers.get('User-Agent', '')
                            if key['user_agent'] == '*' or key['user_agent'] == ua:
                                session['guest_token'] = token
                                session['guest_name'] = key['name']
                                session['guest_permissions'] = key.get('permissions', {})
                                session['ip'] = ip
                                session['user_agent'] = ua
                                session['is_guest'] = True
                                
                                active_users[token] = {
                                    'name': key['name'], 'ip': ip, 'ua': ua[:50],
                                    'type': 'guest', 'login_time': datetime.now().strftime("%H:%M:%S"),
                                    'last_activity': datetime.now().strftime("%H:%M:%S"), 'actions': []
                                }
                                log_action(key['name'], 'login', f'Guest login from {ip}')
                                return jsonify({'success': True, 'message': f'Welcome, {key["name"]}!'})
                    return jsonify({'success': False, 'message': 'Key expired'})
            return jsonify({'success': False, 'message': 'Invalid key'})
        
        if not check_bruteforce(ip):
            blocked_ips.add(ip)
            abort(429)
        
        step = data.get('step')
        if step == '1':
            password = data.get('password', '')
            if hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256(PASSWORD.encode()).hexdigest():
                session['step1'] = True
                session['session_token'] = secrets.token_hex(32)
                session['ip'] = ip
                session['user_agent'] = request.headers.get('User-Agent')
                return jsonify({'success': True, 'message': QUESTION})
            login_attempts[ip].append(time.time())
            return jsonify({'success': False, 'message': 'Wrong password'})
        
        elif step == '2':
            if 'step1' not in session:
                return jsonify({'success': False, 'message': 'Session expired'})
            if data.get('answer', '').lower().strip() == ANSWER.lower().strip():
                session['step2'] = True
                session['authenticated'] = True
                session.permanent = True
                
                token = session.get('session_token')
                active_users[token] = {
                    'name': 'Admin', 'ip': ip, 'ua': request.headers.get('User-Agent', '')[:50],
                    'type': 'admin', 'login_time': datetime.now().strftime("%H:%M:%S"),
                    'last_activity': datetime.now().strftime("%H:%M:%S"), 'actions': []
                }
                log_action('Admin', 'login', f'Admin login from {ip}')
                return jsonify({'success': True, 'message': 'Success'})
            login_attempts[ip].append(time.time())
            return jsonify({'success': False, 'message': 'Wrong answer'})
    
    return render_template('login.html', question=QUESTION)

@app.route('/logout', methods=['POST'])
def logout():
    user_key = session.get('guest_token') or session.get('session_token')
    user_name = session.get('guest_name', 'Admin')
    if user_key and user_key in active_users:
        del active_users[user_key]
        log_action(user_name, 'logout', 'User logged out')
    session.clear()
    return jsonify({'success': True})

@app.route(ADMINPAGE)
def admin_panel():
    if not check_basic_admin_access():
        abort(403)
    
    if FILEAUTH != 'null' and 'admin_file_verified' not in session:
        return render_template('admin_verify.html', fileauth=FILEAUTH)
    
    return render_template('admin.html', servers=SERVERS, config=config)

@app.route('/api/admin/verify-file', methods=['POST'])
def verify_admin_file():
    if not check_basic_admin_access():
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if FILEAUTH == 'null':
        session['admin_file_verified'] = True
        return jsonify({'success': True})
    
    file = request.files.get('authfile')
    if not file:
        return jsonify({'success': False, 'message': 'No file uploaded'}), 400
    
    temp_path = os.path.join(TEMP_DIR, f'temp_auth_{secrets.token_hex(8)}.saa')
    file.save(temp_path)
    
    if verify_auth_file(temp_path):
        os.remove(temp_path)
        session['admin_file_verified'] = True
        log_action('Admin', 'verify_file', 'Auth file verified')
        return jsonify({'success': True})
    else:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'success': False, 'message': 'Invalid auth file'})

@app.route('/api/admin/sessions')
@limiter.exempt
def get_sessions():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    
    now = datetime.now()
    to_remove = []
    for k, v in active_users.items():
        try:
            last = datetime.strptime(v['last_activity'], "%H:%M:%S")
            if (now - last).seconds > 600:
                to_remove.append(k)
        except:
            pass
    for k in to_remove:
        del active_users[k]
    
    return jsonify({
        'active_users': list(active_users.values()),
        'blocked_ips': list(blocked_ips),
        'blocked_agents': list(blocked_agents),
        'action_log': action_log[-100:]
    })

@app.route('/api/admin/block/ip', methods=['POST'])
@limiter.exempt
def block_ip():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    ip = request.json.get('ip')
    if ip:
        blocked_ips.add(ip)
        log_action('Admin', 'block_ip', f'Blocked IP: {ip}')
        return jsonify({'success': True})
    return jsonify({'error': 'IP required'}), 400

@app.route('/api/admin/unblock/ip', methods=['POST'])
@limiter.exempt
def unblock_ip():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    ip = request.json.get('ip')
    if ip:
        blocked_ips.discard(ip)
        log_action('Admin', 'unblock_ip', f'Unblocked IP: {ip}')
        return jsonify({'success': True})
    return jsonify({'error': 'IP required'}), 400

@app.route('/api/admin/block/agent', methods=['POST'])
@limiter.exempt
def block_agent():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    agent = request.json.get('agent')
    if agent:
        blocked_agents.add(agent)
        log_action('Admin', 'block_agent', f'Blocked Agent: {agent[:50]}')
        return jsonify({'success': True})
    return jsonify({'error': 'Agent required'}), 400

@app.route('/api/admin/unblock/agent', methods=['POST'])
@limiter.exempt
def unblock_agent():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    agent = request.json.get('agent')
    if agent:
        blocked_agents.discard(agent)
        log_action('Admin', 'unblock_agent', f'Unblocked Agent: {agent[:50]}')
        return jsonify({'success': True})
    return jsonify({'error': 'Agent required'}), 400

@app.route('/api/admin/generate/key', methods=['POST'])
@limiter.exempt
def generate_key():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.json
    name = data.get('name', 'Guest').strip()
    
    for key in guest_keys:
        if key['name'].lower() == name.lower():
            return jsonify({'success': False, 'message': f'Name "{name}" already exists'}), 400
    
    token = secrets.token_hex(32)
    created = datetime.now()
    
    expires_setting = data.get('expires', '30d')
    if expires_setting == 'never':
        expires = 'never'
    else:
        days = data.get('days', 0)
        hours = data.get('hours', 0)
        minutes = data.get('minutes', 0)
        total_seconds = days * 86400 + hours * 3600 + minutes * 60
        if total_seconds <= 0:
            total_seconds = 30 * 86400
        expires = (created + timedelta(seconds=total_seconds)).isoformat()
    
    key_data = {
        'token': token,
        'name': name,
        'ip': data.get('ip', '*'),
        'user_agent': data.get('user_agent', '*'),
        'created': created.isoformat(),
        'expires': expires,
        'permissions': data.get('permissions', {})
    }
    
    guest_keys.append(key_data)
    save_guest_keys()
    
    log_action('Admin', 'generate_key', f'Generated key for: {name}')
    return jsonify({'success': True, 'key': key_data})

@app.route('/api/admin/keys')
@limiter.exempt
def get_keys():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    
    keys_with_status = []
    for key in guest_keys:
        k = dict(key)
        k['is_active'] = key['token'] in active_users
        k['valid'] = check_key_valid(key)
        keys_with_status.append(k)
    
    return jsonify({'keys': keys_with_status})

@app.route('/api/admin/delete/key', methods=['POST'])
@limiter.exempt
def delete_key():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    
    token = request.json.get('token')
    global guest_keys
    
    deleted_name = None
    for k in guest_keys:
        if k['token'] == token:
            deleted_name = k['name']
            break
    
    guest_keys = [k for k in guest_keys if k['token'] != token]
    save_guest_keys()
    
    if token in active_users:
        del active_users[token]
    
    log_action('Admin', 'delete_key', f'Deleted key: {deleted_name}')
    return jsonify({'success': True})

@app.route('/api/admin/kick/user', methods=['POST'])
@limiter.exempt
def kick_user():
    if check_admin_full_access() != True:
        return jsonify({'error': 'Access denied'}), 403
    
    token = request.json.get('token')
    if token and token in active_users:
        name = active_users[token]['name']
        del active_users[token]
        log_action('Admin', 'kick_user', f'Kicked: {name}')
        return jsonify({'success': True})
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/config')
@auth_required
def get_config():
    perms = get_permissions()
    return jsonify({
        'servers': SERVERS,
        'base_dir': BASE_DIR,
        'psutil_available': PSUTIL_AVAILABLE,
        'permissions': perms,
        'is_admin': check_basic_admin_access(),
        'is_guest': session.get('is_guest', False),
        'guest_name': session.get('guest_name', '')
    })

@app.route('/api/metrics')
@auth_required
@limiter.exempt
def get_metrics():
    return jsonify(get_system_metrics() or {})

@app.route('/api/connections')
@auth_required
@limiter.exempt
def get_connections():
    return jsonify(get_network_connections())

@app.route('/api/files')
@auth_required
def get_files():
    perms = get_permissions()
    if not perms.get('files'):
        return jsonify({'error': 'Permission denied'}), 403
    
    current_path = request.args.get('path', BASE_DIR)
    if not validate_path(current_path):
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        items = []
        for item in os.listdir(current_path):
            item_path = os.path.join(current_path, item)
            if not validate_path(item_path):
                continue
            is_dir = os.path.isdir(item_path)
            stat = os.stat(item_path)
            items.append({
                'name': item, 'is_dir': is_dir,
                'size': stat.st_size if not is_dir else 0,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                'path': item_path
            })
        items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
        return jsonify({
            'current_path': current_path, 'items': items,
            'parent_path': os.path.dirname(current_path) if current_path != BASE_DIR else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/read', methods=['POST'])
@auth_required
def read_file():
    perms = get_permissions()
    if not perms.get('files'):
        return jsonify({'error': 'Permission denied'}), 403
    
    path = request.json.get('path')
    if not validate_path(path):
        return jsonify({'error': 'Access denied'}), 403
    
    if session.get('is_guest'):
        allowed_files = perms.get('allowed_files', '*')
        if allowed_files != '*':
            if path not in allowed_files:
                return jsonify({'error': 'Permission denied for this file'}), 403
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        log_action(session.get('guest_name', 'Admin'), 'read_file', os.path.basename(path))
        return jsonify({'content': content, 'extension': os.path.splitext(path)[1]})
    except:
        return jsonify({'error': 'Cannot read file'}), 500

@app.route('/api/file/create', methods=['POST'])
@auth_required
def create_item():
    if not get_permissions().get('edit'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    path, name, is_dir = data.get('path'), secure_filename(data.get('name', '')), data.get('is_dir', False)
    if not name: return jsonify({'error': 'Invalid name'}), 400
    full_path = os.path.join(path, name)
    if not validate_path(full_path): return jsonify({'error': 'Access denied'}), 403
    try:
        if is_dir: os.makedirs(full_path, exist_ok=True)
        else:
            with open(full_path, 'w', encoding='utf-8') as f: f.write('')
        log_action(session.get('guest_name', 'Admin'), 'create', f'{name} in {path}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/delete', methods=['POST'])
@auth_required
def delete_item():
    if not get_permissions().get('delete'):
        return jsonify({'error': 'Permission denied'}), 403
    path = request.json.get('path')
    if not validate_path(path) or path in [BASE_DIR, LOGS_DIR, TEMP_DIR]:
        return jsonify({'error': 'Access denied'}), 403
    try:
        if os.path.isdir(path): shutil.rmtree(path)
        else: os.remove(path)
        log_action(session.get('guest_name', 'Admin'), 'delete', os.path.basename(path))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/rename', methods=['POST'])
@auth_required
def rename_item():
    if not get_permissions().get('rename'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    old_path, new_name = data.get('old_path'), secure_filename(data.get('new_name', ''))
    if not validate_path(old_path) or not new_name: return jsonify({'error': 'Access denied'}), 403
    new_path = os.path.join(os.path.dirname(old_path), new_name)
    if not validate_path(new_path): return jsonify({'error': 'Access denied'}), 403
    try:
        os.rename(old_path, new_path)
        log_action(session.get('guest_name', 'Admin'), 'rename', f'{os.path.basename(old_path)} -> {new_name}')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/move', methods=['POST'])
@auth_required
def move_item():
    if not get_permissions().get('rename'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    source, destination = data.get('source'), data.get('destination')
    if not validate_path(source) or not validate_path(destination):
        return jsonify({'error': 'Access denied'}), 403
    try:
        shutil.move(source, os.path.join(destination, os.path.basename(source)))
        log_action(session.get('guest_name', 'Admin'), 'move', os.path.basename(source))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/save', methods=['POST'])
@auth_required
def save_file():
    if not get_permissions().get('edit'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    path, content = data.get('path'), data.get('content', '')
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    try:
        with open(path, 'w', encoding='utf-8') as f: f.write(content)
        log_action(session.get('guest_name', 'Admin'), 'save', os.path.basename(path))
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file/upload', methods=['POST'])
@auth_required
@limiter.limit("10 per minute")
def upload_file():
    if not get_permissions().get('upload'):
        return jsonify({'error': 'Permission denied'}), 403
    path = request.form.get('path')
    file = request.files.get('file')
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    if file:
        filename = secure_filename(file.filename)
        if any(filename.lower().endswith(e) for e in ['.exe','.dll','.bat','.cmd','.ps1','.vbs']):
            return jsonify({'error': 'File type not allowed'}), 403
        file.save(os.path.join(path, filename))
        log_action(session.get('guest_name', 'Admin'), 'upload', filename)
        return jsonify({'success': True})
    return jsonify({'error': 'No file'}), 400

@app.route('/api/file/download')
@auth_required
def download_file():
    if not get_permissions().get('download'):
        return jsonify({'error': 'Permission denied'}), 403
    path = request.args.get('path')
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    try:
        log_action(session.get('guest_name', 'Admin'), 'download', os.path.basename(path))
        return send_file(path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search')
@auth_required
def search_files():
    query, path = request.args.get('query', ''), request.args.get('path', BASE_DIR)
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    results = []
    try:
        for root, dirs, files in os.walk(path):
            for name in files + dirs:
                if query.lower() in name.lower():
                    full_path = os.path.join(root, name)
                    if validate_path(full_path):
                        results.append({'path': full_path, 'name': name, 'type': 'dir' if os.path.isdir(full_path) else 'file'})
    except: pass
    return jsonify({'results': results[:100]})

@app.route('/api/search/replace', methods=['POST'])
@auth_required
def search_replace():
    if not get_permissions().get('edit'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    path, pattern, replacement, fp = data.get('path', BASE_DIR), data.get('pattern', ''), data.get('replacement', ''), data.get('file_pattern', '*.*')
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    rc, fm = 0, []
    try:
        for root, dirs, files in os.walk(path):
            for file in files:
                if re.match(fp.replace('*','.*').replace('?','.'), file):
                    fp2 = os.path.join(root, file)
                    if validate_path(fp2):
                        try:
                            with open(fp2, 'r', encoding='utf-8') as f: content = f.read()
                            nc = content.replace(pattern, replacement)
                            if nc != content:
                                with open(fp2, 'w', encoding='utf-8') as f: f.write(nc)
                                rc += content.count(pattern)
                                fm.append(fp2)
                        except: continue
        return jsonify({'success': True, 'replaced_count': rc, 'files_modified': fm})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/archive/create', methods=['POST'])
@auth_required
def create_archive():
    if not get_permissions().get('archive'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    path, files, aname, atype = data.get('path'), data.get('files', []), secure_filename(data.get('archive_name', 'archive.zip')), data.get('archive_type', 'zip')
    if not validate_path(path): return jsonify({'error': 'Access denied'}), 403
    ap = os.path.join(path, aname)
    try:
        if atype == 'zip':
            with zipfile.ZipFile(ap, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file in files:
                    fp = os.path.join(path, secure_filename(file))
                    if validate_path(fp) and os.path.exists(fp):
                        if os.path.isdir(fp):
                            for r, d, fls in os.walk(fp):
                                for fl in fls: zf.write(os.path.join(r, fl), os.path.relpath(os.path.join(r, fl), path))
                        else: zf.write(fp, os.path.basename(fp))
        elif atype in ['tar.gz', 'tar']:
            with tarfile.open(ap, 'w:gz' if atype == 'tar.gz' else 'w') as tf:
                for file in files:
                    fp = os.path.join(path, secure_filename(file))
                    if validate_path(fp) and os.path.exists(fp): tf.add(fp, arcname=os.path.basename(fp))
        return jsonify({'success': True, 'archive_path': ap})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/archive/extract', methods=['POST'])
@auth_required
def extract_archive():
    if not get_permissions().get('extract'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    ap, ep = data.get('archive_path'), data.get('extract_path')
    if not validate_path(ap) or not validate_path(ep): return jsonify({'error': 'Access denied'}), 403
    try:
        if ap.endswith('.zip'):
            with zipfile.ZipFile(ap, 'r') as zf:
                if sum(i.file_size for i in zf.infolist()) > 1073741824: return jsonify({'error': 'Too large'}), 403
                zf.extractall(ep)
        elif ap.endswith(('.tar.gz','.tgz')): tarfile.open(ap, 'r:gz').extractall(ep)
        elif ap.endswith('.tar'): tarfile.open(ap, 'r').extractall(ep)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/terminal/start', methods=['POST'])
@auth_required
def start_terminal():
    perms = get_permissions()
    if not perms.get('start_servers'):
        return jsonify({'error': 'Permission denied'}), 403
    server_id = request.json.get('server_id', 1)
    allowed = perms.get('allowed_servers', '*')
    if allowed != '*' and server_id not in allowed:
        return jsonify({'error': 'Permission denied for this server'}), 403
    server = next((s for s in SERVERS if s['id'] == server_id), None)
    if not server: return jsonify({'error': 'Server not found'}), 404
    try:
        process = subprocess.Popen('cmd.exe', cwd=server['path'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, creationflags=subprocess.CREATE_NEW_CONSOLE)
        process.stdin.write(f'{server["command"]}\n')
        process.stdin.flush()
        processes[server['id']] = process
        write_log(f'server_{server["id"]}', f"Started: {server['command']}", "SYSTEM")
        threading.Thread(target=read_process_output, args=(process, f'server_{server["id"]}'), daemon=True).start()
        log_action(session.get('guest_name', 'Admin'), 'start_server', server['name'])
        return jsonify({'success': True, 'message': f'{server["name"]} started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/terminal/stop', methods=['POST'])
@auth_required
def stop_terminal():
    perms = get_permissions()
    if not perms.get('start_servers'):
        return jsonify({'error': 'Permission denied'}), 403
    server_id = request.json.get('server_id', 1)
    allowed = perms.get('allowed_servers', '*')
    if allowed != '*' and server_id not in allowed:
        return jsonify({'error': 'Permission denied for this server'}), 403
    if server_id in processes:
        processes[server_id].terminate()
        del processes[server_id]
        write_log(f'server_{server_id}', "Stopped", "SYSTEM")
        log_action(session.get('guest_name', 'Admin'), 'stop_server', f'Server {server_id}')
        return jsonify({'success': True})
    return jsonify({'error': 'Not running'}), 404

@app.route('/api/terminal/cmd', methods=['POST'])
@auth_required
@limiter.limit("30 per minute")
def execute_cmd():
    if not get_permissions().get('terminal'):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.json
    cmd, wd = data.get('command', ''), data.get('working_dir', BASE_DIR)
    if not validate_path(wd): return jsonify({'error': 'Access denied'}), 403
    if any(dc in cmd.lower() for dc in ['format','del /f /s','shutdown','restart','diskpart']):
        return jsonify({'error': 'Blocked'}), 403
    try:
        p = subprocess.Popen(cmd, shell=True, cwd=wd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(timeout=30)
        write_log("terminal_cmd", f"> {cmd}\n{out+err}")
        return jsonify({'output': out + err})
    except subprocess.TimeoutExpired:
        p.kill(); return jsonify({'error': 'Timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/get')
@auth_required
def get_logs():
    perms = get_permissions()
    if not perms.get('view_logs'):
        return jsonify({'error': 'Permission denied'}), 403
    log_type = request.args.get('type', 'server_1')
    allowed = perms.get('allowed_logs', '*')
    if allowed != '*' and log_type not in allowed:
        return jsonify({'error': 'Permission denied for this log'}), 403
    return jsonify({'logs': read_logs(log_type)})

@app.route('/api/logs/clear', methods=['POST'])
@auth_required
def clear_logs_endpoint():
    if session.get('is_guest'): return jsonify({'error': 'Permission denied'}), 403
    lt = request.json.get('type')
    if lt in log_files: 
        clear_logs(lt)
        log_action(session.get('guest_name', 'Admin'), 'clear_logs', lt)
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid'}), 400

def read_process_output(process, log_name):
    try:
        for line in iter(process.stdout.readline, ''):
            if line: write_log(log_name, line.strip())
    except: pass
    try:
        for line in iter(process.stderr.readline, ''):
            if line: write_log(log_name, f"ERROR: {line.strip()}", "ERROR")
    except: pass

if __name__ == '__main__':
    cert_file = os.path.join(SERVER_DIR, 'cert.pem')
    key_file = os.path.join(SERVER_DIR, 'key.pem')
    use_ssl = os.path.exists(cert_file) and os.path.exists(key_file)
    
    print(f"Server Manager starting on port {PORTS[0]}" + (" with SSL" if use_ssl else ""))
    print(f"Server directory: {SERVER_DIR}")
    print(f"Admin page: {ADMINPAGE}")
    for s in SERVERS:
        print(f"  [{s['id']}] {s['name']}: {s['path']}")
    
    if use_ssl:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        app.run(host='0.0.0.0', port=PORTS[0], debug=False, threaded=True, ssl_context=context)
    else:
        app.run(host='0.0.0.0', port=PORTS[0], debug=False, threaded=True)