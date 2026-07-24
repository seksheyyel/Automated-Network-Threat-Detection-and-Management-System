import os, json, hashlib, socket, threading, time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from threading import Lock

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from scapy.all import sniff, ARP, IP, TCP, UDP

DB_CONFIG = {'host': 'localhost', 'user': 'root', 'password': '', 'database': 'network_monitor'}

ALERT_RETENTION_DAYS = 30


def db():
    return mysql.connector.connect(**DB_CONFIG)


def log_action(action, status='success', username='', user_id=None, ip=None):
    if ip is None:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '0.0.0.0').split(',')[0].strip()
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO activity_logs (user_id, username, action, ip_address, status, created_at) VALUES (%s,%s,%s,%s,%s,%s)",
        (user_id, username, action, ip, status, datetime.now()),
    )
    conn.commit()
    cur.close()
    conn.close()


def save_alert(alert_type, source_ip, details):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO network_alerts (alert_type, source_ip, details, timestamp) VALUES (%s,%s,%s,%s)",
        (alert_type, source_ip, json.dumps(details), datetime.now()),
    )
    conn.commit()
    cur.close()
    conn.close()


def get_alerts():
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM network_alerts ORDER BY timestamp DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        if isinstance(r['details'], str):
            r['details'] = json.loads(r['details'])
        r['timestamp'] = str(r['timestamp'])
    return rows


def delete_alert(alert_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM network_alerts WHERE id=%s", (alert_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    cur.close()
    conn.close()
    return deleted


def delete_all_alerts():
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM network_alerts")
    conn.commit()
    removed = cur.rowcount
    cur.close()
    conn.close()
    return removed


def cleanup_old_alerts(days=ALERT_RETENTION_DAYS):
    cutoff = datetime.now() - timedelta(days=days)
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM network_alerts WHERE timestamp < %s", (cutoff,))
    conn.commit()
    removed = cur.rowcount
    cur.close()
    conn.close()
    if removed:
        print(f"[CLEANUP] Removed {removed} alert(s) older than {days} days")
    return removed


def get_own_ips():
    ips = {'127.0.0.1'}
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(('8.8.8.8', 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


def get_whitelist_entries():
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM whitelist_ips ORDER BY added_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        r['added_at'] = str(r['added_at'])
    return rows


def add_whitelist(ip, label=''):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO whitelist_ips (ip_address, label, added_at) VALUES (%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE label=VALUES(label)",
        (ip, label, datetime.now()),
    )
    conn.commit()
    cur.close()
    conn.close()


def remove_whitelist(entry_id):
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM whitelist_ips WHERE id=%s", (entry_id,))
    conn.commit()
    cur.close()
    conn.close()


AUTO_OWN_IPS = get_own_ips()
WHITELIST = set(AUTO_OWN_IPS)


def refresh_whitelist():
    WHITELIST.clear()
    WHITELIST.update(AUTO_OWN_IPS)
    try:
        WHITELIST.update(e['ip_address'] for e in get_whitelist_entries())
    except Exception as exc:
        print(f"[WHITELIST] reload failed: {exc}")


refresh_whitelist()


def get_best_interface():
    return 'Wi-Fi'


class ArpSpoofDetector:
    WINDOW, THRESHOLD, COOLDOWN = 30, 3, 30

    def __init__(self):
        self.trusted_mac = {}
        self.history = defaultdict(list)
        self.last_alert = {}
        self.lock = Lock()
    
    def detect(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:
            return
        ip, mac, now = pkt[ARP].psrc, pkt[ARP].hwsrc.lower(), time.time()
        if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00') or ip in WHITELIST:
            return

        with self.lock:
            if ip not in self.trusted_mac:
                self.trusted_mac[ip] = mac
                self.history[ip].append((mac, now))
                return

            self.history[ip] = [(m, t) for m, t in self.history[ip] if now - t <= self.WINDOW]
            self.history[ip].append((mac, now))
            macs = {m for m, _ in self.history[ip]}

            if len(macs) < self.THRESHOLD:
                self.trusted_mac[ip] = mac
                return
            if now - self.last_alert.get(ip, 0) < self.COOLDOWN:
                return

            save_alert('ARP Spoofing', ip, {
                'trusted_mac': self.trusted_mac[ip],
                'attacker_macs': list(macs - {self.trusted_mac[ip]}),
                'description': f"IP {ip} claimed {len(macs)} different MACs within {self.WINDOW}s.",
                'action': 'Verify devices on the network. Enable Dynamic ARP Inspection if possible.',
            })
            self.last_alert[ip] = now
            self.history[ip] = [(mac, now)]
            self.trusted_mac[ip] = mac


class DDoSDetector:
    WINDOW, THRESHOLD, COOLDOWN = 3, 1000, 30

    def __init__(self):
        self.stats = defaultdict(lambda: {'count': 0, 'start': time.time(), 'last_alert': 0})
        self.lock = Lock()

    def detect(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip, now = pkt[IP].src, time.time()
        if ip in WHITELIST:
            return

        with self.lock:
            s = self.stats[ip]
            if now - s['start'] > self.WINDOW:
                s['count'], s['start'] = 0, now
            s['count'] += 1

            if s['count'] < self.THRESHOLD or now - s['last_alert'] < self.COOLDOWN:
                return

            save_alert('DDoS Attack', ip, {
                'packets_in_window': s['count'],
                'rate_per_second': round(s['count'] / self.WINDOW),
                'description': f"{ip} sent {s['count']} packets in {self.WINDOW}s.",
                'action': 'Block IP at the firewall or investigate the source device.',
            })
            s['last_alert'] = now


class PortScanDetector:
    WINDOW, THRESHOLD, COOLDOWN = 10, 20, 30

    def __init__(self):
        self.ports_seen = defaultdict(list)
        self.last_alert = {}
        self.lock = Lock()

    def detect(self, pkt):
        if not pkt.haslayer(IP):
            return
        ip, now = pkt[IP].src, time.time()
        if ip in WHITELIST:
            return

        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport
        else:
            return

        with self.lock:
            self.ports_seen[ip] = [(p, t) for p, t in self.ports_seen[ip] if now - t <= self.WINDOW]
            self.ports_seen[ip].append((port, now))
            unique_ports = {p for p, _ in self.ports_seen[ip]}

            if len(unique_ports) < self.THRESHOLD or now - self.last_alert.get(ip, 0) < self.COOLDOWN:
                return

            save_alert('Port Scan', ip, {
                'unique_ports': len(unique_ports),
                'ports': sorted(unique_ports),
                'description': f"{ip} probed {len(unique_ports)} unique ports in {self.WINDOW}s.",
                'action': 'Monitor or block the source IP if activity is unexpected.',
            })
            self.last_alert[ip] = now
            self.ports_seen[ip] = []


def capture_loop():
    arp, ddos, portscan = ArpSpoofDetector(), DDoSDetector(), PortScanDetector()

    def handle(pkt):
        try:
            arp.detect(pkt)
            ddos.detect(pkt)
            portscan.detect(pkt)
        except Exception as exc:
            print(f"[PACKET ERROR] {exc}")

    while True:
        iface = get_best_interface()
        try:
            print(f"[CAPTURE] Sniffing on: {iface}")
            sniff(iface=iface, prn=handle, store=False)
        except Exception as exc:
            print(f"[SNIFF ERROR] {exc} — retrying in 5s")
            time.sleep(5)


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.urandom(24)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')

print(f"[WHITELIST] {sorted(WHITELIST)}")


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'admin' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper


def api_login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'admin' not in session:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*a, **kw)
    return wrapper


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM admin WHERE username=%s AND password=%s", (username, pw_hash))
        admin = cur.fetchone()
        cur.close()
        conn.close()

        if admin:
            session.clear()
            session['admin'] = username
            session['admin_id'] = admin.get('id')
            log_action('Login', username=username, user_id=admin.get('id'))
            return redirect(url_for('dashboard'))

        log_action('Login', status='failed', username=username or '(unknown)')
        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    log_action('Logout', username=session.get('admin', ''), user_id=session.get('admin_id'))
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=session['admin'])


@app.route('/alert')
@login_required
def alert():
    cleanup_old_alerts()
    return render_template('alerts.html', user=session['admin'])


@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html', user=session['admin'])


@app.route('/whitelist')
@login_required
def whitelist():
    return render_template('whitelist.html', user=session['admin'])


@app.route('/api/alerts')
@api_login_required
def api_alerts():
    cleanup_old_alerts()
    return jsonify({'alerts': get_alerts()})


@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
@api_login_required
def api_alert_delete(alert_id):
    try:
        deleted = delete_alert(alert_id)
        if not deleted:
            return jsonify({'success': False, 'message': 'Alert not found.'}), 404
        log_action(f'Delete Alert (ID {alert_id})', username=session.get('admin', ''), user_id=session.get('admin_id'))
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'success': False, 'message': str(exc)}), 500


@app.route('/api/alerts', methods=['DELETE'])
@api_login_required
def api_alerts_delete_all():
    try:
        removed = delete_all_alerts()
        log_action(f'Delete Alert (All - {removed} removed)', username=session.get('admin', ''), user_id=session.get('admin_id'))
        return jsonify({'success': True, 'removed': removed})
    except Exception as exc:
        return jsonify({'success': False, 'message': str(exc)}), 500


@app.route('/api/whitelist')
@api_login_required
def api_whitelist():
    return jsonify({'entries': get_whitelist_entries()})


@app.route('/api/whitelist', methods=['POST'])
@api_login_required
def api_whitelist_add():
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip_address') or '').strip()
    label = (data.get('label') or '').strip()
    if not ip:
        return jsonify({'success': False, 'message': 'IP address is required.'}), 400

    add_whitelist(ip, label)
    refresh_whitelist()
    log_action(f'Whitelist IP added: {ip}', username=session.get('admin', ''), user_id=session.get('admin_id'))
    return jsonify({'success': True})


@app.route('/api/whitelist/<int:entry_id>', methods=['DELETE'])
@api_login_required
def api_whitelist_remove(entry_id):
    remove_whitelist(entry_id)
    refresh_whitelist()
    log_action(f'Whitelist entry removed (id={entry_id})', username=session.get('admin', ''), user_id=session.get('admin_id'))
    return jsonify({'success': True})


@app.route('/api/logs')
@api_login_required
def api_logs():
    try:
        per_page = max(1, min(int(request.args.get('per_page', 100)), 1000))
    except (TypeError, ValueError):
        per_page = 100

    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT id, user_id, username, action, ip_address, status, created_at "
        "FROM activity_logs ORDER BY created_at DESC LIMIT %s",
        (per_page,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        r['created_at'] = str(r['created_at'])
    return jsonify({'logs': rows})


if __name__ == '__main__':
    cleanup_old_alerts()
    threading.Thread(target=capture_loop, daemon=True).start()
    app.run(debug=False)
