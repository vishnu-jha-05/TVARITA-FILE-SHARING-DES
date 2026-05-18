"""
Secure File Sharing System — Web GUI (TVARITA Design)
"""
import os, sys, json, time, threading, socket
from flask import Flask, render_template, request, jsonify

from des import des_encrypt, des_decrypt
from diffie_hellman import DiffieHellman
from network import Host, Client, DEFAULT_PORT

app = Flask(__name__)

# ── State ── Separate state for send and receive so they don't conflict
def _new_state():
    return {
        'logs': [],
        'progress': 0,
        'metrics': '',
        'status': 'idle',  # idle, running, done
        'result': None,
    }

send_state = _new_state()
recv_state = _new_state()
history = []
lock = threading.Lock()

# Temp directory for uploaded files (cross-platform)
TMP_DIR = os.path.join(os.path.expanduser('~'), '.tvarita_tmp')
os.makedirs(TMP_DIR, exist_ok=True)

def _get_local_ip():
    """
    Reliably detect the correct local IP address of this machine.
    
    Uses a UDP socket trick: by 'connecting' to an external address (8.8.8.8),
    the OS is forced to select the correct active network interface (e.g. Wi-Fi or Hotspot).
    No actual data is sent — it just asks the OS which interface it would use.
    This avoids the common bug of gethostbyname() returning a VirtualBox/Ethernet IP.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS (no data is sent)
        ip = s.getsockname()[0]     # Read which local interface the OS chose
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = _get_local_ip()

def add_log(target_state, msg, tag='info'):
    with lock:
        target_state['logs'].append({'time': time.strftime('%H:%M:%S'), 'msg': msg, 'tag': tag})

def set_progress(target_state, cur, tot):
    with lock:
        target_state['progress'] = int(cur / tot * 100) if tot else 0

@app.after_request
def add_no_cache_headers(response):
    """
    Prevent browsers from caching any page.
    This ensures the phone always gets a fresh page with the correct IP address,
    even if the hotspot assigns a new IP after reconnecting.
    """
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    """
    Serve the main TVARITA interface.
    
    We detect the IP dynamically from the HTTP request host header.
    This way, when the PC opens localhost:8080, it shows the LOCAL_IP for the phone.
    When the phone opens 10.146.225.5:8080, the page confirms that exact IP back.
    This is 100% reliable regardless of how many network adapters the PC has.
    """
    host = request.host.split(':')[0]  # Strip the port number (e.g. "10.146.225.5:8080" -> "10.146.225.5")
    # If accessed from the PC itself (localhost), show the detected network IP for phone to connect
    # If accessed from phone with actual IP, confirm that same IP back to the user
    display_ip = LOCAL_IP if host in ('localhost', '127.0.0.1') else host
    return render_template('index.html', LOCAL_IP=display_ip)


@app.route('/api/status')
def api_status():
    """
    API Route: Polls the current state of the transfer.
    The frontend continuously calls this every 500ms to update the UI 
    progress bar, logs, and success messages without refreshing the page.
    """
    mode = request.args.get('mode', 'send')
    with lock:
        st = send_state if mode == 'send' else recv_state
        return jsonify({**st, 'history': history})


UDP_PORT = 5556
DISCOVER_MSG = b"TVARITA_DISCOVER"

def udp_listener_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data == DISCOVER_MSG:
                sock.sendto(b"TVARITA_HOST", addr)
        except:
            pass

@app.route('/api/scan', methods=['GET'])
def api_scan():
    found_ips = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)
    
    try:
        sock.sendto(DISCOVER_MSG, ('<broadcast>', UDP_PORT))
        
        start = time.time()
        while time.time() - start < 1.0:
            try:
                data, addr = sock.recvfrom(1024)
                if data == b"TVARITA_HOST" and addr[0] != LOCAL_IP:
                    if addr[0] not in found_ips:
                        found_ips.append(addr[0])
            except socket.timeout:
                break
    except Exception as e:
        print("Discovery error:", e)
    finally:
        sock.close()
        
    return jsonify({'ips': found_ips})


@app.route('/api/send', methods=['POST'])
def api_send():
    """
    API Route: Initiates a file send operation.
    When a user selects a file to send, the frontend uploads it here.
    This route saves the file to a temporary directory and spawns a 
    background `_host_thread` (the Sender) to listen for connections.
    """
    global send_state
    f = request.files.get('file')
    port = int(request.form.get('port', DEFAULT_PORT))
    
    # Validation: Ensure a file was actually uploaded by the user
    if not f:
        return jsonify({'error': 'No file'}), 400

    # Save uploaded file temporarily (cross-platform path handling)
    # We store it in a hidden temporary directory so we don't clutter the main project folder
    tmp = os.path.join(TMP_DIR, f.filename)
    f.save(tmp)

    # Use a threading lock to prevent UI race conditions when updating the state
    with lock:
        send_state = _new_state()
        send_state['status'] = 'running'

    # Start the actual network transfer in the background so the Flask server isn't blocked
    threading.Thread(target=_host_thread, args=(tmp, port), daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/recv', methods=['POST'])
def api_recv():
    """
    API Route: Initiates a file receive operation.
    When a user clicks 'Start Receive', this route spawns a 
    background `_client_thread` (the Receiver) which attempts to connect 
    to the internal sender thread via localhost (127.0.0.1).
    """
    global recv_state
    data = request.get_json()
    
    # Force 127.0.0.1 because both the Sender Host and Receiver Client threads 
    # run on this same backend Python server. This avoids Firewall/LAN IP blocks.
    ip = '127.0.0.1' 
    port = int(data.get('port', DEFAULT_PORT))

    # Reset the receiver state to start fresh
    with lock:
        recv_state = _new_state()
        recv_state['status'] = 'running'

    # Create a subfolder to store received files
    # We will serve files from this folder later so the mobile phone can download them
    save_dir = os.path.join(TMP_DIR, "received")
    os.makedirs(save_dir, exist_ok=True)
    
    # Start receiving the file in the background
    threading.Thread(target=_client_thread, args=(ip, port, save_dir), daemon=True).start()
    return jsonify({'ok': True})

@app.route('/download/<path:filename>')
def download_file(filename):
    from flask import send_from_directory
    received_dir = os.path.join(TMP_DIR, "received")
    return send_from_directory(received_dir, filename, as_attachment=True)


def _set_metrics(target_state, m):
    parts = []
    for k, l in [('encryption_time', '🔒 Enc'), ('decryption_time', '🔓 Dec'),
                  ('key_exchange_time', '🔑 Key'), ('transfer_time', '📡 Xfer')]:
        if k in m:
            parts.append(f"{l}: {m[k]:.3f}s")
    if 'file_size' in m:
        parts.append(f"📦 {m['file_size']:,} B")
    if m.get('transfer_time') and m.get('file_size'):
        parts.append(f"⚡ {m['file_size']/m['transfer_time']/1024:.1f} KB/s")
    with lock:
        target_state['metrics'] = '  •  '.join(parts)


def _host_thread(filepath, port):
    """
    Background Thread: The Sender (Host).
    This thread performs the actual peer-to-peer sending over a TCP socket.
    1. Opens a listening socket and waits for a connection.
    2. Performs Diffie-Hellman key exchange with the client.
    3. Encrypts the file using DES and the shared key.
    4. Sends the encrypted bytes over the network.
    """
    h = None
    met = {}
    _log = lambda m, t='info': add_log(send_state, m, t)
    _prog = lambda cur, tot: set_progress(send_state, cur, tot)
    try:
        h = Host(port=port, callback=lambda m: _log(m))
        h.start()
        if not h.accept_connection():
            return

        _log("🔑 Diffie-Hellman key exchange...", 'accent')
        dh = DiffieHellman()
        t0 = time.time()
        other = h.exchange_dh_keys(dh)
        if not other:
            _log("❌ Key exchange failed!", 'error')
            return
        key = dh.derive_des_key(other)
        met['key_exchange_time'] = time.time() - t0
        _log(f"🔑 DES Key: {key.hex()}", 'key')
        _log(f"✅ Key exchange complete ({met['key_exchange_time']:.4f}s)", 'success')

        _log("📤 Encrypting and sending file...", 'accent')
        m = h.send_file(filepath, key, des_encrypt, progress_callback=_prog)
        if m:
            met.update(m)
            _log("✅ File sent successfully!", 'success')
            _set_metrics(send_state, met)
            name = os.path.basename(filepath)
            with lock:
                send_state['result'] = {
                    'title': '📤 File Sent!',
                    'detail': f"📄 {name}<br>📦 {m.get('file_size',0):,} bytes<br>⏱ {m.get('transfer_time',0):.2f}s"
                }
                history.append({
                    'type': 'Sent',
                    'filename': name,
                    'size': f"{m.get('file_size',0):,} bytes",
                    'time': time.strftime('%H:%M:%S')
                })
        else:
            _log("❌ Send failed!", 'error')
    except Exception as e:
        _log(f"❌ Error: {e}", 'error')
    finally:
        if h:
            h.close()
        with lock:
            send_state['status'] = 'done'
        try:
            os.remove(filepath)
        except:
            pass


def _client_thread(ip, port, save_dir):
    """
    Background Thread: The Receiver (Client).
    This thread performs the peer-to-peer receiving over a TCP socket.
    1. Connects to the host IP (usually 127.0.0.1 for local backend transfer).
    2. Performs Diffie-Hellman key exchange.
    3. Receives encrypted file data over the network.
    4. Decrypts the file using DES and the shared key.
    5. Saves the decrypted file to the server's local storage for HTTP download.
    """
    c = None
    met = {}
    _log = lambda m, t='info': add_log(recv_state, m, t)
    _prog = lambda cur, tot: set_progress(recv_state, cur, tot)
    try:
        c = Client(callback=lambda m: _log(m))
        if not c.connect(ip, port):
            return

        _log("🔑 Diffie-Hellman key exchange...", 'accent')
        dh = DiffieHellman()
        t0 = time.time()
        other = c.exchange_dh_keys(dh)
        if not other:
            _log("❌ Key exchange failed!", 'error')
            return
        key = dh.derive_des_key(other)
        met['key_exchange_time'] = time.time() - t0
        _log(f"🔑 DES Key: {key.hex()}", 'key')
        _log(f"✅ Key exchange complete ({met['key_exchange_time']:.4f}s)", 'success')

        _log("📥 Receiving encrypted file...", 'accent')
        m = c.receive_file(save_dir, key, des_decrypt, progress_callback=_prog)
        if m:
            met.update(m)
            _log("✅ File received and decrypted!", 'success')
            _set_metrics(recv_state, met)
            p = m.get('save_path', '')
            fname = os.path.basename(p)
            with lock:
                recv_state['result'] = {
                    'title': '📥 File Received!',
                    'detail': f"📄 {fname}<br>📦 {m.get('file_size',0):,} bytes<br>✅ Integrity verified<br><br><a href='/download/{fname}' class='btn-modern' style='display:inline-block; margin-top:10px; text-decoration:none;' download>💾 Download to Device</a>"
                }
                history.append({
                    'type': 'Received',
                    'filename': fname,
                    'size': f"{m.get('file_size',0):,} bytes",
                    'time': time.strftime('%H:%M:%S')
                })
        else:
            _log("❌ Receive failed!", 'error')
    except Exception as e:
        _log(f"❌ Error: {e}", 'error')
    finally:
        if c:
            c.close()
        with lock:
            recv_state['status'] = 'done'


if __name__ == '__main__':
    os.environ['TK_SILENCE_DEPRECATION'] = '1'

    # ── Auto-kill any old server still running on port 8080 ──
    # This prevents the "Address already in use" error and stale IP display bug.
    import subprocess
    try:
        result = subprocess.run(
            ['netstat', '-ano'], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if ':8080' in line and 'LISTENING' in line:
                parts = line.split()
                old_pid = parts[-1]
                if old_pid.isdigit() and int(old_pid) != os.getpid():
                    subprocess.run(['taskkill', '/PID', old_pid, '/F'],
                                   capture_output=True, timeout=5)
                    print(f"  [!] Killed old server process (PID {old_pid})")
                    time.sleep(1)  # Give the port time to release
    except:
        pass  # If cleanup fails, Flask will report the port conflict normally

    # Recalculate IP fresh (in case network changed since module loaded)
    LOCAL_IP = _get_local_ip()

    threading.Thread(target=udp_listener_thread, daemon=True).start()
    import webbrowser

    print("\n  ╔═══════════════════════════════════════════════╗")
    print("  ║         TVARITA — Secure File Sharing         ║")
    print("  ╠═══════════════════════════════════════════════╣")
    print(f"  ║  PC Browser : http://localhost:8080            ║")
    print(f"  ║  Phone URL  : http://{LOCAL_IP}:8080  ║")
    print("  ╚═══════════════════════════════════════════════╝\n")
    print("  → Open the Phone URL on your mobile browser to connect!")
    print("  → Press Ctrl+C to stop the server.\n")

    webbrowser.open('http://localhost:8080')
    app.run(host='0.0.0.0', port=8080, debug=False)

