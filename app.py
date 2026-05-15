"""
Secure File Sharing System — Web GUI (CloudDrop Design)
Uses Flask to serve a browser-based UI matching the Stitch design.
Author: Aniket
"""
import os, sys, json, time, threading, socket
from flask import Flask, render_template_string, request, jsonify

from des import des_encrypt, des_decrypt
from diffie_hellman import DiffieHellman
from network import Host, Client, DEFAULT_PORT

app = Flask(__name__)

# ── State ──
state = {
    'logs': [],
    'progress': 0,
    'metrics': '',
    'status': 'idle',  # idle, running, done
    'result': None,
}
lock = threading.Lock()

try:
    LOCAL_IP = socket.gethostbyname(socket.gethostname())
except:
    LOCAL_IP = "127.0.0.1"

def add_log(msg, tag='info'):
    with lock:
        state['logs'].append({'time': time.strftime('%H:%M:%S'), 'msg': msg, 'tag': tag})

def set_progress(cur, tot):
    with lock:
        state['progress'] = int(cur / tot * 100) if tot else 0

HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudDrop — Secure File Transfer</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap');
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Manrope',sans-serif; background:#F0F2F7; color:#181C20; min-height:100vh; }

/* NAV */
.nav { background:#fff; display:flex; align-items:center; padding:0 24px; height:52px;
       border-bottom:1px solid #E0E3E8; }
.logo { font-size:15px; font-weight:800; color:#0066FF; margin-right:32px; }
.nav-tabs { display:flex; gap:4px; }
.tab { padding:8px 16px; border-radius:6px; cursor:pointer; font-size:13px; font-weight:500;
       color:#9CA3AF; transition:all .2s; border:none; background:none; }
.tab:hover { background:#F0F2F7; }
.tab.active { background:#EBF0FF; color:#0066FF; font-weight:700; }

/* LAYOUT */
.container { max-width:520px; margin:32px auto; padding:0 20px; }

/* CARD */
.card { background:#fff; border-radius:12px; border:1px solid #E0E3E8; padding:32px; }
.card h1 { font-size:24px; font-weight:800; margin-bottom:4px; }
.card .subtitle { color:#6B7280; font-size:13px; margin-bottom:20px; }

/* FORM */
.field-label { font-size:11px; font-weight:700; color:#9CA3AF; text-transform:uppercase;
               letter-spacing:.05em; margin-bottom:4px; }
.input { width:100%; padding:10px 14px; border:1px solid #D1D5DB; border-radius:8px;
         font-size:14px; font-family:inherit; background:#F9FAFB; outline:none;
         transition:border .2s; }
.input:focus { border-color:#0066FF; background:#fff; }
.field { margin-bottom:14px; }

/* IP BOX */
.ip-box { background:#EBF0FF; border-radius:8px; padding:12px 16px; margin-bottom:16px; }
.ip-box .ip { font-weight:700; color:#0066FF; font-size:13px; }
.ip-box .ip-hint { color:#6B7280; font-size:11px; margin-top:2px; }

/* DROP ZONE */
.drop-zone { border:2px dashed #D1D5DB; border-radius:10px; padding:28px; text-align:center;
             cursor:pointer; transition:all .2s; margin-bottom:16px; background:#F9FAFB; }
.drop-zone:hover { border-color:#0066FF; background:#EBF0FF; }
.drop-zone .icon { font-size:42px; margin-bottom:4px; }
.drop-zone .dz-text { color:#6B7280; font-size:13px; }
.drop-zone .dz-sub { color:#9CA3AF; font-size:11px; }
.drop-zone.has-file { border-color:#10B981; background:#F0FDF4; }
.drop-zone.has-file .icon { color:#10B981; }

/* BUTTON */
.btn-primary { width:100%; padding:14px; border:none; border-radius:10px; background:#0066FF;
               color:#fff; font-size:15px; font-weight:700; cursor:pointer; font-family:inherit;
               transition:background .2s; }
.btn-primary:hover { background:#0050CB; }
.btn-primary:disabled { background:#D1D5DB; cursor:not-allowed; }

/* SAVE ROW */
.save-row { display:flex; gap:8px; align-items:center; }
.save-path { flex:1; padding:8px 12px; background:#F9FAFB; border:1px solid #D1D5DB;
             border-radius:6px; font-size:12px; color:#6B7280; overflow:hidden;
             text-overflow:ellipsis; white-space:nowrap; }
.btn-sm { padding:8px 14px; border:1px solid #D1D5DB; border-radius:6px; background:#F9FAFB;
          color:#0066FF; font-size:12px; font-weight:600; cursor:pointer; font-family:inherit; }
.btn-sm:hover { background:#EBF0FF; }

/* ICON BOX */
.icon-box { background:#EBF0FF; border-radius:10px; padding:20px; text-align:center;
            margin:16px 0; }
.icon-box .big-icon { font-size:48px; color:#0066FF; }

/* FOOTER */
.footer { text-align:center; color:#9CA3AF; font-size:11px; margin-top:16px; }

/* LOG PANEL */
.log-container { max-width:720px; margin:24px auto; padding:0 20px; }
.log-header h1 { font-size:22px; font-weight:800; }
.log-header .sub { color:#6B7280; font-size:13px; margin-bottom:14px; }
.metrics-bar { background:#EBF0FF; border-radius:8px; padding:12px 16px; margin-bottom:10px;
               color:#0066FF; font-size:12px; font-weight:600; min-height:20px; }
.progress-bar { height:6px; background:#E0E3E8; border-radius:3px; overflow:hidden;
                margin-bottom:4px; }
.progress-fill { height:100%; background:#0066FF; border-radius:3px; transition:width .3s; }
.progress-pct { text-align:right; font-size:11px; color:#9CA3AF; margin-bottom:8px; }
.log-box { background:#fff; border:1px solid #E0E3E8; border-radius:8px; padding:14px;
           font-family:'Courier New',monospace; font-size:12px; line-height:1.6;
           max-height:320px; overflow-y:auto; }
.log-line { margin-bottom:2px; }
.log-line .ts { color:#9CA3AF; }
.log-success { color:#10B981; }
.log-error { color:#EF4444; }
.log-accent { color:#0066FF; }
.log-key { color:#7C3AED; }
.log-info { color:#6B7280; }

/* FILE INPUT (hidden) */
.file-input { display:none; }

/* RESULT */
.result-box { background:#F0FDF4; border:1px solid #10B981; border-radius:10px;
              padding:20px; text-align:center; margin-top:16px; }
.result-box h2 { color:#10B981; font-size:18px; margin-bottom:8px; }
.result-box p { color:#6B7280; font-size:13px; }

/* Hide panels */
.panel { display:none; }
.panel.active { display:block; }
</style>
</head>
<body>

<!-- NAV -->
<div class="nav">
  <div class="logo">◈ CloudDrop</div>
  <div class="nav-tabs">
    <button class="tab active" onclick="showTab('send')" id="tab-send">↗ Transfer</button>
    <button class="tab" onclick="showTab('recv')" id="tab-recv">↙ Receive</button>
    <button class="tab" onclick="showTab('log')" id="tab-log">☰ Log</button>
  </div>
</div>

<!-- SEND PANEL -->
<div class="panel active" id="panel-send">
<div class="container">
<div class="card">
  <h1>Send files</h1>
  <p class="subtitle">Securely transfer via DES + Diffie-Hellman encryption</p>

  <div class="field">
    <div class="field-label">Port</div>
    <input class="input" id="send-port" value="5555" type="number">
  </div>

  <div class="ip-box">
    <div class="ip">🌐 Your IP: ''' + LOCAL_IP + '''</div>
    <div class="ip-hint">Share this IP with the receiver</div>
  </div>

  <input type="file" class="file-input" id="file-input" onchange="fileSelected(this)">
  <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
    <div class="icon" id="dz-icon">☁</div>
    <div class="dz-text" id="dz-text">Click to choose a file</div>
    <div class="dz-sub" id="dz-sub">Ready to move files</div>
  </div>

  <button class="btn-primary" id="send-btn" onclick="startSend()">Start transfer</button>
  <div class="footer">◈ Secure Peer-to-Peer Transfer</div>
</div>
</div>
</div>

<!-- RECV PANEL -->
<div class="panel" id="panel-recv">
<div class="container">
<div class="card">
  <h1>Receive files</h1>
  <p class="subtitle">Connect to a host and receive encrypted files</p>

  <div class="field">
    <div class="field-label">Host IP</div>
    <input class="input" id="recv-ip" value="127.0.0.1">
  </div>
  <div class="field">
    <div class="field-label">Port</div>
    <input class="input" id="recv-port" value="5555" type="number">
  </div>
  <div class="field">
    <div class="field-label">Save To</div>
    <div class="save-row">
      <div class="save-path" id="save-path">~/Downloads</div>
    </div>
  </div>

  <div class="icon-box"><div class="big-icon">☁↓</div></div>
  <button class="btn-primary" id="recv-btn" onclick="startRecv()">Start Transfer</button>
  <div class="footer">◈ Secure Peer-to-Peer Transfer</div>
</div>
</div>
</div>

<!-- LOG PANEL -->
<div class="panel" id="panel-log">
<div class="log-container">
  <div class="log-header">
    <h1>Transfer Log</h1>
    <p class="sub">Real-time activity and performance metrics</p>
  </div>
  <div class="metrics-bar" id="metrics">No transfer data yet</div>
  <div class="progress-bar"><div class="progress-fill" id="progress" style="width:0%"></div></div>
  <div class="progress-pct" id="progress-pct">0%</div>
  <div class="log-box" id="log-box"></div>
  <div id="result-area"></div>
</div>
</div>

<script>
function showTab(t) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.getElementById('panel-'+t).classList.add('active');
  document.getElementById('tab-'+t).classList.add('active');
}

let selectedFile = null;
function fileSelected(input) {
  if (input.files.length > 0) {
    selectedFile = input.files[0];
    document.getElementById('dz-icon').textContent = '✓';
    document.getElementById('dz-text').textContent = '📄 ' + selectedFile.name;
    document.getElementById('dz-sub').textContent = selectedFile.size.toLocaleString() + ' bytes';
    document.getElementById('drop-zone').classList.add('has-file');
  }
}

function startSend() {
  if (!selectedFile) { alert('Please select a file first.'); return; }
  const port = document.getElementById('send-port').value;
  const btn = document.getElementById('send-btn');
  btn.disabled = true; btn.textContent = '⏳ Waiting for connection...';
  showTab('log');

  const fd = new FormData();
  fd.append('file', selectedFile);
  fd.append('port', port);
  fetch('/api/send', {method:'POST', body:fd});
  startPolling();
}

function startRecv() {
  const ip = document.getElementById('recv-ip').value;
  const port = document.getElementById('recv-port').value;
  const btn = document.getElementById('recv-btn');
  btn.disabled = true; btn.textContent = '⏳ Connecting...';
  showTab('log');

  fetch('/api/recv', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip, port})});
  startPolling();
}

let polling = null;
function startPolling() {
  if (polling) clearInterval(polling);
  polling = setInterval(async () => {
    const r = await fetch('/api/status');
    const d = await r.json();
    // Progress
    document.getElementById('progress').style.width = d.progress + '%';
    document.getElementById('progress-pct').textContent = d.progress + '%';
    if (d.progress >= 100) document.getElementById('progress').style.background = '#10B981';
    // Metrics
    if (d.metrics) document.getElementById('metrics').textContent = d.metrics;
    // Logs
    const box = document.getElementById('log-box');
    box.innerHTML = d.logs.map(l =>
      `<div class="log-line"><span class="ts">[${l.time}]</span> <span class="log-${l.tag}">${l.msg}</span></div>`
    ).join('');
    box.scrollTop = box.scrollHeight;
    // Result
    if (d.result) {
      document.getElementById('result-area').innerHTML =
        `<div class="result-box"><h2>✅ ${d.result.title}</h2><p>${d.result.detail}</p></div>`;
      clearInterval(polling);
      document.getElementById('send-btn').disabled = false;
      document.getElementById('send-btn').textContent = 'Start transfer';
      document.getElementById('recv-btn').disabled = false;
      document.getElementById('recv-btn').textContent = 'Start Transfer';
    }
  }, 500);
}
</script>
</body>
</html>'''


@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/api/status')
def api_status():
    with lock:
        return jsonify(state)


@app.route('/api/send', methods=['POST'])
def api_send():
    f = request.files.get('file')
    port = int(request.form.get('port', DEFAULT_PORT))
    if not f:
        return jsonify({'error': 'No file'}), 400

    # Save uploaded file temporarily
    tmp = os.path.join('/tmp', f.filename)
    f.save(tmp)

    with lock:
        state['logs'] = []
        state['progress'] = 0
        state['metrics'] = ''
        state['status'] = 'running'
        state['result'] = None

    threading.Thread(target=_host_thread, args=(tmp, port), daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/recv', methods=['POST'])
def api_recv():
    data = request.get_json()
    ip = data.get('ip', '127.0.0.1')
    port = int(data.get('port', DEFAULT_PORT))

    with lock:
        state['logs'] = []
        state['progress'] = 0
        state['metrics'] = ''
        state['status'] = 'running'
        state['result'] = None

    save_dir = os.path.expanduser("~/Downloads")
    threading.Thread(target=_client_thread, args=(ip, port, save_dir), daemon=True).start()
    return jsonify({'ok': True})


def _set_metrics(m):
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
        state['metrics'] = '  •  '.join(parts)


def _host_thread(filepath, port):
    h = None
    met = {}
    try:
        h = Host(port=port, callback=lambda m: add_log(m))
        h.start()
        if not h.accept_connection():
            return

        add_log("🔑 Diffie-Hellman key exchange...", 'accent')
        dh = DiffieHellman()
        t0 = time.time()
        other = h.exchange_dh_keys(dh)
        if not other:
            add_log("❌ Key exchange failed!", 'error')
            return
        key = dh.derive_des_key(other)
        met['key_exchange_time'] = time.time() - t0
        add_log(f"🔑 DES Key: {key.hex()}", 'key')
        add_log(f"✅ Key exchange complete ({met['key_exchange_time']:.4f}s)", 'success')

        add_log("📤 Encrypting and sending file...", 'accent')
        m = h.send_file(filepath, key, des_encrypt, progress_callback=set_progress)
        if m:
            met.update(m)
            add_log("✅ File sent successfully!", 'success')
            _set_metrics(met)
            name = os.path.basename(filepath)
            with lock:
                state['result'] = {
                    'title': 'Transfer Complete',
                    'detail': f"📄 {name}<br>📦 {m.get('file_size',0):,} bytes<br>⏱ {m.get('transfer_time',0):.2f}s"
                }
        else:
            add_log("❌ Send failed!", 'error')
    except Exception as e:
        add_log(f"❌ Error: {e}", 'error')
    finally:
        if h:
            h.close()
        with lock:
            state['status'] = 'done'
        try:
            os.remove(filepath)
        except:
            pass


def _client_thread(ip, port, save_dir):
    c = None
    met = {}
    try:
        c = Client(callback=lambda m: add_log(m))
        if not c.connect(ip, port):
            return

        add_log("🔑 Diffie-Hellman key exchange...", 'accent')
        dh = DiffieHellman()
        t0 = time.time()
        other = c.exchange_dh_keys(dh)
        if not other:
            add_log("❌ Key exchange failed!", 'error')
            return
        key = dh.derive_des_key(other)
        met['key_exchange_time'] = time.time() - t0
        add_log(f"🔑 DES Key: {key.hex()}", 'key')
        add_log(f"✅ Key exchange complete ({met['key_exchange_time']:.4f}s)", 'success')

        add_log("📥 Receiving encrypted file...", 'accent')
        m = c.receive_file(save_dir, key, des_decrypt, progress_callback=set_progress)
        if m:
            met.update(m)
            add_log("✅ File received and decrypted!", 'success')
            _set_metrics(met)
            p = m.get('save_path', '')
            with lock:
                state['result'] = {
                    'title': 'File Received!',
                    'detail': f"📄 {os.path.basename(p)}<br>📁 {p}<br>📦 {m.get('file_size',0):,} bytes<br>✅ Integrity verified"
                }
        else:
            add_log("❌ Receive failed!", 'error')
    except Exception as e:
        add_log(f"❌ Error: {e}", 'error')
    finally:
        if c:
            c.close()
        with lock:
            state['status'] = 'done'


if __name__ == '__main__':
    os.environ['TK_SILENCE_DEPRECATION'] = '1'
    import webbrowser
    print("\n  ◈ CloudDrop starting at http://localhost:8080\n")
    webbrowser.open('http://localhost:8080')
    app.run(host='0.0.0.0', port=8080, debug=False)
