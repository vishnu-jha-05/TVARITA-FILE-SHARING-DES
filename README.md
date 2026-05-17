# 🔐 Secure File Sharing System

## DES Encryption + Diffie-Hellman Key Exchange

A secure file sharing application built entirely from scratch in Python. This project demonstrates core concepts of **Cryptography and Network Security (CNS)** by implementing DES encryption, Diffie-Hellman key exchange, and TCP socket communication — all without relying on any cryptographic libraries.

---

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Installation & Usage](#installation--usage)
- [Module Details](#module-details)
- [Performance Metrics](#performance-metrics)
- [Screenshots](#screenshots)
- [Author](#author)

---

## ✨ Features

- **DES Encryption from Scratch** — Complete implementation including all 8 S-boxes, Feistel network, key schedule, IP/FP permutations, and ECB mode
- **Diffie-Hellman Key Exchange** — Secure key agreement over an insecure channel using a 1024-bit safe prime (RFC 2409)
- **No Cryptographic Libraries** — Every algorithm is implemented from first principles
- **TCP Socket Communication** — Custom binary protocol for reliable file transfer
- **Web GUI (TVARITA)** — Clean, modern Flask-based browser interface with real-time logging and progress tracking
- **Performance Metrics** — Measures encryption time, key exchange time, transfer speed, and file sizes
- **Integrity Verification** — Validates that decrypted file matches the original size
- **LAN Support** — Works on both localhost and across local network

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              app.py (Web GUI Layer — Flask)           │
│         TVARITA UI — Browser-based Interface        │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │  Transfer    │  │   Receive    │  │    Log    │  │
│  │  (Send File) │  │ (Get File)   │  │  Metrics  │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┘  │
└─────────┼─────────────────┼─────────────────────────┘
          │                 │
    ┌─────▼─────┐     ┌─────▼─────┐
    │ network.py│     │ network.py│
    │   Host    │◄───►│  Client   │
    │  (Server) │ TCP │           │
    └─────┬─────┘     └─────┬─────┘
          │                 │
    ┌─────▼─────────────────▼─────┐
    │    diffie_hellman.py         │
    │  DH Key Exchange → Shared   │
    │  Secret → DES Key Derivation│
    └─────────────┬───────────────┘
                  │
    ┌─────────────▼───────────────┐
    │         des.py               │
    │  DES Encrypt/Decrypt (ECB)   │
    │  PKCS5 Padding | Feistel     │
    └─────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Encryption | DES (implemented from scratch) |
| Key Exchange | Diffie-Hellman (implemented from scratch) |
| Networking | Python `socket` (TCP) |
| GUI | Flask (web-based, TVARITA design with Manrope font) |
| Hashing | SHA-256 (for DES key derivation) |

---

## 📁 Project Structure

```
CNS Final Project/
├── app.py              # Flask web GUI (TVARITA design)
├── templates/
│   └── index.html      # Frontend user interface
├── des.py              # Full DES algorithm from scratch
├── diffie_hellman.py   # Diffie-Hellman key exchange
├── network.py          # TCP socket networking (Host/Client)
├── project_report.txt  # Formal academic project report
└── README.md           # This file
```

---

## 🔄 How It Works

### Data Flow Protocol

```
Host (Sender)                          Client (Receiver)
─────────────                          ──────────────────
1. Start server, listen on port
                                       2. Connect to host IP:port
3. Accept connection
4. Generate DH private key (a)         5. Generate DH private key (b)
6. Compute public A = g^a mod p        7. Compute public B = g^b mod p
8. Send A ──────────────────────────►  9. Receive A
                                       10. Send B
11. Receive B ◄──────────────────────
12. Compute shared = B^a mod p         13. Compute shared = A^b mod p
14. Derive DES key = SHA-256(shared)[:8]
15. Encrypt file with DES (ECB + PKCS5)
16. Send file header ──────────────►   17. Receive header
18. Send encrypted chunks ─────────►   19. Receive encrypted chunks
20. Send completion signal ─────────►  21. Decrypt file with DES
                                       22. Verify integrity
                                       23. Save decrypted file
```

### Wire Protocol Format

Each message follows: `[1 byte type][4 bytes length][payload]`

| Message Type | Code | Purpose |
|-------------|------|---------|
| `MSG_DH_PUBLIC_KEY` | `0x01` | Exchange Diffie-Hellman public keys |
| `MSG_FILE_HEADER` | `0x02` | File metadata (name, size) |
| `MSG_FILE_DATA` | `0x03` | Encrypted file data chunk (64 KB) |
| `MSG_FILE_COMPLETE` | `0x04` | Transfer completion signal |
| `MSG_ERROR` | `0xFF` | Error message |

---

## 🚀 Installation & Usage

### Prerequisites

- Python 3.6 or higher
- Flask (`pip3 install flask`)

### Running the Application

```bash
# Navigate to project directory
cd "CNS Final Project"

# Launch the web GUI (opens in browser at http://localhost:8080)
python3 app.py
```

### Sending a File (From PC)

1. Open `http://localhost:8080` on your PC browser
2. Stay on the **Transfer** tab
3. Click the file drop zone and select a file
4. Note the displayed **IP address** — share it with mobile devices on the network
5. Click **"Start transfer"** — the server will encrypt the file

### Receiving a File (From Mobile)

1. Open the PC's IP address (e.g., `http://10.146.225.5:8080`) on your mobile browser
2. Tap the **Receive** tab
3. Tap **"Start Receive"**
4. Once the DES decryption is complete, tap the **"Download to Device"** button to save the file!

### Self-Tests

```bash
# Test DES encryption/decryption
python3 des.py

# Test Diffie-Hellman key exchange
python3 diffie_hellman.py
```

---

## 📦 Module Details

### `des.py` — DES Encryption (488 lines)

Complete DES implementation with:

| Component | Description |
|-----------|------------|
| **Permutation Tables** | IP, FP, E, P, PC-1, PC-2 — all standard NIST tables |
| **S-Boxes** | All 8 substitution boxes (4×16 each) |
| **Key Schedule** | 64-bit key → PC-1 → 16 round subkeys via left shifts + PC-2 |
| **Feistel Function** | Expansion → XOR with subkey → S-box substitution → P permutation |
| **Block Cipher** | IP → 16 Feistel rounds → Swap halves → FP |
| **Decryption** | Same algorithm with subkeys in reverse order |
| **Padding** | PKCS5 padding for arbitrary-length data |
| **Mode** | ECB (Electronic Codebook) mode |

### `diffie_hellman.py` — Key Exchange (213 lines)

| Component | Description |
|-----------|------------|
| **Prime** | 1024-bit safe prime from RFC 2409 (OAKLEY Group 2) |
| **Generator** | g = 2 (primitive root) |
| **Private Key** | Random integer in [2, p-2] |
| **Public Key** | A = g^a mod p |
| **Shared Secret** | s = B^a mod p = A^b mod p |
| **Key Derivation** | SHA-256(shared_secret)[:8] → 8-byte DES key |

### `network.py` — TCP Networking (442 lines)

| Component | Description |
|-----------|------------|
| **Host class** | TCP server — bind, listen, accept, send files |
| **Client class** | TCP client — connect, receive files |
| **Protocol** | Custom binary framing with message types |
| **Chunking** | 64 KB chunks for large file transfer |
| **Timeout** | 60-second socket timeout |
| **Threading** | Non-blocking operations for GUI responsiveness |

### `app.py` & `templates/index.html` — Flask Web GUI

| Component | Description |
|-----------|------------|
| **Framework** | Flask with centralized backend processing |
| **Design** | TVARITA — Premium responsive mobile UI with CSS shadows |
| **Tabs** | Transfer (send) / Receive / Log / History |
| **Download** | Dynamic HTTP file serving via `/download/<filename>` |
| **Architecture**| Loopback TCP routing (both Host and Client threads run on backend) |
| **Progress** | Real-time progress bar via API polling (500ms) |
| **Log** | Color-coded, timestamped activity log |
| **Metrics** | Encryption time, transfer speed, file sizes |

### `test_e2e.py` — Integration Tests

| Test | What It Verifies |
|------|------------------|
| **DH Key Exchange** | Both parties derive the same shared DES key |
| **DES Small Data** | Encrypt → decrypt roundtrip on text |
| **DES Binary Data** | Encrypt → decrypt roundtrip on 1 KB binary |
| **Hex Encoding** | DH public key survives hex encode/decode (wire format) |
| **Full Pipeline** | DH → DES encrypt → simulated transfer → DES decrypt → verify |

---

## 📊 Performance Metrics

The application automatically measures and displays:

| Metric | Description |
|--------|------------|
| **Encryption Time** | Time to encrypt the entire file with DES |
| **Decryption Time** | Time to decrypt the received data |
| **Key Exchange Time** | Time for Diffie-Hellman handshake |
| **Transfer Time** | Time to send/receive encrypted data over TCP |
| **Transfer Speed** | Calculated in KB/s |
| **File Sizes** | Original vs. encrypted size comparison |

---

## 📸 Screenshots

### Transfer Tab — File Selected & Ready to Send
> Shows the sender interface with a file chosen, port configured, and host IP displayed for sharing.

![Transfer Tab — File ready to send](screenshots/01_transfer_file_selected.png)

### Receive Tab — Awaiting Connection
> The receiver interface with host IP, port, and save directory configured, ready to connect.

![Receive Tab — Ready to connect](screenshots/02_receive_tab.png)

### Transfer Log — Completed Transfer
> Real-time log showing the full pipeline: Diffie-Hellman key exchange → DES encryption → file transfer → confirmation with performance metrics (encryption time, transfer speed, file size).

![Transfer Log — Completed transfer](screenshots/03_transfer_complete.png)

---

## 🔒 Security Considerations

- **DES** is used for educational purposes — modern systems use AES-256
- **ECB mode** encrypts blocks independently — CBC would be more secure for production
- The **1024-bit DH prime** provides adequate security for demonstration
- **SHA-256** key derivation ensures uniform key distribution from the shared secret
- No authentication mechanism — vulnerable to MITM (educational scope)

---

## 👨‍💻 Authors

**Vishnu Jha & Aniket**

Project: Secure File Sharing System using DES and Diffie-Hellman
Course: Cryptography and Network Security (CNS) — Final Project
