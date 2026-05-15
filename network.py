"""
Network Module — TCP Socket Communication

Handles all networking for the secure file sharing system:
- Host mode: Start a TCP server and wait for a client connection
- Connect mode: Connect to a host's TCP server
- Protocol: Exchange DH public keys, then send/receive encrypted files
- Threaded design to keep the GUI responsive

Author: Aniket
Project: Secure File Sharing System using DES and Diffie-Hellman
"""

import socket
import struct
import threading
import time
import os


# ============================================================
# Protocol Constants
# ============================================================

# Message types (1-byte header)
MSG_DH_PUBLIC_KEY = 0x01    # Diffie-Hellman public key
MSG_FILE_HEADER   = 0x02    # File metadata (name + size)
MSG_FILE_DATA     = 0x03    # Encrypted file data chunk
MSG_FILE_COMPLETE = 0x04    # File transfer complete
MSG_ERROR         = 0xFF    # Error message

# Network settings
BUFFER_SIZE = 65536         # 64 KB chunks for file transfer
DEFAULT_PORT = 5555
SOCKET_TIMEOUT = 60         # seconds


# ============================================================
# Protocol Helpers — Send/Receive Messages
# ============================================================

def send_message(sock, msg_type, data):
    """
    Send a protocol message over the socket.
    
    Format: [1 byte type][4 bytes length][data]
    
    Args:
        sock: Connected socket
        msg_type: Message type constant (MSG_*)
        data: bytes payload
    """
    header = struct.pack("!BI", msg_type, len(data))
    sock.sendall(header + data)


def recv_message(sock):
    """
    Receive a protocol message from the socket.
    
    Returns:
        (msg_type, data) tuple
    """
    # Read header (1 byte type + 4 bytes length = 5 bytes)
    header = _recv_exact(sock, 5)
    if header is None:
        raise ConnectionError("Connection closed while reading header")
    
    msg_type, data_len = struct.unpack("!BI", header)
    
    # Read data payload
    if data_len > 0:
        data = _recv_exact(sock, data_len)
        if data is None:
            raise ConnectionError("Connection closed while reading data")
    else:
        data = b""
    
    return msg_type, data


def _recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(min(n - len(data), BUFFER_SIZE))
        if not chunk:
            return None
        data += chunk
    return data


# ============================================================
# Host (Server) — Accepts a Single Connection
# ============================================================

class Host:
    """
    TCP Server that listens for a single client connection.
    Used by the sender to host the file sharing session.
    """
    
    def __init__(self, port=DEFAULT_PORT, callback=None):
        """
        Args:
            port: Port number to listen on
            callback: Function to call with status messages — callback(msg: str)
        """
        self.port = port
        self.callback = callback or (lambda msg: None)
        self.server_socket = None
        self.client_socket = None
        self.client_address = None
        self.running = False
    
    def log(self, message):
        """Send a log message to the callback."""
        self.callback(message)
    
    def start(self):
        """Start the server and wait for a connection."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(SOCKET_TIMEOUT)
        
        # Bind to all interfaces so it works on LAN too
        self.server_socket.bind(("0.0.0.0", self.port))
        self.server_socket.listen(1)
        self.running = True
        
        # Get local IP addresses for display
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        self.log(f"Server started on port {self.port}")
        self.log(f"Local IP: {local_ip}")
        self.log(f"Localhost: 127.0.0.1:{self.port}")
        self.log("Waiting for a client to connect...")
    
    def accept_connection(self):
        """Wait for and accept a client connection."""
        try:
            self.client_socket, self.client_address = self.server_socket.accept()
            self.client_socket.settimeout(SOCKET_TIMEOUT)
            self.log(f"Client connected from {self.client_address[0]}:{self.client_address[1]}")
            return True
        except socket.timeout:
            self.log("Connection timed out. No client connected.")
            return False
        except Exception as e:
            self.log(f"Error accepting connection: {e}")
            return False
    
    def exchange_dh_keys(self, dh):
        """
        Exchange Diffie-Hellman public keys with the connected client.
        Host sends first, then receives.
        
        Args:
            dh: DiffieHellman instance
        
        Returns:
            Other party's public key as integer, or None on failure
        """
        try:
            # Send our public key
            pub_hex = dh.get_public_key_hex()
            send_message(self.client_socket, MSG_DH_PUBLIC_KEY, pub_hex.encode('utf-8'))
            self.log("Sent DH public key to client")
            
            # Receive client's public key
            msg_type, data = recv_message(self.client_socket)
            if msg_type != MSG_DH_PUBLIC_KEY:
                self.log(f"Expected DH key, got message type {msg_type}")
                return None
            
            other_public = int(data.decode('utf-8'), 16)
            self.log("Received DH public key from client")
            
            return other_public
            
        except Exception as e:
            self.log(f"Key exchange error: {e}")
            return None
    
    def send_file(self, filepath, des_key, encrypt_func, progress_callback=None):
        """
        Send an encrypted file to the connected client.
        
        Args:
            filepath: Path to the file to send
            des_key: 8-byte DES key
            encrypt_func: Function to encrypt data — encrypt_func(data, key) -> encrypted_data
            progress_callback: Optional callback for progress updates — callback(bytes_sent, total_bytes)
        
        Returns:
            dict with performance metrics
        """
        metrics = {}
        filename = os.path.basename(filepath)
        
        try:
            # Read file
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            self.log(f"File: {filename} ({file_size:,} bytes)")
            
            # Encrypt
            self.log("Encrypting file with DES...")
            enc_start = time.time()
            encrypted_data = encrypt_func(file_data, des_key)
            enc_time = time.time() - enc_start
            metrics['encryption_time'] = enc_time
            self.log(f"Encryption complete in {enc_time:.4f}s")
            
            # Send file header (filename + original size)
            header_data = f"{filename}|{file_size}|{len(encrypted_data)}".encode('utf-8')
            send_message(self.client_socket, MSG_FILE_HEADER, header_data)
            self.log("Sent file header")
            
            # Send encrypted file data in chunks
            self.log("Sending encrypted file data...")
            transfer_start = time.time()
            total_sent = 0
            
            for i in range(0, len(encrypted_data), BUFFER_SIZE):
                chunk = encrypted_data[i:i + BUFFER_SIZE]
                send_message(self.client_socket, MSG_FILE_DATA, chunk)
                total_sent += len(chunk)
                
                if progress_callback:
                    progress_callback(total_sent, len(encrypted_data))
            
            # Send completion signal
            send_message(self.client_socket, MSG_FILE_COMPLETE, b"DONE")
            
            transfer_time = time.time() - transfer_start
            metrics['transfer_time'] = transfer_time
            metrics['file_size'] = file_size
            metrics['encrypted_size'] = len(encrypted_data)
            
            speed = file_size / transfer_time if transfer_time > 0 else 0
            self.log(f"Transfer complete in {transfer_time:.4f}s ({speed / 1024:.1f} KB/s)")
            
            return metrics
            
        except Exception as e:
            self.log(f"Send error: {e}")
            return None
    
    def close(self):
        """Close all sockets."""
        self.running = False
        try:
            if self.client_socket:
                self.client_socket.close()
            if self.server_socket:
                self.server_socket.close()
        except Exception:
            pass
        self.log("Server closed")


# ============================================================
# Client — Connects to a Host
# ============================================================

class Client:
    """
    TCP Client that connects to a host server.
    Used by the receiver to connect and receive files.
    """
    
    def __init__(self, callback=None):
        """
        Args:
            callback: Function to call with status messages — callback(msg: str)
        """
        self.callback = callback or (lambda msg: None)
        self.socket = None
        self.connected = False
    
    def log(self, message):
        """Send a log message to the callback."""
        self.callback(message)
    
    def connect(self, host, port=DEFAULT_PORT):
        """
        Connect to a host server.
        
        Args:
            host: IP address or hostname of the server
            port: Port number
        
        Returns:
            True if connected successfully
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(SOCKET_TIMEOUT)
            self.socket.connect((host, port))
            self.connected = True
            self.log(f"Connected to {host}:{port}")
            return True
        except Exception as e:
            self.log(f"Connection failed: {e}")
            return False
    
    def exchange_dh_keys(self, dh):
        """
        Exchange Diffie-Hellman public keys with the host.
        Client receives first, then sends.
        
        Args:
            dh: DiffieHellman instance
        
        Returns:
            Other party's public key as integer, or None on failure
        """
        try:
            # Receive host's public key first
            msg_type, data = recv_message(self.socket)
            if msg_type != MSG_DH_PUBLIC_KEY:
                self.log(f"Expected DH key, got message type {msg_type}")
                return None
            
            other_public = int(data.decode('utf-8'), 16)
            self.log("Received DH public key from host")
            
            # Send our public key
            pub_hex = dh.get_public_key_hex()
            send_message(self.socket, MSG_DH_PUBLIC_KEY, pub_hex.encode('utf-8'))
            self.log("Sent DH public key to host")
            
            return other_public
            
        except Exception as e:
            self.log(f"Key exchange error: {e}")
            return None
    
    def receive_file(self, save_dir, des_key, decrypt_func, progress_callback=None):
        """
        Receive and decrypt a file from the host.
        
        Args:
            save_dir: Directory to save the received file
            des_key: 8-byte DES key
            decrypt_func: Function to decrypt data — decrypt_func(data, key) -> decrypted_data
            progress_callback: Optional callback for progress updates
        
        Returns:
            dict with performance metrics, or None on failure
        """
        metrics = {}
        
        try:
            # Receive file header
            msg_type, data = recv_message(self.socket)
            if msg_type != MSG_FILE_HEADER:
                self.log(f"Expected file header, got message type {msg_type}")
                return None
            
            header_parts = data.decode('utf-8').split('|')
            filename = header_parts[0]
            original_size = int(header_parts[1])
            encrypted_size = int(header_parts[2])
            
            self.log(f"Receiving: {filename} ({original_size:,} bytes)")
            
            # Receive encrypted file data
            self.log("Receiving encrypted data...")
            transfer_start = time.time()
            encrypted_data = b""
            
            while True:
                msg_type, chunk = recv_message(self.socket)
                
                if msg_type == MSG_FILE_COMPLETE:
                    break
                elif msg_type == MSG_FILE_DATA:
                    encrypted_data += chunk
                    if progress_callback:
                        progress_callback(len(encrypted_data), encrypted_size)
                else:
                    self.log(f"Unexpected message type: {msg_type}")
                    return None
            
            transfer_time = time.time() - transfer_start
            metrics['transfer_time'] = transfer_time
            self.log(f"Data received in {transfer_time:.4f}s")
            
            # Decrypt the file
            self.log("Decrypting file with DES...")
            dec_start = time.time()
            decrypted_data = decrypt_func(encrypted_data, des_key)
            dec_time = time.time() - dec_start
            metrics['decryption_time'] = dec_time
            self.log(f"Decryption complete in {dec_time:.4f}s")
            
            # Save the file
            save_path = os.path.join(save_dir, filename)
            # Avoid overwriting existing files
            base, ext = os.path.splitext(save_path)
            counter = 1
            while os.path.exists(save_path):
                save_path = f"{base}_({counter}){ext}"
                counter += 1
            
            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            
            metrics['file_size'] = original_size
            metrics['encrypted_size'] = len(encrypted_data)
            metrics['save_path'] = save_path
            
            # Verify integrity
            if len(decrypted_data) == original_size:
                self.log(f"✅ File saved: {save_path}")
                self.log(f"✅ Integrity verified ({original_size:,} bytes)")
                metrics['integrity'] = True
            else:
                self.log(f"⚠️ Size mismatch: expected {original_size}, got {len(decrypted_data)}")
                metrics['integrity'] = False
            
            return metrics
            
        except Exception as e:
            self.log(f"Receive error: {e}")
            return None
    
    def close(self):
        """Close the socket."""
        self.connected = False
        try:
            if self.socket:
                self.socket.close()
        except Exception:
            pass
        self.log("Connection closed")
