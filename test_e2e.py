"""
End-to-End Test — Verifies the complete pipeline:
  DH Key Exchange → DES Encrypt → Network Send → Network Receive → DES Decrypt → Verify

Runs entirely in-memory (no actual sockets) to test the crypto + protocol logic.
"""

import sys
import os
import tempfile
import time

# Add project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from des import des_encrypt, des_decrypt
from diffie_hellman import DiffieHellman


def test_end_to_end():
    print("=" * 60)
    print("End-to-End Integration Test")
    print("=" * 60)
    
    results = []
    
    # ─── Test 1: DH Key Exchange ───
    print("\n[TEST 1] Diffie-Hellman Key Exchange")
    t0 = time.time()
    alice = DiffieHellman()
    bob = DiffieHellman()
    
    alice_pub = alice.get_public_key()
    bob_pub = bob.get_public_key()
    
    alice_des_key = alice.derive_des_key(bob_pub)
    bob_des_key = bob.derive_des_key(alice_pub)
    
    kx_time = time.time() - t0
    
    if alice_des_key == bob_des_key:
        print(f"  ✅ PASS — Keys match: {alice_des_key.hex()}")
        print(f"  ⏱  Key exchange: {kx_time:.4f}s")
        results.append(True)
    else:
        print(f"  ❌ FAIL — Keys don't match!")
        results.append(False)
    
    # ─── Test 2: DES Encrypt/Decrypt Small Data ───
    print("\n[TEST 2] DES Encrypt/Decrypt (small data)")
    key = alice_des_key
    plaintext = b"Hello, Secure World! This is a CNS project test."
    
    t0 = time.time()
    ciphertext = des_encrypt(plaintext, key)
    enc_time = time.time() - t0
    
    t0 = time.time()
    decrypted = des_decrypt(ciphertext, key)
    dec_time = time.time() - t0
    
    if decrypted == plaintext:
        print(f"  ✅ PASS — Decrypted matches original ({len(plaintext)} bytes)")
        print(f"  ⏱  Encrypt: {enc_time:.4f}s | Decrypt: {dec_time:.4f}s")
        results.append(True)
    else:
        print(f"  ❌ FAIL — Decrypted: {decrypted}")
        results.append(False)
    
    # ─── Test 3: DES Encrypt/Decrypt Binary File ───
    print("\n[TEST 3] DES Encrypt/Decrypt (binary data — simulated file)")
    # Create random binary data (simulate a file)
    import random
    random.seed(42)
    file_data = bytes(random.randint(0, 255) for _ in range(1024))  # 1 KB
    
    t0 = time.time()
    encrypted_file = des_encrypt(file_data, key)
    enc_time = time.time() - t0
    
    t0 = time.time()
    decrypted_file = des_decrypt(encrypted_file, key)
    dec_time = time.time() - t0
    
    if decrypted_file == file_data:
        print(f"  ✅ PASS — File integrity verified ({len(file_data)} bytes)")
        print(f"  ⏱  Encrypt: {enc_time:.4f}s | Decrypt: {dec_time:.4f}s")
        print(f"  📊 Original: {len(file_data)} B → Encrypted: {len(encrypted_file)} B")
        results.append(True)
    else:
        print(f"  ❌ FAIL — File integrity check failed!")
        results.append(False)
    
    # ─── Test 4: DH Hex Encoding (Network Simulation) ───
    print("\n[TEST 4] DH Public Key Hex Encoding (network wire format)")
    alice_hex = alice.get_public_key_hex()
    bob_hex = bob.get_public_key_hex()
    
    # Simulate sending hex over the wire and reconstructing
    alice_reconstructed = DiffieHellman.public_key_from_hex(alice_hex)
    bob_reconstructed = DiffieHellman.public_key_from_hex(bob_hex)
    
    if alice_reconstructed == alice_pub and bob_reconstructed == bob_pub:
        print(f"  ✅ PASS — Hex encoding/decoding preserves keys")
        results.append(True)
    else:
        print(f"  ❌ FAIL — Key corruption during hex encoding!")
        results.append(False)
    
    # ─── Test 5: Full Pipeline Simulation ───
    print("\n[TEST 5] Full Pipeline (DH → DES Encrypt → Transfer → DES Decrypt)")
    
    # Simulate the complete flow
    total_start = time.time()
    
    # Step 1: Key Exchange
    sender = DiffieHellman()
    receiver = DiffieHellman()
    sender_key = sender.derive_des_key(receiver.get_public_key())
    receiver_key = receiver.derive_des_key(sender.get_public_key())
    
    # Step 2: Sender encrypts file
    original_data = b"This is a confidential document for CNS Final Project." * 20
    encrypted = des_encrypt(original_data, sender_key)
    
    # Step 3: Simulate network transfer (just pass the bytes)
    received_encrypted = encrypted  # In real app, this goes over TCP
    
    # Step 4: Receiver decrypts
    recovered = des_decrypt(received_encrypted, receiver_key)
    
    total_time = time.time() - total_start
    
    if recovered == original_data:
        print(f"  ✅ PASS — Complete pipeline verified!")
        print(f"  ⏱  Total time: {total_time:.4f}s")
        print(f"  📊 Original: {len(original_data)} B → Encrypted: {len(encrypted)} B → Recovered: {len(recovered)} B")
        results.append(True)
    else:
        print(f"  ❌ FAIL — Data corruption in pipeline!")
        results.append(False)
    
    # ─── Summary ───
    print("\n" + "=" * 60)
    passed = sum(results)
    total = len(results)
    if passed == total:
        print(f"🎉 ALL {total} TESTS PASSED!")
    else:
        print(f"⚠️  {passed}/{total} tests passed, {total - passed} failed")
    print("=" * 60)
    
    return all(results)


if __name__ == "__main__":
    success = test_end_to_end()
    sys.exit(0 if success else 1)
