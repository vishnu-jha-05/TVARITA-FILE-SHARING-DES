"""
DES (Data Encryption Standard) — Full Implementation from Scratch

Implements the complete DES algorithm including:
- Key Schedule Generation (64-bit key → 16 round subkeys)
- Initial Permutation (IP) and Final Permutation (FP)
- 16-round Feistel Network
- S-box Substitutions (8 S-boxes)
- Expansion (E), Permutation (P), PC-1, PC-2
- ECB Mode with PKCS5 Padding

Author: Aniket
Project: Secure File Sharing System using DES and Diffie-Hellman
"""


# ============================================================
# Standard DES Permutation Tables
# ============================================================

# Initial Permutation (IP) Table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (IP-Inverse) Table
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

# Expansion Permutation Table (32 bits → 48 bits)
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# Permutation (P-box) Table
P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
]

# Permuted Choice 1 (PC-1): 64-bit key → 56-bit key
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

# Permuted Choice 2 (PC-2): 56-bit key → 48-bit subkey
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Left Shift Schedule for Key Generation (per round)
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 Substitution Boxes (S-boxes): each maps 6 bits → 4 bits
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 2, 0, 14, 9, 11],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]


# ============================================================
# Helper Functions
# ============================================================

def bytes_to_bits(data):
    """Convert a bytes object to a list of bits (0s and 1s)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    """Convert a list of bits back to a bytes object."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte = (byte << 1) | bits[i + j]
            else:
                byte = byte << 1
        result.append(byte)
    return bytes(result)


def permute(data, table):
    """Apply a permutation table to the data (list of bits)."""
    return [data[i - 1] for i in table]


def left_shift(bits, n):
    """Circular left shift of a list of bits by n positions."""
    return bits[n:] + bits[:n]


def xor_bits(a, b):
    """XOR two lists of bits element-wise."""
    return [x ^ y for x, y in zip(a, b)]


# ============================================================
# Key Schedule — Generate 16 Round Subkeys
# ============================================================

def generate_subkeys(key_bytes):
    """
    Generate 16 round subkeys from a 64-bit (8-byte) DES key.
    
    Steps:
    1. Apply PC-1 to reduce 64-bit key to 56 bits
    2. Split into two 28-bit halves (C and D)
    3. For each round, left-shift both halves and apply PC-2
       to produce a 48-bit subkey
    
    Args:
        key_bytes: 8-byte key as bytes
    
    Returns:
        List of 16 subkeys, each a list of 48 bits
    """
    # Convert key to bits
    key_bits = bytes_to_bits(key_bytes)
    
    # Apply Permuted Choice 1 (64 → 56 bits)
    key_56 = permute(key_bits, PC1)
    
    # Split into left (C) and right (D) halves, each 28 bits
    C = key_56[:28]
    D = key_56[28:]
    
    subkeys = []
    for round_num in range(16):
        # Left circular shift both halves
        C = left_shift(C, SHIFT_SCHEDULE[round_num])
        D = left_shift(D, SHIFT_SCHEDULE[round_num])
        
        # Combine and apply Permuted Choice 2 (56 → 48 bits)
        combined = C + D
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    
    return subkeys


# ============================================================
# Feistel Function — The Heart of DES
# ============================================================

def feistel(right_half, subkey):
    """
    DES Feistel function f(R, K).
    
    Steps:
    1. Expand R from 32 to 48 bits using E table
    2. XOR expanded R with 48-bit subkey
    3. Apply 8 S-boxes to reduce 48 bits back to 32 bits
    4. Apply P permutation
    
    Args:
        right_half: 32-bit list (right half of the block)
        subkey: 48-bit list (round subkey)
    
    Returns:
        32-bit list after applying the Feistel function
    """
    # Step 1: Expansion (32 → 48 bits)
    expanded = permute(right_half, E)
    
    # Step 2: XOR with subkey
    xored = xor_bits(expanded, subkey)
    
    # Step 3: S-box substitution (48 → 32 bits)
    sbox_output = []
    for i in range(8):
        # Extract 6-bit chunk for this S-box
        chunk = xored[i * 6:(i + 1) * 6]
        
        # Row = first and last bits (2-bit number)
        row = (chunk[0] << 1) | chunk[5]
        
        # Column = middle 4 bits (4-bit number)
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        
        # Look up value in S-box
        val = S_BOXES[i][row][col]
        
        # Convert 4-bit value to bits
        for j in range(3, -1, -1):
            sbox_output.append((val >> j) & 1)
    
    # Step 4: P permutation (32 → 32 bits)
    result = permute(sbox_output, P)
    
    return result


# ============================================================
# DES Block Encryption / Decryption (64-bit blocks)
# ============================================================

def des_encrypt_block(block_bits, subkeys):
    """
    Encrypt a single 64-bit block using DES.
    
    Steps:
    1. Apply Initial Permutation (IP)
    2. 16 rounds of the Feistel network
    3. Swap halves after last round
    4. Apply Final Permutation (FP)
    
    Args:
        block_bits: 64-bit list (plaintext block)
        subkeys: List of 16 subkeys (each 48-bit list)
    
    Returns:
        64-bit list (ciphertext block)
    """
    # Step 1: Initial Permutation
    block = permute(block_bits, IP)
    
    # Split into left and right halves (32 bits each)
    left = block[:32]
    right = block[32:]
    
    # Step 2: 16 rounds of Feistel network
    for round_num in range(16):
        # Save right half
        prev_right = right[:]
        
        # Apply Feistel function and XOR with left half
        f_output = feistel(right, subkeys[round_num])
        right = xor_bits(left, f_output)
        
        # Left becomes previous right
        left = prev_right
    
    # Step 3: Combine (note: right + left, NOT left + right)
    combined = right + left
    
    # Step 4: Final Permutation
    ciphertext = permute(combined, FP)
    
    return ciphertext


def des_decrypt_block(block_bits, subkeys):
    """
    Decrypt a single 64-bit block using DES.
    Decryption is the same as encryption but with subkeys in reverse order.
    
    Args:
        block_bits: 64-bit list (ciphertext block)
        subkeys: List of 16 subkeys (each 48-bit list)
    
    Returns:
        64-bit list (plaintext block)
    """
    # Use subkeys in reverse order for decryption
    return des_encrypt_block(block_bits, subkeys[::-1])


# ============================================================
# PKCS5 Padding
# ============================================================

def pkcs5_pad(data):
    """
    Add PKCS5 padding to data to make it a multiple of 8 bytes.
    Each padding byte has the value of the number of padding bytes added.
    """
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def pkcs5_unpad(data):
    """
    Remove PKCS5 padding from data.
    The last byte indicates how many padding bytes to remove.
    """
    if len(data) == 0:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid PKCS5 padding")
    # Verify all padding bytes are correct
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Invalid PKCS5 padding")
    return data[:-pad_len]


# ============================================================
# High-Level Encrypt / Decrypt Functions
# ============================================================

def des_encrypt(data, key):
    """
    Encrypt arbitrary-length data using DES in ECB mode.
    
    Args:
        data: bytes — plaintext data to encrypt
        key: bytes — 8-byte DES key
    
    Returns:
        bytes — encrypted ciphertext
    """
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    
    # Generate 16 round subkeys
    subkeys = generate_subkeys(key)
    
    # Pad the data to a multiple of 8 bytes
    padded = pkcs5_pad(data)
    
    # Encrypt each 8-byte (64-bit) block
    ciphertext = b""
    for i in range(0, len(padded), 8):
        block = padded[i:i + 8]
        block_bits = bytes_to_bits(block)
        encrypted_bits = des_encrypt_block(block_bits, subkeys)
        ciphertext += bits_to_bytes(encrypted_bits)
    
    return ciphertext


def des_decrypt(data, key):
    """
    Decrypt DES-encrypted data in ECB mode.
    
    Args:
        data: bytes — ciphertext data to decrypt
        key: bytes — 8-byte DES key (same key used for encryption)
    
    Returns:
        bytes — decrypted plaintext
    """
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    if len(data) % 8 != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")
    
    # Generate 16 round subkeys
    subkeys = generate_subkeys(key)
    
    # Decrypt each 8-byte (64-bit) block
    plaintext = b""
    for i in range(0, len(data), 8):
        block = data[i:i + 8]
        block_bits = bytes_to_bits(block)
        decrypted_bits = des_decrypt_block(block_bits, subkeys)
        plaintext += bits_to_bytes(decrypted_bits)
    
    # Remove padding
    plaintext = pkcs5_unpad(plaintext)
    
    return plaintext


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("DES Implementation — Self-Test")
    print("=" * 60)
    
    # Test with a known plaintext and key
    key = b"DESCRYPT"  # 8-byte key
    plaintext = b"Hello, this is a test of DES encryption from scratch!"
    
    print(f"\nKey       : {key}")
    print(f"Plaintext : {plaintext}")
    print(f"PT Length : {len(plaintext)} bytes")
    
    # Encrypt
    ciphertext = des_encrypt(plaintext, key)
    print(f"\nCiphertext: {ciphertext.hex()}")
    print(f"CT Length : {len(ciphertext)} bytes")
    
    # Decrypt
    decrypted = des_decrypt(ciphertext, key)
    print(f"\nDecrypted : {decrypted}")
    print(f"DT Length : {len(decrypted)} bytes")
    
    # Verify
    if decrypted == plaintext:
        print("\n✅ SUCCESS — Decrypted text matches original plaintext!")
    else:
        print("\n❌ FAILURE — Mismatch detected!")
    
    print("=" * 60)
