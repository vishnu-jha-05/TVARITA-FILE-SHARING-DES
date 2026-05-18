"""
Diffie-Hellman Key Exchange — Implementation from Scratch

Implements the Diffie-Hellman key exchange protocol for securely
establishing a shared secret key between two parties over an
insecure channel.

Steps:
1. Both parties agree on public parameters (prime p, generator g)
2. Each party generates a private key
3. Each party computes and shares their public key
4. Each party computes the shared secret from the other's public key
5. The shared secret is used to derive a DES encryption key

Project: Secure File Sharing System using DES and Diffie-Hellman
"""

import random
import hashlib


# ============================================================
# Public Parameters — Well-Known Safe Prime and Generator
# ============================================================

# A 1024-bit safe prime (from RFC 2409 / OAKLEY Group 2)
# This is a widely-used prime for Diffie-Hellman that is known to be safe.
# Using a well-known prime is standard practice (not a security weakness).
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF",
    16
)

# Generator (primitive root modulo p)
DH_GENERATOR = 2


# ============================================================
# Diffie-Hellman Key Exchange Class
# ============================================================

class DiffieHellman:
    """
    Diffie-Hellman Key Exchange Implementation.
    
    Usage:
        # Party A
        alice = DiffieHellman()
        alice_public = alice.get_public_key()
        
        # Party B
        bob = DiffieHellman()
        bob_public = bob.get_public_key()
        
        # Exchange public keys and compute shared secret
        alice_shared = alice.compute_shared_secret(bob_public)
        bob_shared = bob.compute_shared_secret(alice_public)
        
        # alice_shared == bob_shared (same shared secret!)
        
        # Derive DES key
        des_key = alice.derive_des_key(bob_public)
    """
    
    def __init__(self, prime=None, generator=None, private_key=None):
        """
        Initialize Diffie-Hellman with public parameters.
        
        Args:
            prime: Large prime number p (default: 1024-bit safe prime)
            generator: Generator g (default: 2)
            private_key: Optional private key (randomly generated if not provided)
        """
        self.prime = prime or DH_PRIME
        self.generator = generator or DH_GENERATOR
        
        # Generate random private key (256 bits for security)
        if private_key is not None:
            self.private_key = private_key
        else:
            self.private_key = random.randint(2, self.prime - 2)
        
        # Compute public key: A = g^a mod p
        self.public_key = pow(self.generator, self.private_key, self.prime)
    
    def get_public_key(self):
        """Return the public key to share with the other party."""
        return self.public_key
    
    def get_public_key_hex(self):
        """Return the public key as a hex string (for network transmission)."""
        return hex(self.public_key)[2:]
    
    @staticmethod
    def public_key_from_hex(hex_string):
        """Convert a hex string back to a public key integer."""
        return int(hex_string, 16)
    
    def compute_shared_secret(self, other_public_key):
        """
        Compute the shared secret using the other party's public key.
        
        Formula: shared_secret = other_public_key ^ private_key mod prime
        
        Args:
            other_public_key: The other party's public key (integer)
        
        Returns:
            The shared secret as an integer
        """
        if other_public_key <= 1 or other_public_key >= self.prime:
            raise ValueError("Invalid public key received")
        
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        return shared_secret
    
    def derive_des_key(self, other_public_key):
        """
        Derive an 8-byte DES key from the shared secret.
        
        Uses SHA-256 hash of the shared secret and takes the first 8 bytes
        to create a valid DES key.
        
        Args:
            other_public_key: The other party's public key (integer)
        
        Returns:
            8-byte DES key as bytes
        """
        # Compute shared secret
        shared_secret = self.compute_shared_secret(other_public_key)
        
        # Convert shared secret to bytes
        secret_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        # Hash with SHA-256 for uniform distribution
        hash_digest = hashlib.sha256(secret_bytes).digest()
        
        # Take first 8 bytes as DES key
        des_key = hash_digest[:8]
        
        return des_key
    
    def get_parameters(self):
        """Return the public parameters (prime and generator)."""
        return {
            'prime': self.prime,
            'generator': self.generator,
            'prime_bits': self.prime.bit_length(),
        }


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Diffie-Hellman Key Exchange — Self-Test")
    print("=" * 60)
    
    # Simulate two parties: Alice and Bob
    print("\n--- Generating keys ---")
    alice = DiffieHellman()
    bob = DiffieHellman()
    
    params = alice.get_parameters()
    print(f"Prime bits    : {params['prime_bits']}")
    print(f"Generator     : {params['generator']}")
    
    # Get public keys
    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()
    
    print(f"\nAlice public  : {str(alice_public)[:40]}...")
    print(f"Bob public    : {str(bob_public)[:40]}...")
    
    # Compute shared secrets
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)
    
    print(f"\nAlice shared  : {str(alice_shared)[:40]}...")
    print(f"Bob shared    : {str(bob_shared)[:40]}...")
    
    # Verify they match
    if alice_shared == bob_shared:
        print("\n✅ Shared secrets MATCH!")
    else:
        print("\n❌ Shared secrets DO NOT match!")
    
    # Derive DES keys
    alice_des_key = alice.derive_des_key(bob_public)
    bob_des_key = bob.derive_des_key(alice_public)
    
    print(f"\nAlice DES key : {alice_des_key.hex()}")
    print(f"Bob DES key   : {bob_des_key.hex()}")
    
    if alice_des_key == bob_des_key:
        print("\n✅ DES keys MATCH! Ready for encryption.")
    else:
        print("\n❌ DES keys DO NOT match!")
    
    print("=" * 60)
