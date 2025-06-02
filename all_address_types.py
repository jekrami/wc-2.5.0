#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Generates all Bitcoin address types from a seed phrase

import hashlib
import hmac
import binascii
import subprocess
import sys
import csv
from typing import List, Dict, Any, Optional

# Function to ensure all dependencies are installed
def ensure_dependencies():
    required_packages = ["mnemonic", "bip32utils", "base58", "bech32", "ecdsa"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Installing missing packages: {', '.join(missing_packages)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
        print("Packages installed successfully.")

# Call this at the beginning of the script
ensure_dependencies()

# Now import the necessary packages
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN
import base58
from bech32 import bech32_encode, convertbits
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string


class AddressGenerator:
    """
    Bitcoin address generator that supports multiple address types:
    - P2PKH (Compressed and Uncompressed)
    - P2WPKH (Native SegWit)
    - P2SH-P2WPKH (Nested SegWit)
    - P2SH-P2PKH
    - P2WSH-P2WPKH
    - P2WSH-P2PKH
    """
    
    def __init__(self, mnemonic: str, passphrase: str = "", skip_validation: bool = False):
        """
        Initialize with a mnemonic phrase

        Args:
            mnemonic: BIP39 mnemonic phrase
            passphrase: Optional passphrase for additional security
            skip_validation: Skip BIP39 validation for non-standard mnemonics
        """
        self.mnemonic = mnemonic
        self.passphrase = passphrase
        self.mnemo = Mnemonic("english")
        
        # Validate mnemonic unless skipped
        if not skip_validation and not self.mnemo.check(mnemonic):
            raise ValueError("Invalid BIP39 mnemonic. Use skip_validation=True for non-standard mnemonics.")
        
        # Generate seed from mnemonic
        self.seed = self.mnemo.to_seed(self.mnemonic, passphrase=self.passphrase)
        
        # Try to get entropy if valid BIP39
        try:
            self.entropy = self.mnemo.to_entropy(self.mnemonic)
        except Exception:
            if skip_validation:
                # For non-BIP39 mnemonics, create deterministic entropy
                self.entropy = hashlib.sha256(self.mnemonic.encode()).digest()[:16]
            else:
                raise
    
    def get_master_node(self):
        """Get the BIP32 master node from seed"""
        return BIP32Key.fromEntropy(self.seed)
    
    def derive_key(self, path: str):
        """
        Derive a key using a BIP32 path string

        Args:
            path: BIP32 path (e.g., "m/44'/0'/0'/0/0")
        
        Returns:
            BIP32Key object
        """
        # Parse path string
        if path.lower().startswith('m/'):
            path = path[2:]
        
        path_indices = path.split('/')
        
        # Start with master key
        key = self.get_master_node()
        
        # Derive child keys
        for idx in path_indices:
            if idx.endswith("'") or idx.endswith("h"):
                # Hardened derivation
                index = int(idx[:-1]) + BIP32_HARDEN
            else:
                # Normal derivation
                index = int(idx)
            
            key = key.ChildKey(index)
        
        return key
    
    def hash160(self, data: bytes) -> bytes:
        """Perform RIPEMD160(SHA256(data))"""
        sha256_hash = hashlib.sha256(data).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        return ripemd160.digest()
    
    def get_p2pkh_address_compressed(self, key: BIP32Key) -> str:
        """
        Get a P2PKH address with compressed public key

        Args:
            key: BIP32Key object
        
        Returns:
            P2PKH address (1...)
        """
        # Default implementation is compressed
        return key.Address()
    
    def get_p2pkh_address_uncompressed(self, key: BIP32Key) -> str:
        """
        Get a P2PKH address with uncompressed public key

        Args:
            key: BIP32Key object
        
        Returns:
            P2PKH address (1...)
        """
        # Get uncompressed public key from private key
        from ecdsa import SigningKey, SECP256k1
        
        # Get private key bytes
        private_key_bytes = key.PrivateKey()
        
        # Create signing key
        sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        # Get uncompressed public key (65 bytes: 0x04 + 32-byte x coord + 32-byte y coord)
        vk = sk.get_verifying_key()
        uncompressed_pub_key = b'\x04' + vk.to_string()
        
        # Hash160 of uncompressed public key
        h160 = self.hash160(uncompressed_pub_key)
        
        # Create P2PKH address
        return base58.b58encode_check(b'\x00' + h160).decode('utf-8')
    
    def get_p2wpkh_address(self, key: BIP32Key) -> str:
        """
        Get a P2WPKH (Native SegWit) address

        Args:
            key: BIP32Key object
        
        Returns:
            Native SegWit address (bc1q...)
        """
        # Get compressed public key
        public_key = key.PublicKey()
        
        # Hash160 of public key
        key_hash = self.hash160(public_key)
        
        # Convert 8-bit bytes to 5-bit bytes for bech32 encoding
        five_bit_data = convertbits(key_hash, frombits=8, tobits=5, pad=True)
        
        # Encode as bech32 address
        return bech32_encode("bc", five_bit_data)
    
    def get_p2sh_p2wpkh_address(self, key: BIP32Key) -> str:
        """
        Get a P2SH-P2WPKH (Nested SegWit) address

        Args:
            key: BIP32Key object
        
        Returns:
            P2SH-P2WPKH address (3...)
        """
        # Get compressed public key
        public_key = key.PublicKey()
        
        # Hash160 of public key
        key_hash = self.hash160(public_key)
        
        # Create P2WPKH witness program
        witness_program = b'\x00\x14' + key_hash
        
        # Hash160 of witness program
        script_hash = self.hash160(witness_program)
        
        # Create P2SH address
        return base58.b58encode_check(b'\x05' + script_hash).decode('utf-8')
    
    def get_p2sh_p2pkh_address(self, key: BIP32Key) -> str:
        """
        Get a P2SH-P2PKH address

        Args:
            key: BIP32Key object
        
        Returns:
            P2SH-P2PKH address (3...)
        """
        # Get compressed public key
        public_key = key.PublicKey()
        
        # Hash160 of public key
        key_hash = self.hash160(public_key)
        
        # Create P2PKH script: OP_DUP OP_HASH160 <key_hash> OP_EQUALVERIFY OP_CHECKSIG
        script = b'\x76\xa9\x14' + key_hash + b'\x88\xac'
        
        # Hash160 of script
        script_hash = self.hash160(script)
        
        # Create P2SH address
        return base58.b58encode_check(b'\x05' + script_hash).decode('utf-8')
    
    def get_p2wsh_p2wpkh_address(self, key: BIP32Key) -> str:
        """
        Get a P2WSH-P2WPKH address

        Args:
            key: BIP32Key object
        
        Returns:
            P2WSH-P2WPKH address (bc1w...)
        """
        # Get compressed public key
        public_key = key.PublicKey()
        
        # Hash160 of public key
        key_hash = self.hash160(public_key)
        
        # Create P2WPKH script: 0 <key_hash>
        script = b'\x00\x14' + key_hash
        
        # Calculate SHA256 of script (P2WSH uses SHA256 instead of HASH160)
        script_hash = hashlib.sha256(script).digest()
        
        # Convert 8-bit bytes to 5-bit bytes for bech32 encoding
        five_bit_data = convertbits(script_hash, frombits=8, tobits=5, pad=True)
        
        # Encode as bech32 address with version 0
        return bech32_encode("bc", five_bit_data)
    
    def get_p2wsh_p2pkh_address(self, key: BIP32Key) -> str:
        """
        Get a P2WSH-P2PKH address

        Args:
            key: BIP32Key object
        
        Returns:
            P2WSH-P2PKH address (bc1w...)
        """
        # Get compressed public key
        public_key = key.PublicKey()
        
        # Hash160 of public key
        key_hash = self.hash160(public_key)
        
        # Create P2PKH script: OP_DUP OP_HASH160 <key_hash> OP_EQUALVERIFY OP_CHECKSIG
        script = b'\x76\xa9\x14' + key_hash + b'\x88\xac'
        
        # Calculate SHA256 of script (P2WSH uses SHA256 instead of HASH160)
        script_hash = hashlib.sha256(script).digest()
        
        # Convert 8-bit bytes to 5-bit bytes for bech32 encoding
        five_bit_data = convertbits(script_hash, frombits=8, tobits=5, pad=True)
        
        # Encode as bech32 address with version 0
        return bech32_encode("bc", five_bit_data)
    
    def generate_all_address_types(self, path: str) -> Dict[str, str]:
        """
        Generate all address types for a given derivation path

        Args:
            path: BIP32 path (e.g., "m/44'/0'/0'/0/0")
        
        Returns:
            Dictionary of address types and their corresponding addresses
        """
        # Derive key for the given path
        key = self.derive_key(path)
        
        # Get private key in WIF format
        private_key_wif = key.WalletImportFormat()
        
        # Generate all address types
        return {
            "path": path,
            "private_key": private_key_wif,
            "P2PKH (Compressed)": self.get_p2pkh_address_compressed(key),
            "P2PKH (Uncompressed)": self.get_p2pkh_address_uncompressed(key),
            "P2WPKH": self.get_p2wpkh_address(key),
            "P2SH-P2WPKH": self.get_p2sh_p2wpkh_address(key),
            "P2SH-P2PKH": self.get_p2sh_p2pkh_address(key),
            "P2WSH-P2WPKH": self.get_p2wsh_p2wpkh_address(key),
            "P2WSH-P2PKH": self.get_p2wsh_p2pkh_address(key)
        }
    
    def generate_addresses_for_common_paths(self, num_addresses: int = 10, output_csv: Optional[str] = None) -> Dict[str, List[Dict[str, str]]]:
        """
        Generate addresses for common Bitcoin derivation paths and optionally save them to a CSV file

        Args:
            num_addresses: Number of addresses to generate per path type
            output_csv: Path to the CSV file to save addresses (optional)
        
        Returns:
            Dictionary of path types and lists of address information
        """
        # Common derivation path prefixes
        path_prefixes = [
            {"type": "BIP44 Legacy", "prefix": "m/44'/0'/0'"},     # Legacy
            {"type": "BIP49 SegWit", "prefix": "m/49'/0'/0'"},     # SegWit
            {"type": "BIP84 Native SegWit", "prefix": "m/84'/0'/0'"},  # Native SegWit
            {"type": "BIP86 Taproot", "prefix": "m/86'/0'/0'"}     # Taproot
        ]
        
        results = {}
        all_addresses = []

        # For each path type
        for path_info in path_prefixes:
            path_type = path_info["type"]
            prefix = path_info["prefix"]
            
            path_results = []
            
            # Generate external addresses (change=0)
            for i in range(num_addresses):
                path = f"{prefix}/0/{i}"
                addr_info = self.generate_all_address_types(path)
                path_results.append(addr_info)
                all_addresses.extend([address for addr_type, address in addr_info.items() if addr_type not in ["path", "private_key"]])
            
            # Generate internal/change addresses (change=1)
            for i in range(num_addresses):
                path = f"{prefix}/1/{i}"
                addr_info = self.generate_all_address_types(path)
                path_results.append(addr_info)
                all_addresses.extend([address for addr_type, address in addr_info.items() if addr_type not in ["path", "private_key"]])
            
            results[path_type] = path_results

        if output_csv:
            with open(output_csv, mode='w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Address"])
                for address in all_addresses:
                    writer.writerow([address])
            print(f"CSV file '{output_csv}' has been created successfully.")

        return results


def print_addresses(mnemonic: str, passphrase: str = "", skip_validation: bool = False, num_addresses: int = 5):
    """
    Print all address types for a given mnemonic phrase

    Args:
        mnemonic: BIP39 mnemonic phrase
        passphrase: Optional passphrase
        skip_validation: Skip BIP39 validation for non-standard mnemonics
        num_addresses: Number of addresses to generate per path type
    """
    print(f"Generating addresses for mnemonic: {mnemonic}")
    if passphrase:
        print(f"Using passphrase: {passphrase}")
    
    try:
        # Create address generator
        generator = AddressGenerator(mnemonic, passphrase, skip_validation)
        
        # Generate addresses for all common paths
        all_addresses = generator.generate_addresses_for_common_paths(num_addresses)
        
        # Print results
        for path_type, addresses in all_addresses.items():
            print(f"\n=== {path_type} ===")
            
            for addr_info in addresses:
                print(f"\nPath: {addr_info['path']}")
                print(f"Private Key (WIF): {addr_info['private_key']}")
                
                for addr_type, address in addr_info.items():
                    if addr_type not in ["path", "private_key"]:
                        print(f"{addr_type}: {address}")
        
        print("\nAddress generation completed successfully.")
    
    except Exception as e:
        print(f"Error generating addresses: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    try:
        # Ensure dependencies are installed
        ensure_dependencies()
        
        # Your seed phrase - replace with your own
        my_mnemonic = "alpha burger swapped fewer hospitaal cast promote album change scrub divorced exit"
        
        # Create an AddressGenerator instance
        generator = AddressGenerator(
            mnemonic=my_mnemonic,
            passphrase="",
            skip_validation=True  # Set to True for non-BIP39 mnemonics
        )
        
        # Generate addresses and save them to a CSV file
        generator.generate_addresses_for_common_paths(
            num_addresses=5,  # Generate 5 addresses per path type
            output_csv="addresses.csv"  # Save addresses to addresses.csv
        )
        
        print("Addresses have been saved to addresses.csv")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()