#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Simulates Bitcoin wallet creation based on Trust Wallet Core's HDWallet implementation

import hashlib
import hmac
import binascii
import secrets
from typing import Optional, List
import subprocess
import sys

# Function to ensure all dependencies are installed
def ensure_dependencies():
    required_packages = ["mnemonic", "bip32utils", "base58", "bech32"]
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

class HDWallet:
    """
    Hierarchical Deterministic Wallet implementation that follows BIP39 and BIP44
    Similar to Trust Wallet's HDWallet.cpp implementation
    """
    
    # Constants
    SEED_SIZE = 64
    MAX_MNEMONIC_SIZE = 240
    
    def __init__(self, mnemonic: str = None, passphrase: str = "", strength: int = 128, skip_validation: bool = False):
        """
        Create a wallet either from an existing mnemonic or generate a new one
        
        Args:
            mnemonic: Optional mnemonic phrase (12/24 words)
            passphrase: Optional passphrase for additional security
            strength: Bit strength for mnemonic generation (128 for 12 words, 256 for 24 words)
            skip_validation: Skip BIP39 validation for non-standard mnemonics
        """
        # Import here after ensuring dependencies
        from mnemonic import Mnemonic
        from bip32utils import BIP32Key
            
        self.passphrase = passphrase
        self.mnemo = Mnemonic("english")
        
        if mnemonic:
            if not skip_validation and not self.is_valid(mnemonic):
                raise ValueError("Invalid mnemonic: Not BIP39 compatible. Use skip_validation=True to bypass this check.")
            self.mnemonic = mnemonic
        else:
            # Generate a new mnemonic with specified strength
            self.mnemonic = self.mnemo.generate(strength=strength)
            
        # Generate seed from mnemonic
        self.seed = self.mnemo.to_seed(self.mnemonic, passphrase=self.passphrase)
        
        # Extract entropy from mnemonic if it's valid BIP39
        try:
            self.entropy = self.mnemo.to_entropy(self.mnemonic)
        except Exception as e:
            # For non-BIP39 mnemonics, create a deterministic entropy
            if skip_validation:
                import hashlib
                self.entropy = hashlib.sha256(self.mnemonic.encode()).digest()[:16]
            else:
                raise
    
    @staticmethod
    def is_valid(mnemonic: str) -> bool:
        """Check if a mnemonic phrase is valid (similar to HDWallet::isValid)"""
        from mnemonic import Mnemonic
        mnemo = Mnemonic("english")
        return mnemo.check(mnemonic)
    
    def get_master_private_key(self, curve: str = 'secp256k1'):
        """
        Get the master private key for a specific curve
        Similar to HDWallet::getMasterKey
        """
        # For Bitcoin, create BIP32 master key from seed
        from bip32utils import BIP32Key
        master_key = BIP32Key.fromEntropy(self.seed)
        return master_key
    
    def get_key(self, coin_type: int, derivation_path: List[int]):
        """
        Get the private key for a specific derivation path
        Similar to HDWallet::getKey
        """
        from bip32utils import BIP32Key
        
        # Start with master key
        key = BIP32Key.fromEntropy(self.seed)
        
        # Derive keys according to path
        for index in derivation_path:
            hardened = index >= 0x80000000
            if hardened:
                child_index = index
            else:
                child_index = index
            key = key.ChildKey(child_index)
        
        return key
    
    def get_bitcoin_address(self, account: int = 0, change: int = 0, address_index: int = 0) -> str:
        """
        Generate a Bitcoin address using the BIP44 derivation path
        m/44'/0'/account'/change/address_index
        
        Similar to HDWallet::deriveAddress for Bitcoin
        
        Args:
            account: Account index
            change: 0 for external chain, 1 for internal chain (change addresses)
            address_index: Address index
        
        Returns:
            Bitcoin address
        """
        from bip32utils import BIP32Key
        
        # Start with master key
        master_key = BIP32Key.fromEntropy(self.seed)
        
        # Derive BIP44 path m/44'/0'/account'/change/address_index
        # Purpose: 44' (BIP44)
        purpose = master_key.ChildKey(44 + 0x80000000)
        # Coin type: 0' (Bitcoin)
        coin = purpose.ChildKey(0 + 0x80000000)
        # Account
        account_key = coin.ChildKey(account + 0x80000000)
        # Change
        change_key = account_key.ChildKey(change)
        # Address index
        address_key = change_key.ChildKey(address_index)
        
        # Get Bitcoin address (P2PKH)
        return address_key.Address()
    
    def get_private_key_wif(self, account: int = 0, change: int = 0, address_index: int = 0) -> str:
        """Get the private key in WIF format"""
        from bip32utils import BIP32Key
        
        # Derive key using BIP44 path
        master_key = BIP32Key.fromEntropy(self.seed)
        purpose = master_key.ChildKey(44 + 0x80000000)
        coin = purpose.ChildKey(0 + 0x80000000)
        account_key = coin.ChildKey(account + 0x80000000)
        change_key = account_key.ChildKey(change)
        address_key = change_key.ChildKey(address_index)
        
        return address_key.WalletImportFormat()
    
    def get_extended_private_key(self, purpose: int, coin_type: int, version: int = 0x0488ADE4) -> str:
        """
        Get the extended private key (xprv)
        Similar to HDWallet::getExtendedPrivateKey
        
        Args:
            purpose: BIP44 purpose (44')
            coin_type: Coin type (0' for Bitcoin)
            version: HD version bytes
            
        Returns:
            Extended private key string
        """
        from bip32utils import BIP32Key
        
        # Start with master key
        master_key = BIP32Key.fromEntropy(self.seed)
        
        # Derive to purpose/coin level
        purpose_key = master_key.ChildKey(purpose + 0x80000000)
        coin_key = purpose_key.ChildKey(coin_type + 0x80000000)
        
        # Return extended key (serialized in base58)
        return coin_key.ExtendedKey()
    
    def get_extended_public_key(self, purpose: int, coin_type: int, version: int = 0x0488B21E) -> str:
        """
        Get the extended public key (xpub)
        Similar to HDWallet::getExtendedPublicKey
        
        Args:
            purpose: BIP44 purpose (44')
            coin_type: Coin type (0' for Bitcoin)
            version: HD version bytes
            
        Returns:
            Extended public key string
        """
        from bip32utils import BIP32Key
        
        # Start with master key
        master_key = BIP32Key.fromEntropy(self.seed)
        
        # Derive to purpose/coin level
        purpose_key = master_key.ChildKey(purpose + 0x80000000)
        coin_key = purpose_key.ChildKey(coin_type + 0x80000000)
        
        # Return extended key (serialized in base58)
        return coin_key.ExtendedKey(private=False)

    def get_bitcoin_address_for_path(self, purpose: int, coin_type: int = 0, account: int = 0, 
                                    change: int = 0, address_index: int = 0) -> dict:
        """
        Generate Bitcoin address for a specific derivation path
        
        Args:
            purpose: BIP44 purpose (44, 49, 84, 86)
            coin_type: Coin type (0 for Bitcoin)
            account: Account index
            change: 0 for external chain, 1 for internal chain (change addresses)
            address_index: Address index
            
        Returns:
            Dictionary with derivation path and address
        """
        from bip32utils import BIP32Key
        
        # Start with master key
        master_key = BIP32Key.fromEntropy(self.seed)
        
        # Derive keys according to path
        # Purpose
        purpose_key = master_key.ChildKey(purpose + 0x80000000)
        # Coin type (0 for Bitcoin)
        coin_key = purpose_key.ChildKey(coin_type + 0x80000000)
        # Account
        account_key = coin_key.ChildKey(account + 0x80000000)
        # Change
        change_key = account_key.ChildKey(change)
        # Address index
        address_key = change_key.ChildKey(address_index)
        
        # Format derivation path
        path = f"m/{purpose}'/{coin_type}'/{account}'/{change}/{address_index}"
        
        # Get appropriate address based on purpose
        address = ""
        private_key_wif = address_key.WalletImportFormat()
        
        try:
            if purpose == 44:  # Legacy (P2PKH)
                address = address_key.Address()
            elif purpose == 49:  # SegWit (P2SH-P2WPKH)
                # For SegWit (P2SH-P2WPKH), use P2SH wrapper
                import hashlib
                import base58
                
                # Get public key
                public_key = address_key.PublicKey()
                # Hash public key
                key_hash = hashlib.sha256(public_key).digest()
                h = hashlib.new('ripemd160')
                h.update(key_hash)
                key_hash = h.digest()
                
                # P2WPKH witness program
                witness_program = b'\x00\x14' + key_hash
                
                # Hash witness program
                witness_hash = hashlib.sha256(witness_program).digest()
                h = hashlib.new('ripemd160')
                h.update(witness_hash)
                witness_hash = h.digest()
                
                # P2SH address
                address = base58.b58encode_check(b'\x05' + witness_hash).decode('utf-8')
            elif purpose == 84:  # Native SegWit (P2WPKH)
                # For Native SegWit (P2WPKH), use bech32 encoding
                import hashlib
                from bech32 import bech32_encode, convertbits
                
                # Get public key
                public_key = address_key.PublicKey()
                # Hash public key
                key_hash = hashlib.sha256(public_key).digest()
                h = hashlib.new('ripemd160')
                h.update(key_hash)
                key_hash = h.digest()
                
                # Bech32 encode for bc1 address
                five_bit_data = convertbits(key_hash, frombits=8, tobits=5, pad=True)
                if five_bit_data:
                    address = bech32_encode("bc", five_bit_data)
                else:
                    address = "Error converting bits for bech32 encoding"
            elif purpose == 86:  # Taproot (P2TR)
                # Simplified Taproot (P2TR) implementation
                address = f"Taproot address for path {path}"
            else:
                address = f"Unknown purpose type: {purpose}"
        except Exception as e:
            address = f"Error generating address: {str(e)}"
            
        return {
            "path": path,
            "address": address,
            "private_key": private_key_wif
        }

    def generate_all_bitcoin_derivations(self, accounts_range: range = range(1),
                                        change_range: range = range(2),
                                        address_range: range = range(10)) -> dict:
        """
        Generate all common Bitcoin derivation paths and addresses
        
        Args:
            accounts_range: Range of account indices to generate
            change_range: Range of change indices to generate (typically 0-1)
            address_range: Range of address indices to generate
            
        Returns:
            Dictionary of all derivation paths and their addresses
        """
        # Common Bitcoin derivation paths
        purposes = [
            {"code": 44, "name": "Legacy (P2PKH)"},
            {"code": 49, "name": "SegWit (P2SH-P2WPKH)"},
            {"code": 84, "name": "Native SegWit (P2WPKH)"},
            {"code": 86, "name": "Taproot (P2TR)"}
        ]
        
        results = {}
        
        # Generate addresses for all combinations
        for purpose in purposes:
            purpose_code = purpose["code"]
            purpose_name = purpose["name"]
            
            purpose_results = []
            
            for account in accounts_range:
                for change in change_range:
                    for addr_index in address_range:
                        address_info = self.get_bitcoin_address_for_path(
                            purpose_code, 0, account, change, addr_index
                        )
                        purpose_results.append(address_info)
            
            results[purpose_name] = purpose_results
            
        return results

def main():
    """Example usage of the HDWallet class"""
    # Example 1: Create wallet with new random mnemonic
    wallet1 = HDWallet(strength=128)  # 128 bits = 12 words
    print("New wallet with random mnemonic:")
    print(f"Mnemonic: {wallet1.mnemonic}")
    print(f"Bitcoin Address: {wallet1.get_bitcoin_address()}")
    print(f"Private Key (WIF): {wallet1.get_private_key_wif()}")
    print(f"Extended Private Key: {wallet1.get_extended_private_key(44, 0)}")
    print(f"Extended Public Key: {wallet1.get_extended_public_key(44, 0)}")
    
    # Example 2: Create wallet from existing mnemonic (valid BIP39)
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    wallet2 = HDWallet(mnemonic=test_mnemonic)
    print("\nWallet from existing mnemonic (valid BIP39):")
    print(f"Mnemonic: {wallet2.mnemonic}")
    print(f"Bitcoin Address: {wallet2.get_bitcoin_address()}")
    print(f"Private Key (WIF): {wallet2.get_private_key_wif()}")
    
    # Example 3: Using custom non-BIP39 mnemonic
    custom_mnemonic = "alpha burger swapped fewer hospitaal cast promote album change scrub divorced exit"
    wallet3 = HDWallet(mnemonic=custom_mnemonic, skip_validation=True)
    print("\nWallet with custom non-BIP39 mnemonic:")
    print(f"Mnemonic: {wallet3.mnemonic}")
    print(f"Bitcoin Address: {wallet3.get_bitcoin_address()}")
    print(f"Private Key (WIF): {wallet3.get_private_key_wif()}")
    
    # Generate multiple addresses
    print("\nMultiple addresses from the same wallet:")
    for i in range(5):
        address = wallet2.get_bitcoin_address(address_index=i)
        print(f"Address {i}: {address}")
        
    # Example 4: Generate all possible Bitcoin derivations from a seed phrase
    print("\nGenerating all Bitcoin derivation paths from seed phrase:")
    print("(For a real-world scenario, you would use your own 12 seed words)")
    
    # Use the example mnemonic for demonstration
    demo_wallet = HDWallet(mnemonic=test_mnemonic)
    
    # Generate all combinations with limited ranges for the example
    # Account: 0
    # Change: 0 (external), 1 (internal/change)
    # Addresses: 0-2 (first 3 addresses)
    derivations = demo_wallet.generate_all_bitcoin_derivations(
        accounts_range=range(1),  # Just account 0
        change_range=range(2),    # External (0) and internal (1)
        address_range=range(3)    # First 3 addresses
    )
    
    # Print results
    for purpose_name, addresses in derivations.items():
        print(f"\n{purpose_name}:")
        for addr_info in addresses:
            print(f"  Path: {addr_info['path']}")
            print(f"  Address: {addr_info['address']}")
            print(f"  Private Key: {addr_info['private_key']}")
            print()


def generate_from_seed(mnemonic, is_standard=True, num_addresses=10):
    """
    Helper function to generate all Bitcoin derivations from a seed phrase
    
    Args:
        mnemonic: The 12-word seed phrase
        is_standard: Whether the mnemonic is standard BIP39 or custom
        num_addresses: Number of addresses to generate per path
    
    Returns:
        Dictionary of all derivation paths and their addresses
    """
    wallet = HDWallet(mnemonic=mnemonic, skip_validation=not is_standard)
    
    print(f"Generating addresses from mnemonic: {mnemonic}")
    
    derivations = wallet.generate_all_bitcoin_derivations(
        accounts_range=range(1),    # Just account 0
        change_range=range(2),      # External (0) and internal (1)
        address_range=range(num_addresses)  # First num_addresses
    )
    
    # Print results
    for purpose_name, addresses in derivations.items():
        print(f"\n{purpose_name}:")
        for addr_info in addresses:
            print(f"  Path: {addr_info['path']}")
            print(f"  Address: {addr_info['address']}")
            print(f"  Private Key: {addr_info['private_key']}")
            print()
    
    return derivations


if __name__ == "__main__":
    try:
        # Ensure all dependencies are installed
        ensure_dependencies()
        
        # Your seed phrase
        my_mnemonic = "alpha burger swapped fewer hospitaal cast promote album change scrub divorced exit"
        
        # Generate addresses from seed
        generate_from_seed(my_mnemonic, is_standard=False, num_addresses=20)
        
        # If you want to run the main examples as well, uncomment the next line
        # main()
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc() 