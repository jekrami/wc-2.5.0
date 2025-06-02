import hashlib
import hmac
import bip39
import bip32utils

# Function to create a Bitcoin wallet from a 12-word mnemonic
def create_btc_wallet(mnemonic, passphrase=""):
    # Step 1: Generate seed from mnemonic and passphrase
    seed = bip39.mnemonic_to_seed(mnemonic, passphrase)

    # Step 2: Create master key using BIP32
    master_key = bip32utils.BIP32Key.fromEntropy(seed)

    # Step 3: Derive the Bitcoin address
    # Using the standard derivation path for Bitcoin: m/44'/0'/0'/0/0
    derived_key = master_key.ChildKey(44 + bip32utils.BIP32_HARDEN)
    derived_key = derived_key.ChildKey(0 + bip32utils.BIP32_HARDEN)
    derived_key = derived_key.ChildKey(0 + bip32utils.BIP32_HARDEN)
    derived_key = derived_key.ChildKey(0)
    derived_key = derived_key.ChildKey(0)

    # Get the Bitcoin address
    btc_address = derived_key.Address()

    return btc_address

# Example usage
if __name__ == "__main__":
    # Example 12-word mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    passphrase = ""  # Optional passphrase

    # Create Bitcoin wallet
    btc_address = create_btc_wallet(mnemonic, passphrase)
    print("Bitcoin Address:", btc_address)
