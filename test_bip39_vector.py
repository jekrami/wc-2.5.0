from bip_utils import Bip39SeedGenerator

# Test vector from BIP39
# Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Passphrase: "" (empty)
# Expected seed: c55257c360c07c72029aeb60b72243ad556811cb996cd9f87f6e0a904fd43b7408555847d9276cf05db24c2f967f0613891279084890fe1ef86be18dd2098542
mnemonic_bip39 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
passphrase_bip39 = ""  # Standard BIP39 test vectors often use an empty passphrase

# Generate seed using bip_utils
seed_bip_utils = Bip39SeedGenerator(mnemonic_bip39).Generate(passphrase_bip39)

print(f"Mnemonic: '{mnemonic_bip39}'")
print(f"Passphrase: '{passphrase_bip39}'")
print(f"Generated Seed (bip_utils): {seed_bip_utils.hex()}")

# For comparison, let's add the output from legacy_wallet_recovery.py for the same mnemonic
# Expected from legacy_wallet_recovery.py: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
# Expected from standard BIP39 test vector: c55257c360c07c72029aeb60b72243ad556811cb996cd9f87f6e0a904fd43b7408555847d9276cf05db24c2f967f0613891279084890fe1ef86be18dd2098542

# The user's script is legacy_wallet_recovery.py
# Let's import the function from it to make sure we are comparing apples to apples
from legacy_wallet_recovery import generate_seed_from_legacy_mnemonic

seed_legacy_script = generate_seed_from_legacy_mnemonic(mnemonic_bip39, passphrase_bip39)
print(f"Generated Seed (legacy_wallet_recovery.py): {seed_legacy_script.hex()}")
