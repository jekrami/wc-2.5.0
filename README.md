# Bitcoin Wallet Address Generator

This repository contains Python scripts to generate Bitcoin wallet addresses from a 12-word seed phrase (mnemonic). The implementation is based on the Trust Wallet Core's approach for creating HD wallets.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Address Types](#address-types)
- [Derivation Paths](#derivation-paths)
- [Full Example](#full-example)
- [Non-BIP39 Seeds](#non-bip39-seeds)
- [Troubleshooting](#troubleshooting)

## Overview

The scripts in this repository implement Bitcoin wallet address generation from mnemonic seed phrases using BIP39, BIP32, BIP44, and related standards. The implementation is based on Trust Wallet Core's approach, which follows the industry-standard Bitcoin HD wallet architecture.

There are two main scripts:
1. **wallet.py** - Basic implementation of HD wallet with Bitcoin address generation
2. **all_address_types.py** - Comprehensive script that generates all major Bitcoin address types

## Features

- Generate Bitcoin addresses from BIP39 mnemonic phrases
- Support for non-standard (non-BIP39) seed phrases
- Create addresses for all major Bitcoin address formats:
  - P2PKH (Legacy) addresses (1...)
  - P2SH (Script Hash) addresses (3...)
  - P2WPKH (Native SegWit) addresses (bc1q...)
  - P2WSH (SegWit Script Hash) addresses
  - P2TR (Taproot) addresses
- Generate addresses for multiple derivation paths
- Output private keys in WIF format
- Extensive error handling and dependency management

## Requirements

- Python 3.6 or higher
- Required Python packages (automatically installed by the scripts):
  - `mnemonic` - BIP39 mnemonic generation and handling
  - `bip32utils` - BIP32 hierarchical deterministic wallet implementation
  - `base58` - Base58 encoding and decoding
  - `bech32` - Bech32 encoding and decoding for SegWit addresses
  - `ecdsa` - Elliptic curve cryptography

## Installation

1. Clone this repository or download the script files
2. Ensure you have Python 3.6+ installed
3. The scripts will automatically install the required dependencies when run

## Basic Usage

### Generate Addresses from a Seed Phrase

To generate addresses from your 12-word seed phrase:

1. Open `all_address_types.py`
2. Edit the `my_mnemonic` variable with your 12-word seed phrase
3. Run the script:

```bash
python all_address_types.py
```

For non-BIP39 standard seed phrases, ensure the `skip_validation` parameter is set to `True`.

### Customizing Address Generation

You can modify the following parameters:

- `passphrase` - Optional passphrase for additional security
- `skip_validation` - Set to `True` for non-BIP39 compatible seed phrases
- `num_addresses` - Number of addresses to generate per derivation path

## Address Types

The `all_address_types.py` script generates the following address types:

1. **P2PKH (Compressed)** - Standard legacy addresses starting with "1"
   - Example: `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
   
2. **P2PKH (Uncompressed)** - Legacy addresses with uncompressed public keys
   - Example: `1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm`

3. **P2WPKH** - Native SegWit addresses starting with "bc1q"
   - Example: `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`

4. **P2SH-P2WPKH** - SegWit nested in P2SH (addresses starting with "3")
   - Example: `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`

5. **P2SH-P2PKH** - P2PKH nested in P2SH
   - Example: `3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX`

6. **P2WSH-P2WPKH** - P2WPKH nested in P2WSH
   - Example: `bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3`

7. **P2WSH-P2PKH** - P2PKH nested in P2WSH
   - Example: `bc1qft5p2uhsdcdc3l2ua4ap5qqfg4pjaqlp250x7us7a8qqhrxrxfsq7wqu47`

## Derivation Paths

The scripts generate addresses for the following derivation paths:

1. **BIP44 (Legacy)**: `m/44'/0'/0'/0/*` and `m/44'/0'/0'/1/*`
2. **BIP49 (SegWit)**: `m/49'/0'/0'/0/*` and `m/49'/0'/0'/1/*`
3. **BIP84 (Native SegWit)**: `m/84'/0'/0'/0/*` and `m/84'/0'/0'/1/*`
4. **BIP86 (Taproot)**: `m/86'/0'/0'/0/*` and `m/86'/0'/0'/1/*`

Where:
- The first `/0/` or `/1/` indicates external (receiving) or internal (change) addresses
- The final `/*` is the address index (0, 1, 2, etc.)

## Full Example

Here's a complete example of how to use the code to generate Bitcoin addresses from a seed phrase:

```python
# 1. Import the required module from all_address_types.py
from all_address_types import print_addresses

# 2. Your 12-word seed phrase
my_seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# 3. Generate and display all address types
print_addresses(
    mnemonic=my_seed_phrase,
    passphrase="",             # Optional passphrase
    skip_validation=False,     # Set to True for non-BIP39 seed phrases
    num_addresses=5            # Generate 5 addresses per path type
)
```

## Non-BIP39 Seeds

For non-standard seed phrases that don't conform to the BIP39 specification:

1. Set `skip_validation=True` when calling the functions
2. The code will use a SHA256 hash of the seed phrase to generate deterministic entropy
3. This ensures compatibility with any set of words used as a seed phrase

Example with a non-BIP39 seed phrase:

```python
non_standard_seed = "alpha burger swapped fewer hospitaal cast promote album change scrub divorced exit"
print_addresses(mnemonic=non_standard_seed, skip_validation=True)
```

## Troubleshooting

### Missing Dependencies

If you encounter dependency issues:

```bash
pip install mnemonic bip32utils base58 bech32 ecdsa
```

### Error Handling

The scripts include comprehensive error handling and will display detailed error messages if problems occur. If you encounter any issues:

1. Ensure your seed phrase is entered correctly
2. Check that the `skip_validation` flag is set correctly for your seed phrase type
3. Review the error message and traceback for specific information

### Known Limitations

- Taproot (P2TR) address implementation in the basic `wallet.py` script is limited
- Some complex nested address types may require additional libraries for full validation

---

This README and the associated scripts were created based on an analysis of Trust Wallet Core's HDWallet implementation, adapted for Python to enable Bitcoin address recovery from seed phrases. 