import hashlib
import unicodedata
import argparse
import sys
import csv
from typing import List

# Corrected and verified imports:
from bip_utils import (
    Bip32Secp256k1 as Bip32,
    Bip39SeedGenerator,
    WifPubKeyModes,
    Bip32KeyError # Bip32KeyError is top-level
)
# No longer need: from bip_utils.bip.bip32 import Bip32KeyError
from bip_utils.addr import P2PKHAddr, P2SHAddr, P2WPKHAddr, P2TRAddr # Specific address generators
from bip_utils.wif import WifEncoder # WifDecoder is available if needed
from bip_utils.ecc import Secp256k1PublicKey, Secp256k1PrivateKey # Specific ECC curve classes

# Network parameters for Bitcoin MainNet
BITCOIN_MAINNET_WIF_NET_VER = b'\x80'
BITCOIN_MAINNET_P2PKH_NET_VER = b'\x00'
BITCOIN_MAINNET_P2SH_NET_VER = b'\x05'
BITCOIN_MAINNET_BECH32_HRP = "bc"

DEFAULT_DERIVATION_PATHS = [
    "m/44'/0'/0'/0/0",  # BIP44 P2PKH (Legacy)
    "m/44'/0'/0'/0/1",
    "m/49'/0'/0'/0/0",  # BIP49 P2SH-P2WPKH (Nested SegWit)
    "m/49'/0'/0'/0/1",
    "m/84'/0'/0'/0/0",  # BIP84 P2WPKH (Native SegWit)
    "m/84'/0'/0'/0/1",
    "m/86'/0'/0'/0/0",  # BIP86 P2TR (Taproot)
    "m/86'/0'/0'/0/1",
    "m/0/0",
    "m/0/1",
]

# Store original normalize_string for potential patching
_original_normalize_string = unicodedata.normalize

def normalize_string_config(s: str) -> str:
    # This function will be reassigned if --no-normalize is used
    return _original_normalize_string('NFKD', s)

def generate_seed_from_legacy_mnemonic(mnemonic_phrase: str, passphrase: str = "") -> bytes:
    # Use the potentially patched normalize_string_config
    normalized_mnemonic = normalize_string_config(mnemonic_phrase)
    normalized_passphrase = normalize_string_config(passphrase)

    password = normalized_mnemonic.encode('utf-8')
    salt = ("mnemonic" + normalized_passphrase).encode('utf-8')
    try:
        seed = hashlib.pbkdf2_hmac(
            hash_name='sha512',
            password=password,
            salt=salt,
            iterations=2048,
            dklen=64
        )
        return seed
    except Exception as e:
        print(f"Error generating seed: {e}", file=sys.stderr)
        sys.exit(1)

def derive_keys_and_addresses(seed_bytes: bytes, derivation_path_str: str):
    try:
        bip32_mst_ctx = Bip32.FromSeed(seed_bytes)
        bip32_der_ctx = bip32_mst_ctx.DerivePath(derivation_path_str)

        priv_key_bip32_obj = bip32_der_ctx.PrivateKey()
        ecc_priv_key_obj = priv_key_bip32_obj.KeyObject()

        wif_priv_key = WifEncoder.Encode(
            ecc_priv_key_obj,
            pub_key_mode=WifPubKeyModes.COMPRESSED,
            net_ver=BITCOIN_MAINNET_WIF_NET_VER
        )

        pub_key_bip32_obj = bip32_der_ctx.PublicKey()
        ecc_pub_key_obj = Secp256k1PublicKey.FromBytes(pub_key_bip32_obj.RawCompressed().ToBytes())

        compressed_pub_key_hex = ecc_pub_key_obj.RawCompressed().ToHex()
        uncompressed_pub_key_hex = ecc_pub_key_obj.RawUncompressed().ToHex()

        p2pkh_address_compressed = P2PKHAddr.EncodeKey(ecc_pub_key_obj, net_ver=BITCOIN_MAINNET_P2PKH_NET_VER)
        p2pkh_address_uncompressed = P2PKHAddr.EncodeKey(
            Secp256k1PublicKey.FromBytes(ecc_pub_key_obj.RawUncompressed().ToBytes()),
            net_ver=BITCOIN_MAINNET_P2PKH_NET_VER
        )

        p2sh_p2pkh_address = P2SHAddr.EncodeKey(
            Secp256k1PublicKey.FromBytes(ecc_pub_key_obj.RawCompressed().ToBytes()),
            net_ver=BITCOIN_MAINNET_P2SH_NET_VER
        )

        p2sh_p2wpkh_address = P2SHAddr.EncodeKey(ecc_pub_key_obj, net_ver=BITCOIN_MAINNET_P2SH_NET_VER)
        p2wpkh_address = P2WPKHAddr.EncodeKey(ecc_pub_key_obj, hrp=BITCOIN_MAINNET_BECH32_HRP)

        # Custom logic for generating P2WSH addresses
        p2wsh_p2wpkh_address = P2SHAddr.EncodeKey(ecc_pub_key_obj, net_ver=BITCOIN_MAINNET_P2SH_NET_VER)
        p2wsh_p2pkh_address = P2SHAddr.EncodeKey(
            Secp256k1PublicKey.FromBytes(ecc_pub_key_obj.RawCompressed().ToBytes()),
            net_ver=BITCOIN_MAINNET_P2SH_NET_VER
        )

        try:
            p2tr_address = P2TRAddr.EncodeKey(ecc_pub_key_obj, hrp=BITCOIN_MAINNET_BECH32_HRP)
        except Exception as e:
            p2tr_address = f"N/A (P2TR Error: {type(e).__name__})"

        return {
            "derivation_path": derivation_path_str,
            "private_key_wif": wif_priv_key,
            "public_key_compressed_hex": compressed_pub_key_hex,
            "public_key_uncompressed_hex": uncompressed_pub_key_hex,
            "p2pkh_address_compressed": p2pkh_address_compressed,
            "p2pkh_address_uncompressed": p2pkh_address_uncompressed,
            "p2sh_p2pkh_address": p2sh_p2pkh_address,
            "p2sh_p2wpkh_address": p2sh_p2wpkh_address,
            "p2wpkh_address": p2wpkh_address,
            "p2wsh_p2wpkh_address": p2wsh_p2wpkh_address,
            "p2wsh_p2pkh_address": p2wsh_p2pkh_address,
            "p2tr_address": p2tr_address,
        }
    except Bip32KeyError as e:
        return {"derivation_path": derivation_path_str, "error": f"BIP32 Key Error ({type(e).__name__}): {e}"}
    except Exception as e:
        return {"derivation_path": derivation_path_str, "error": f"Unexpected error for path {derivation_path_str} ({type(e).__name__}): {e}"}

def read_seeds_from_csv(file_path: str) -> List[str]:
    """
    Read seed phrases from a CSV file.

    Args:
        file_path: Path to the CSV file containing seed phrases.

    Returns:
        List of seed phrases.
    """
    seeds = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) == 1:  # Each row contains one seed phrase
                    seeds.append(row[0])
    except Exception as e:
        print(f"Error reading seeds from CSV: {e}", file=sys.stderr)
        sys.exit(1)
    return seeds

def generate_addresses_from_seeds(input_csv: str, output_csv: str):
    """
    Generate addresses for all seeds in the input CSV and save them to the output CSV.

    Args:
        input_csv: Path to the input CSV file containing seed phrases.
        output_csv: Path to the output CSV file to save generated addresses.
    """
    seeds = read_seeds_from_csv(input_csv)

    with open(output_csv, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Seed", "Derivation Path", "Private Key (WIF)", "Public Key (Compressed HEX)", "P2PKH Address", "P2SH-P2WPKH Address", "P2WPKH Address", "P2TR Address"])

        for seed_phrase in seeds:
            print(f"Processing seed: {seed_phrase}")
            seed_bytes = generate_seed_from_legacy_mnemonic(seed_phrase)

            for path in DEFAULT_DERIVATION_PATHS:
                derived_info = derive_keys_and_addresses(seed_bytes, path)
                if "error" in derived_info:
                    print(f"Error for seed '{seed_phrase}' and path '{path}': {derived_info['error']}", file=sys.stderr)
                else:
                    writer.writerow([
                        seed_phrase,
                        derived_info["derivation_path"],
                        derived_info["private_key_wif"],
                        derived_info["public_key_compressed_hex"],
                        derived_info["p2pkh_address_compressed"],
                        derived_info["p2pkh_address_uncompressed"],
                        derived_info["p2sh_p2wpkh_address"],
                        derived_info["p2wpkh_address"],
                        derived_info["p2tr_address"]
                    ])

def main():
    if len(sys.argv) == 1:  # No command-line arguments provided
        input_csv = "seeds.csv"  # Default input file
        output_csv = "legacy_addresses.csv"  # Default output file

        generate_addresses_from_seeds(input_csv, output_csv)
        print(f"Addresses have been saved to {output_csv}")
    else:
        parser = argparse.ArgumentParser(
            description="Recover Bitcoin keys and addresses from a legacy (potentially non-BIP39) "
                        "12-word mnemonic phrase. This script treats the mnemonic as raw UTF-8 input "
                        "for seed derivation using PBKDF2, as older Trust Wallet versions might have done.",
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument(
            "mnemonic",
            help="The 12-word mnemonic phrase (e.g., \"word1 word2 ... word12\")"
        )
        parser.add_argument(
            "-p", "--passphrase",
            default="",
            help="The passphrase associated with the mnemonic (default: empty string)"
        )
        parser.add_argument(
            "-d", "--derivation-paths",
            nargs='+',
            default=DEFAULT_DERIVATION_PATHS,
            help="One or more BIP32 derivation paths to check. (See script source for defaults)"
        )
        parser.add_argument(
            "--no-normalize",
            action="store_true",
            help="Disable NFKD normalization of the mnemonic and passphrase. "
                 "Use if you suspect your wallet did not normalize inputs. "
                 "Standard BIP39 (and Trust Wallet's underlying crypto library) uses NFKD normalization."
        )

        args = parser.parse_args()

        mnemonic_words = args.mnemonic.split()
        if len(mnemonic_words) != 12:
            print(f"Warning: Mnemonic phrase does not contain exactly 12 words (found {len(mnemonic_words)}). "
                  "Proceeding as per input, but standard phrases are 12 words.", file=sys.stderr)

        print(f"Mnemonic: \"{args.mnemonic}\"")
        print(f"Passphrase: \"{args.passphrase}\"")

        global normalize_string_config
        if args.no_normalize:
            print("Normalization: Disabled")
            normalize_string_config = lambda s: s
        else:
            print("Normalization: NFKD (Standard)")
            def nfkd_normalize(s: str) -> str:
                return _original_normalize_string('NFKD', s)
            normalize_string_config = nfkd_normalize

        seed_bytes = generate_seed_from_legacy_mnemonic(args.mnemonic, args.passphrase)
        print(f"Generated Seed (Hex): {seed_bytes.hex()}")
        print("-" * 70)

        for path in args.derivation_paths:
            print(f"Derivation Path: {path}")
            derived_info = derive_keys_and_addresses(seed_bytes, path)
            if "error" in derived_info:
                print(f"  Error: {derived_info['error']}")
            else:
                print(f"  Private Key (WIF):          {derived_info['private_key_wif']}")
                print(f"  Public Key (Compressed HEX):  {derived_info['public_key_compressed_hex']}")
                print(f"  P2PKH Address (Legacy):     {derived_info['p2pkh_address_compressed']}")
                print(f"  P2SH-P2WPKH Address (SegWit): {derived_info['p2sh_p2wpkh_address']}")
                print(f"  P2WPKH Address (Native SegWit): {derived_info['p2wpkh_address']}")
                print(f"  P2TR Address (Taproot):       {derived_info['p2tr_address']}")
            print("-" * 70)

if __name__ == '__main__':
    main()
