from bip_utils.wif import WifEncoder, WifPubKeyModes
from bip_utils.ecc import Secp256k1PrivateKey # For creating a private key object
from bip_utils.utils.misc import DataBytes # To wrap raw bytes if needed by KeyObject

# Sample private key (32 bytes, replace with a real one if needed for specific tests, but random is fine for API testing)
# This is the private key for the BIP39 mnemonic "abandon abandon ... about", path m/44'/0'/0'/0/0
sample_priv_key_bytes = bytes.fromhex("30add027a35eeea3d95280885658151b95340076d2c87490f38a0dc79983577b")

print(f"Sample Private Key Bytes: {sample_priv_key_bytes.hex()}")

# Attempt 1: Using Secp256k1PrivateKey.FromBytes
try:
    priv_key_obj = Secp256k1PrivateKey.FromBytes(sample_priv_key_bytes)
    print("\n--- Testing with Secp256k1PrivateKey object ---")
    print(f"Private Key Object: {priv_key_obj}")

    # Iterate through WifPubKeyModes enum members
    for mode_name, mode_member in WifPubKeyModes.__members__.items():
        print(f"  Attempting with WifPubKeyModes.{mode_name} ({mode_member})")

        # Try with pub_key_mode as keyword argument
        try:
            wif_encoded_kw = WifEncoder.Encode(priv_key_obj, pub_key_mode=mode_member)
            print(f"    SUCCESS (keyword): {wif_encoded_kw}")
        except Exception as e:
            print(f"    FAILED (keyword): {type(e).__name__} - {e}")

        # Try with pub_key_mode as positional argument (if API supports it)
        # WifEncoder.Encode(priv_key_bytes_or_obj, pub_key_mode, net_ver)
        try:
            # Bitcoin mainnet WIF prefix is 0x80
            wif_encoded_pos = WifEncoder.Encode(priv_key_obj, mode_member, b'\x80')
            print(f"    SUCCESS (positional with net_ver): {wif_encoded_pos}")
        except Exception as e:
            print(f"    FAILED (positional with net_ver): {type(e).__name__} - {e}")

        try:
            # Try without net_ver if it's optional or defaulted
            wif_encoded_pos_no_net = WifEncoder.Encode(priv_key_obj, mode_member)
            print(f"    SUCCESS (positional no net_ver): {wif_encoded_pos_no_net}")
        except Exception as e:
            print(f"    FAILED (positional no net_ver): {type(e).__name__} - {e}")

except Exception as e:
    print(f"Error creating Secp256k1PrivateKey object: {type(e).__name__} - {e}")


# Attempt 2: Using raw bytes directly (if KeyObject is not the way)
# Based on previous logs, it seemed KeyObject was preferred, but let's be thorough.
print("\n--- Testing with raw private key bytes ---")
# Iterate through WifPubKeyModes enum members
for mode_name, mode_member in WifPubKeyModes.__members__.items():
    print(f"  Attempting with WifPubKeyModes.{mode_name} ({mode_member})")

    # Try with pub_key_mode as keyword argument
    try:
        wif_encoded_kw_bytes = WifEncoder.Encode(sample_priv_key_bytes, pub_key_mode=mode_member)
        print(f"    SUCCESS (keyword, raw bytes): {wif_encoded_kw_bytes}")
    except Exception as e:
        print(f"    FAILED (keyword, raw bytes): {type(e).__name__} - {e}")

    # Try with pub_key_mode as positional argument
    try:
        wif_encoded_pos_bytes = WifEncoder.Encode(sample_priv_key_bytes, mode_member, b'\x80')
        print(f"    SUCCESS (positional with net_ver, raw bytes): {wif_encoded_pos_bytes}")
    except Exception as e:
        print(f"    FAILED (positional with net_ver, raw bytes): {type(e).__name__} - {e}")

    try:
        wif_encoded_pos_no_net_bytes = WifEncoder.Encode(sample_priv_key_bytes, mode_member)
        print(f"    SUCCESS (positional no net_ver, raw bytes): {wif_encoded_pos_no_net_bytes}")
    except Exception as e:
        print(f"    FAILED (positional no net_ver, raw bytes): {type(e).__name__} - {e}")

# Try to understand the expected type for the private key argument
print("\n--- WifEncoder.Encode signature inspection (if possible) ---")
try:
    import inspect
    print(inspect.signature(WifEncoder.Encode))
except Exception as e:
    print(f"Could not inspect signature: {e}")
