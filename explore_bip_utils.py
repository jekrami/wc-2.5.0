import bip_utils
import inspect

print("--- Top-level bip_utils attributes ---")
for name in dir(bip_utils):
    if not name.startswith("_"):
        try:
            attr = getattr(bip_utils, name)
            print(f"  {name} (type: {type(attr)})")
            if inspect.ismodule(attr):
                print(f"    --- Sub-attributes of {name} module ---")
                for sub_name in dir(attr):
                    if not sub_name.startswith("_"):
                        try:
                            sub_attr = getattr(attr, sub_name)
                            print(f"      {sub_name} (type: {type(sub_attr)})")
                        except Exception:
                            pass # Some attributes might not be directly gettable or are problematic
                print(f"    --- End of {name} ---")
        except Exception:
             print(f"  {name} (could not getattr or get type)")


print("\n--- Attempting specific imports ---")
try:
    from bip_utils import BtcAddr
    print("Successfully imported: from bip_utils import BtcAddr")
except ImportError as e:
    print(f"Failed: from bip_utils import BtcAddr ({e})")

try:
    from bip_utils.addr import BtcAddr
    print("Successfully imported: from bip_utils.addr import BtcAddr")
except ImportError as e:
    print(f"Failed: from bip_utils.addr import BtcAddr ({e})")

try:
    from bip_utils.bitcoin import BtcAddr
    print("Successfully imported: from bip_utils.bitcoin import BtcAddr")
except ImportError as e:
    print(f"Failed: from bip_utils.bitcoin import BtcAddr ({e})")

try:
    from bip_utils.utils.addr import BtcAddr
    print("Successfully imported: from bip_utils.utils.addr import BtcAddr")
except ImportError as e:
    print(f"Failed: from bip_utils.utils.addr import BtcAddr ({e})")

try:
    from bip_utils.coins.bitcoin import BtcAddr
    print("Successfully imported: from bip_utils.coins.bitcoin import BtcAddr")
except ImportError as e:
    print(f"Failed: from bip_utils.coins.bitcoin import BtcAddr ({e})")

print("\n--- Checking for WIF, PrivateKey, PublicKey ---")
try:
    from bip_utils import WifEncoder, WifDecoder, PrivateKey, PublicKey
    print("Successfully imported WifEncoder, WifDecoder, PrivateKey, PublicKey from bip_utils")
except ImportError as e:
    print(f"Failed to import WIF/Key classes from bip_utils directly: {e}")
    try:
        from bip_utils.wif import WifEncoder, WifDecoder
        print("Successfully imported WifEncoder, WifDecoder from bip_utils.wif")
        from bip_utils.ecc import PrivateKey, PublicKey
        print("Successfully imported PrivateKey, PublicKey from bip_utils.ecc")
    except ImportError as e2:
        print(f"Further failures in importing WIF/Key classes from submodules: {e2}")
