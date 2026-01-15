from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import json

with open("compromised_data.json", "r", encoding="utf-8") as f:
    data = json.load(f)

for i, row in enumerate(data):
    try:
        print(f"\n[ MESSAGE {i+1}/{len(data)} ]")
        wireshark_data = row['wireshark_data']
        message_length = int(wireshark_data[:8],16)
        key = bytes.fromhex(row['aes_key']) 
        nonce = bytes.fromhex(wireshark_data[8:32])
        ciphertext = bytes.fromhex(wireshark_data[32:])
        aesgcm = AESGCM(key)
        print(aesgcm.decrypt(nonce, ciphertext, None))
        print(f" - Message length: {message_length}")

    except InvalidTag:
        print(f"[ERROR] Invalid authentication tag (signature mismatch)")

    except ValueError as e:
        print(f"[ERROR]  Hex parsing error: {e}")

    except KeyError as e:
        print(f"[ERROR]  Missing field {e}")




#XXXXXXXX------------------------AAAAAAAAAAAAAAAAAAA
#LENGTH           NONCE                 CYPHERTEXT
