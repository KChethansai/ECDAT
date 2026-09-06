# Intentionally vulnerable sample: exercises the REAL SourceScanner.
# Every hit below must appear in POST /scans {"target": "sample"} with is_mock=false.
import hashlib

PASSWORD_HASH = hashlib.md5(b"demo-input").hexdigest()      # MD5
TOKEN = hashlib.sha1(b"abc").hexdigest()                    # SHA-1
LEGACY_CIPHER = "DES/CBC/PKCS5Padding"                      # DES + CBC mode
TLS_CTX = {"protocol": "TLSv1.0", "ciphers": ["DES-CBC3-SHA"]}  # TLS1.0 + 3DES
RSA_KEY_BITS = 1024                                         # RSA + short key size
MODERN_CIPHER = "AES-256-GCM"                               # safe contrast
PUBKEY_PEM = "server.crt"  # references server.pem/server.key on disk
# openssl rsautl -encrypt -inkey k.pem -in data.bin          # OpenSSL CLI ref
