"""Fixture: real Python ssl-module API usage for the TLS detection regression test.

Every versioned constant below must produce exactly one protocol finding;
the two unversioned lines at the bottom must produce none.
"""

import ssl

ctx_legacy = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
ctx_11 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
ctx_12 = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx_old_ssl = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
ctx_older_ssl = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
ctx_legacy.minimum_version = ssl.TLSVersion.TLSv1
ctx_floor = ssl.SSLContext()
ctx_floor.minimum_version = ssl.TLSVersion.TLSv1_2
ctx_floor.maximum_version = ssl.TLSVersion.TLSv1_3
safe = ssl.create_default_context()
