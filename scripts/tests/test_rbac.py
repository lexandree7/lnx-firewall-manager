import sqlite3
import hashlib
import secrets
import urllib.request
import json
import urllib.error

# 1. Create a viewer user directly in SQLite
conn = sqlite3.connect('./data/lfm.db')
c = conn.cursor()
c.execute("""
    INSERT OR REPLACE INTO users (id, username, password_hash, display_name, auth_type, totp_enabled, role, created_at, updated_at)
    VALUES ('usr_viewer_test', 'viewer_user', 'mock', 'Viewer Test', 'local', 0, 'viewer', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
""")

# 2. Create an active session for viewer
token = secrets.token_hex(32)
token_hash = hashlib.sha256(token.encode()).hexdigest()
c.execute("""
    INSERT INTO user_sessions (id, user_id, session_token_hash, ip_address, user_agent, expires_at, created_at)
    VALUES ('sess_viewer', 'usr_viewer_test', ?, '127.0.0.1', 'PythonTest', datetime('now', '+1 hour'), CURRENT_TIMESTAMP)
""", (token_hash,))
conn.commit()
conn.close()

headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

# 3. /auth/me for viewer
req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/me', headers=headers)
me = json.loads(urllib.request.urlopen(req).read().decode())
print('[+] Viewer /auth/me:', me['username'], '| Role:', me['role'])

# 4. Viewer tries to access admin-only endpoint: PUT /settings/oidc
try:
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/settings/oidc', data=b'{}', headers=headers, method='PUT')
    urllib.request.urlopen(req)
    print('[-] ERROR: Viewer should not be allowed to PUT /settings/oidc!')
except urllib.error.HTTPError as e:
    print(f'[+] RBAC SUCCESS: Viewer blocked on PUT /settings/oidc with HTTP {e.code} ({e.read().decode().strip()})')

# 5. Viewer tries to apply batch rules: POST /rules/batch/apply
try:
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/rules/batch/apply', data=b'{}', headers=headers, method='POST')
    urllib.request.urlopen(req)
    print('[-] ERROR: Viewer should not be allowed to POST /rules/batch/apply!')
except urllib.error.HTTPError as e:
    print(f'[+] RBAC SUCCESS: Viewer blocked on POST /rules/batch/apply with HTTP {e.code} ({e.read().decode().strip()})')

# 6. Viewer CAN read servers: GET /servers
req = urllib.request.Request('http://127.0.0.1:8443/api/v1/servers', headers=headers)
servers = json.loads(urllib.request.urlopen(req).read().decode())
print(f'[+] RBAC SUCCESS: Viewer successfully listed servers (count: {len(servers)})')
