import urllib.request
import json
import base64
import hmac
import hashlib
import time
import struct

def get_totp_code(secret_b32):
    # Base32 decode
    key = base64.b32decode(secret_b32.replace(' ', '').upper())
    # Current counter
    counter = int(time.time() // 30)
    msg = struct.pack(">Q", counter)
    # HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[19] & 0x0f
    truncated_hash = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff)
    code = str(truncated_hash % 1000000).zfill(6)
    return code

def test_totp_flow():
    # 1. Login as root
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
    res = json.loads(urllib.request.urlopen(req).read().decode())
    token = res['token']
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    print('[+] Logged in with initial password')

    # 2. Setup TOTP
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/user/totp/setup', headers=headers)
    setup = json.loads(urllib.request.urlopen(req).read().decode())
    secret = setup['secret']
    print('[+] TOTP setup initiated. Secret:', secret)

    # 3. Calculate current 6-digit code and enable TOTP
    code = get_totp_code(secret)
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/user/totp/enable', data=json.dumps({'secret': secret, 'code': code}).encode(), headers=headers)
    enable_res = json.loads(urllib.request.urlopen(req).read().decode())
    print('[+] TOTP enabled response:', enable_res)

    # 4. Attempt login WITHOUT TOTP (should fail / require TOTP)
    try:
        req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
        urllib.request.urlopen(req)
        print('[-] ERROR: Login succeeded without TOTP code!')
    except urllib.error.HTTPError as e:
        print(f'[+] SUCCESS: Login without TOTP code rejected: {e.code} ({e.read().decode().strip()})')

    # 5. Attempt login WITH valid TOTP code (should succeed)
    valid_code = get_totp_code(secret)
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin', 'totp_code': valid_code}).encode(), headers={'Content-Type':'application/json'})
    login_res = json.loads(urllib.request.urlopen(req).read().decode())
    print('[+] SUCCESS: Login with TOTP code succeeded! User totp_enabled:', login_res['user']['totp_enabled'])

    # 6. Disable TOTP to keep convenience for user testing unless they want it enabled
    new_headers = {'Authorization': f'Bearer {login_res["token"]}', 'Content-Type': 'application/json'}
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/user/totp/disable', data=json.dumps({'password': 'admin'}).encode(), headers=new_headers)
    disable_res = json.loads(urllib.request.urlopen(req).read().decode())
    print('[+] TOTP disable response:', disable_res)

test_totp_flow()
