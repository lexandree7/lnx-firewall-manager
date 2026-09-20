import urllib.request
import json

def test():
    # 1. Login
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
    resp = json.loads(urllib.request.urlopen(req).read().decode())
    token = resp['token']
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    # 2. Get Servers
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/servers', headers=headers)
    servers = json.loads(urllib.request.urlopen(req).read().decode())
    server_id = servers[0]['id'] if servers else 'global'
    print('[+] Target Server ID:', server_id)

    # 3. List IPSets
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets', headers=headers)
    ipsets = json.loads(urllib.request.urlopen(req).read().decode())
    print('[+] IPSets count:', len(ipsets))

    # 4. Get IPSet Entries
    set_name = ipsets[0]['name'] if ipsets else 'blacklist_spammers'
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/{set_name}/entries', headers=headers)
    entries = json.loads(urllib.request.urlopen(req).read().decode())
    print(f'[+] Initial Entries for {set_name}:', entries)

    # 5. Save/Update IPSet Entries as a list
    test_list = ['192.168.10.1', '192.168.10.2', '10.50.0.0/24', '172.20.1.100']
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/{set_name}/entries', data=json.dumps({'entries': test_list}).encode(), headers=headers, method='POST')
    save_resp = json.loads(urllib.request.urlopen(req).read().decode())
    print(f'[+] Save entries response:', save_resp)

    # 6. Verify GET returns updated list
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/{set_name}/entries', headers=headers)
    updated_entries = json.loads(urllib.request.urlopen(req).read().decode())
    print(f'[+] Verification GET entries for {set_name}:', updated_entries)
    assert updated_entries == test_list, f"Expected {test_list}, got {updated_entries}"
    print('[+] SUCCESS: IPSet list editing and persistence verified 100%!')

test()
