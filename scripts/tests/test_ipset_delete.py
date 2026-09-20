import urllib.request
import json
import urllib.error

def test():
    # 1. Login
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
    resp = json.loads(urllib.request.urlopen(req).read().decode())
    token = resp['token']
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    # 2. Server
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/servers', headers=headers)
    servers = json.loads(urllib.request.urlopen(req).read().decode())
    server_id = servers[0]['id']

    # 3. Create a rule that binds to 'blacklist_spammers'
    # First, let's insert a firewall rule in DB using 'blacklist_spammers'
    import sqlite3
    conn = sqlite3.connect('./data/lfm.db')
    c = conn.cursor()
    c.execute("""
        INSERT OR REPLACE INTO firewall_rules (id, chain_id, server_id, table_name, chain_name, ip_version, position, protocol, target, match_set_name, raw_rule_text)
        VALUES ('rule_test_binding', 'c_input', ?, 'filter', 'INPUT', 'v4', 99, 'all', 'DROP', 'blacklist_spammers', '-m set --match-set blacklist_spammers src -j DROP')
    """, (server_id,))
    conn.commit()
    conn.close()

    # 4. Check usage of 'blacklist_spammers'
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/blacklist_spammers/usage', headers=headers)
    usage = json.loads(urllib.request.urlopen(req).read().decode())
    print('[+] Usage check for blacklist_spammers:', usage)
    assert usage['in_use'] == True
    print(f'[+] Verified blacklist_spammers is IN USE by {len(usage["bound_rules"])} rule(s):', usage['bound_rules'])

    # 5. Attempt DELETE on bound IPSet (MUST FAIL with HTTP 409)
    try:
        req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/blacklist_spammers', headers=headers, method='DELETE')
        urllib.request.urlopen(req)
        print('[-] ERROR: Bound IPSet was deleted when it should have been blocked!')
        assert False
    except urllib.error.HTTPError as e:
        err_body = json.loads(e.read().decode())
        print(f'[+] SUCCESS: Delete correctly blocked with HTTP {e.code}:', err_body['error'])
        assert e.code == 409

    # 6. Create an unlinked IPSet
    unlinked_name = 'unlinked_test_set'
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets', data=json.dumps({'name': unlinked_name, 'type_name': 'hash:ip', 'family': 'inet'}).encode(), headers=headers)
    urllib.request.urlopen(req)
    print(f'[+] Created unlinked IPSet {unlinked_name}')

    # 7. Check usage of unlinked IPSet
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/{unlinked_name}/usage', headers=headers)
    unlinked_usage = json.loads(urllib.request.urlopen(req).read().decode())
    print(f'[+] Usage check for {unlinked_name}:', unlinked_usage)
    assert unlinked_usage['in_use'] == False

    # 8. Attempt DELETE on unlinked IPSet (MUST SUCCEED)
    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{server_id}/ipsets/{unlinked_name}', headers=headers, method='DELETE')
    del_res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f'[+] SUCCESS: Unlinked IPSet deleted:', del_res)
    assert del_res['success'] == True

    # 9. Clean up test binding rule
    conn = sqlite3.connect('./data/lfm.db')
    c = conn.cursor()
    c.execute("DELETE FROM firewall_rules WHERE id = 'rule_test_binding'")
    conn.commit()
    conn.close()

    print('[+] ALL TESTS PASSED: Rule binding protection successfully verified!')

test()
