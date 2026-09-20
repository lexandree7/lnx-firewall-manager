import urllib.request
import json

def test():
    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/auth/login', data=json.dumps({'username':'root','password':'admin'}).encode(), headers={'Content-Type':'application/json'})
    token = json.loads(urllib.request.urlopen(req).read().decode())['token']

    req = urllib.request.Request('http://127.0.0.1:8443/api/v1/servers', headers={'Authorization': f'Bearer {token}'})
    servers = json.loads(urllib.request.urlopen(req).read().decode())
    srv_id = servers[0]['id']

    req = urllib.request.Request(f'http://127.0.0.1:8443/api/v1/servers/{srv_id}/rules', headers={'Authorization': f'Bearer {token}'})
    rules_resp = json.loads(urllib.request.urlopen(req).read().decode())
    print('Server:', rules_resp['hostname'])
    print('Raw rules length:', len(rules_resp.get('raw_rules_v4', '')))
    print('Raw rules preview:\n', rules_resp.get('raw_rules_v4', '')[:300])
    if rules_resp.get('parsed_v4') and rules_resp['parsed_v4'].get('Tables'):
        for tbl, data in rules_resp['parsed_v4']['Tables'].items():
            print(f'Table *{tbl}: {len(data.get("Rules", []))} rules')
            if data.get('Rules'):
                print(f'Sample rule in *{tbl}:', json.dumps(data['Rules'][0]))

test()

