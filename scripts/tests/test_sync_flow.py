import urllib.request
import json
import subprocess
import time

def test_sync():
    base_url = "http://127.0.0.1:8443/api/v1"

    # 1. Login
    login_req = urllib.request.Request(
        f"{base_url}/auth/login",
        data=json.dumps({"username": "root", "password": "admin"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    token = json.loads(urllib.request.urlopen(login_req).read().decode())["token"]
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # 2. Get server
    srv_req = urllib.request.Request(f"{base_url}/servers", headers=headers)
    servers = json.loads(urllib.request.urlopen(srv_req).read().decode())
    srv = servers[0]
    srv_id = srv["id"]
    print(f"[1] Server target: {srv['hostname']} (ID: {srv_id}, status: {srv['status']})")

    # 3. Read initial rules
    rules_req = urllib.request.Request(f"{base_url}/servers/{srv_id}/rules", headers=headers)
    initial_rules_resp = json.loads(urllib.request.urlopen(rules_req).read().decode())
    initial_v4 = initial_rules_resp.get("raw_rules_v4", "")
    print(f"[2] Initial raw rules size: {len(initial_v4)} bytes")

    # 4. Craft new ruleset with our new test rule appended to filter INPUT
    test_comment = "LFM_AUTO_SYNC_TEST_9443"
    test_rule_line = f"-A INPUT -p tcp -m multiport --dports 9443 -m comment --comment \"{test_comment}\" -j ACCEPT"

    lines = initial_v4.splitlines()
    new_lines = []
    in_filter = False
    inserted = False
    for line in lines:
        if line.strip() == "*filter":
            in_filter = True
        elif in_filter and line.strip() == "COMMIT" and not inserted:
            new_lines.append(test_rule_line)
            inserted = True
            in_filter = False
        new_lines.append(line)

    if not inserted:
        new_rules_v4 = initial_v4 + f"\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n{test_rule_line}\nCOMMIT\n"
    else:
        new_rules_v4 = "\n".join(new_lines) + "\n"

    print("[3] Applying batch rules with safety timeout 30s...")
    apply_payload = {
        "target_servers": [srv_id],
        "new_rules_v4": new_rules_v4,
        "rollback_timeout_seconds": 30
    }
    apply_req = urllib.request.Request(
        f"{base_url}/rules/batch/apply",
        data=json.dumps(apply_payload).encode(),
        headers=headers
    )
    apply_resp = json.loads(urllib.request.urlopen(apply_req).read().decode())
    change_id = apply_resp["change_id"]
    print(f"[4] Rules applied in test mode! Change ID: {change_id}")

    # Give agent 0.5s to apply
    time.sleep(0.5)

    print("[5] Confirming commit permanently...")
    confirm_payload = {
        "target_servers": [srv_id],
        "change_id": change_id
    }
    confirm_req = urllib.request.Request(
        f"{base_url}/rules/batch/confirm",
        data=json.dumps(confirm_payload).encode(),
        headers=headers
    )
    confirm_resp = json.loads(urllib.request.urlopen(confirm_req).read().decode())
    print(f"[6] Confirm response: {confirm_resp}")

    # Give hub and agent 0.5s to update state
    time.sleep(0.5)

    # 7. Check server rules endpoint again
    print("[7] Fetching updated rules from server API...")
    rules_req2 = urllib.request.Request(f"{base_url}/servers/{srv_id}/rules", headers=headers)
    updated_rules_resp = json.loads(urllib.request.urlopen(rules_req2).read().decode())
    updated_v4 = updated_rules_resp.get("raw_rules_v4", "")
    
    assert test_comment in updated_v4, f"ERROR: {test_comment} not found in raw_rules_v4!"
    print(f"[SUCCESS] Test rule found in raw_rules_v4!")

    # Check parsed_v4
    filter_rules = updated_rules_resp.get("parsed_v4", {}).get("Tables", {}).get("filter", {}).get("Rules", [])
    found_parsed = any(r.get("Comment") == test_comment or test_comment in r.get("RawText", "") for r in filter_rules)
    assert found_parsed, f"ERROR: {test_comment} not found in parsed_v4!"
    print(f"[SUCCESS] Test rule found in parsed_v4 rules list! Total filter rules: {len(filter_rules)}")

    # 8. Verify directly in WSL host kernel iptables
    kernel_check = subprocess.check_output(["iptables", "-S", "INPUT"]).decode()
    assert test_comment in kernel_check, f"ERROR: {test_comment} not found in actual Linux kernel!"
    print(f"[SUCCESS] Test rule confirmed live inside Linux kernel iptables -S:")
    for line in kernel_check.splitlines():
        if test_comment in line:
            print("   ->", line)

    print("\nALL RULE SYNC VERIFICATIONS PASSED 100%!")

if __name__ == "__main__":
    test_sync()
