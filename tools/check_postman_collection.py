"""
Sends every request of a Postman collection in order (like Postman's Collection Runner) and
checks each expected status code. It also performs the collection's "save variable" steps.

    python tools/check_postman_collection.py <collection.json>

Run it only against scratch databases: it really creates, updates and deletes records.
"""
import json
import re
import sys

import requests

collection = json.load(open(sys.argv[1]))
variables = {v["key"]: v["value"] for v in collection["variable"]}


def fill(text):
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(variables[m.group(1)]), text)


def walk(items):
    for item in items:
        yield from walk(item["item"]) if "item" in item else [item]


failures = 0
for item in walk(collection["item"]):
    req = item["request"]
    script = item["event"][0]["script"]["exec"]
    expected = int(re.search(r"have\.status\((\d+)\)", "".join(script)).group(1))

    headers = {}
    if req["auth"]["type"] == "bearer":
        headers["Authorization"] = "Bearer " + fill(req["auth"]["bearer"][0]["value"])
    body = json.loads(fill(req["body"]["raw"])) if "body" in req else None
    response = requests.request(req["method"], fill(req["url"]["raw"]), json=body, headers=headers)

    if response.status_code == expected:
        for line in script:
            saved = re.search(r'set\("(\w+)", pm\.response\.json\(\)\.([\w.]+)\)', line)
            if saved:
                value = response.json()
                for key in saved.group(2).split("."):
                    value = value[key]
                variables[saved.group(1)] = value

    ok = response.status_code == expected
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {response.status_code} (expected {expected})  {item['name']}"
          + ("" if ok else f"\n      {response.text[:200]}"))

print(f"\n{failures} failures")
