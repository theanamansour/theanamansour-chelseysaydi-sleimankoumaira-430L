"""
Builds the Postman collection for Sleiman Koumaira's services (2, 4 and 8).

    python3 tools/make_postman_collection.py postman/Sleiman_Koumaira_Services.postman_collection.json

The committed collection has empty credentials. A local copy with test credentials filled in is
kept in postman/local/ (ignored by Git).
"""
import json
import sys

OWNER = "Sleiman Koumaira"
PREFIX = "/sleiman-koumaira"  # every route includes the student's full name

AUTH = "Header `Authorization: Bearer <token>` (token from Service 1's login, checked by Service 1's verify endpoint)"
AUTH_ERRORS = "401 missing token or token rejected by Service 1 | 403 role not allowed | 503 Service 1 unavailable"

THREAT_TYPES = "IP Address | Domain | File Hash | Malware Signature | Other Indicators"
SEVERITIES = "Low | Medium | High | Critical"
ASSET_TYPES = "Server | Workstation | Database | Application | Network Device | Cloud Resource"
STATUSES = "Active | Inactive | Under Maintenance"
NOTIFICATION_TYPES = "Incident Assignment | Security Alert | System Notification | Threat Alert | Vulnerability Alert"

API_DOCS = {
    # ---------------- Service 4 ----------------
    "threat_add": dict(
        name="Add Threat Indicator", method="POST", endpoint="/sleiman-koumaira/threats",
        purpose="Adds a threat indicator. High and Critical threats automatically create a Threat Alert notification (Service 8) for every active Security Administrator and Security Analyst.",
        roles="Security Administrator", params=f"None in the URL. {AUTH}.",
        body=f"JSON, all required:\n- `threat_type`: {THREAT_TYPES}\n- `threat_value`: must match the type (IPv4/IPv6, domain, or MD5/SHA-1/SHA-256 hex hash)\n- `description`: text, max 1000\n- `severity`: {SEVERITIES}\n- `source`: text, max 100",
        response='201 Created: `{"status": "success", "message": "Threat indicator added successfully[; threat alert sent to N user(s)]", "data": {threat}}`',
        errors=f"400 validation failed | 409 same type and value already stored | {AUTH_ERRORS}",
    ),
    "threat_get_all": dict(
        name="Retrieve All Threat Indicators", method="GET", endpoint="/sleiman-koumaira/threats",
        purpose="Returns every threat with its information, severity, source and date added.",
        roles="Security Administrator, Security Analyst, Auditor", params=f"None. {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "count": N, "data": [threat, ...]}`', errors=AUTH_ERRORS,
    ),
    "threat_get_one": dict(
        name="Retrieve Specific Threat Indicator", method="GET", endpoint="/sleiman-koumaira/threats/{id}",
        purpose="Returns the complete information of one threat.",
        roles="Security Administrator, Security Analyst, Auditor", params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "data": {threat}}`', errors=f"404 no threat with this ID | {AUTH_ERRORS}",
    ),
    "threat_search": dict(
        name="Search Threat Indicators", method="GET", endpoint="/sleiman-koumaira/threats/search",
        purpose="Searches threats; all given criteria must match (AND).",
        roles="Security Administrator, Security Analyst, Auditor",
        params=f"At least one query parameter:\n- `threat_type` (exact): {THREAT_TYPES}\n- `severity` (exact): {SEVERITIES}\n- `threat_value` (contains, ignores case)\n- `source` (contains, ignores case)\n{AUTH}.",
        body="None.", response='200 OK: `{"status": "success", "count": N, "data": [matching threats]}`',
        errors=f"400 no criteria, unknown parameter, invalid type/severity | {AUTH_ERRORS}",
    ),
    "threat_update": dict(
        name="Update Threat Information", method="PUT", endpoint="/sleiman-koumaira/threats/{id}",
        purpose="Updates the description, severity and/or source of a threat.",
        roles="Security Administrator", params=f"`id` (path, integer). {AUTH}.",
        body=f"JSON with one or more of `description`, `severity` ({SEVERITIES}), `source`. Type and value cannot change.",
        response='200 OK: `{"status": "success", "message": "Threat information updated successfully", "data": {threat}}`',
        errors=f"400 validation failed or field not updatable | 404 no threat with this ID | {AUTH_ERRORS}",
    ),
    "threat_delete": dict(
        name="Delete Threat Indicator", method="DELETE", endpoint="/sleiman-koumaira/threats/{id}",
        purpose="Removes a threat record.", roles="Security Administrator",
        params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "message": "Threat indicator {id} deleted successfully"}`',
        errors=f"404 no threat with this ID | {AUTH_ERRORS}",
    ),
    # ---------------- Service 2 ----------------
    "asset_add": dict(
        name="Add New Asset", method="POST", endpoint="/sleiman-koumaira/assets",
        purpose="Adds an organizational asset. The owner must be an existing user of Service 1.",
        roles="Security Administrator", params=f"None in the URL. {AUTH}.",
        body=f"JSON.\nRequired:\n- `asset_name`: text, max 100\n- `asset_type`: {ASSET_TYPES}\n- `ip_address`: IPv4 or IPv6\n- `department`: text, max 100\n- `owner_id`: ID of an existing user in Service 1\n- `criticality`: {SEVERITIES}\nOptional:\n- `operating_system`, `location`: text, max 100\n- `status`: {STATUSES} (default Active)",
        response='201 Created: `{"status": "success", "message": "Asset added successfully", "data": {asset}}`',
        errors=f"400 validation failed or owner does not exist | {AUTH_ERRORS}",
    ),
    "asset_get_all": dict(
        name="Retrieve All Assets", method="GET", endpoint="/sleiman-koumaira/assets",
        purpose="Returns every asset with its details, criticality level and current status.",
        roles="Security Administrator, Auditor (not Security Analyst)", params=f"None. {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "count": N, "data": [asset, ...]}`', errors=AUTH_ERRORS,
    ),
    "asset_get_one": dict(
        name="Retrieve Specific Asset", method="GET", endpoint="/sleiman-koumaira/assets/{id}",
        purpose="Returns the complete information of one asset.",
        roles="Security Administrator, Security Analyst, Auditor", params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "data": {asset}}`', errors=f"404 no asset with this ID | {AUTH_ERRORS}",
    ),
    "asset_search": dict(
        name="Search Assets", method="GET", endpoint="/sleiman-koumaira/assets/search",
        purpose="Searches assets; all given criteria must match (AND).",
        roles="Security Administrator, Security Analyst, Auditor",
        params=f"At least one query parameter:\n- `asset_type` (exact): {ASSET_TYPES}\n- `criticality` (exact): {SEVERITIES}\n- `asset_name`, `department` (contains, ignores case)\n- `ip_address` (contains, e.g. a subnet like 192.0.2.)\n{AUTH}.",
        body="None.", response='200 OK: `{"status": "success", "count": N, "data": [matching assets]}`',
        errors=f"400 no criteria, unknown parameter, invalid type/criticality | {AUTH_ERRORS}",
    ),
    "asset_update": dict(
        name="Update Asset Information", method="PUT", endpoint="/sleiman-koumaira/assets/{id}",
        purpose="Updates the name, owner, department, criticality and/or status of an asset.",
        roles="Security Administrator", params=f"`id` (path, integer). {AUTH}.",
        body=f"JSON with one or more of `asset_name`, `owner_id` (existing user), `department`, `criticality` ({SEVERITIES}), `status` ({STATUSES}).",
        response='200 OK: `{"status": "success", "message": "Asset information updated successfully", "data": {asset}}`',
        errors=f"400 validation failed, field not updatable or owner does not exist | 404 no asset with this ID | {AUTH_ERRORS}",
    ),
    "asset_delete": dict(
        name="Delete Asset", method="DELETE", endpoint="/sleiman-koumaira/assets/{id}",
        purpose="Removes an asset.", roles="Security Administrator", params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "message": "Asset {id} deleted successfully"}`',
        errors=f"404 no asset with this ID | {AUTH_ERRORS}",
    ),
    # ---------------- Service 8 ----------------
    "note_create": dict(
        name="Create Notification", method="POST", endpoint="/sleiman-koumaira/notifications",
        purpose="Creates a notification for a user. Used by Security Administrators, and by other services with the internal X-Service-Key header (e.g. Threat Alerts from Service 4).",
        roles="Security Administrator (or another service with X-Service-Key)", params=f"None in the URL. {AUTH}.",
        body=f"JSON, all required:\n- `user_id`: ID of an existing user in Service 1\n- `title`: text, max 150\n- `message`: text, max 1000\n- `notification_type`: {NOTIFICATION_TYPES}\n- `severity`: {SEVERITIES}\nThe status always starts as Unread.",
        response='201 Created: `{"status": "success", "message": "Notification created successfully", "data": {notification}}`',
        errors=f"400 validation failed or user does not exist | {AUTH_ERRORS}",
    ),
    "note_user": dict(
        name="Retrieve User Notifications", method="GET", endpoint="/sleiman-koumaira/notifications/user/{user_id}",
        purpose="Returns all notifications of one user, newest first (an empty list if there are none).",
        roles="Security Administrator and Auditor: any user. Security Analyst and Regular Employee: only their own.",
        params=f"`user_id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "count": N, "data": [notification, ...]}`',
        errors=f"403 someone else's notifications | {AUTH_ERRORS}",
    ),
    "note_get_one": dict(
        name="Retrieve Specific Notification", method="GET", endpoint="/sleiman-koumaira/notifications/{id}",
        purpose="Returns one notification.",
        roles="Security Administrator and Auditor: any. Security Analyst and Regular Employee: only their own.",
        params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "data": {notification}}`',
        errors=f"404 no notification with this ID | 403 someone else's notification | {AUTH_ERRORS}",
    ),
    "note_read": dict(
        name="Mark Notification as Read", method="PUT", endpoint="/sleiman-koumaira/notifications/{id}/read",
        purpose="Sets the status to Read and records the read date (UTC). Marking it again keeps the first read date.",
        roles="Security Administrator (any), Security Analyst and Regular Employee (own only). Not the Auditor (read-only).",
        params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "message": "Notification marked as read", "data": {notification with read_at}}`',
        errors=f"404 no notification with this ID | 403 someone else's notification or Auditor | {AUTH_ERRORS}",
    ),
    "note_search": dict(
        name="Search Notifications", method="GET", endpoint="/sleiman-koumaira/notifications/search",
        purpose="Searches notifications; all criteria must match exactly (AND). Analysts only get their own notifications.",
        roles="Security Administrator, Auditor (any user); Security Analyst (own only)",
        params=f"At least one query parameter:\n- `user_id`\n- `notification_type`: {NOTIFICATION_TYPES}\n- `severity`: {SEVERITIES}\n- `status`: Unread | Read\n{AUTH}.",
        body="None.", response='200 OK: `{"status": "success", "count": N, "data": [matching notifications]}`',
        errors=f"400 no criteria, unknown parameter or invalid value | 403 analyst asking for another user | {AUTH_ERRORS}",
    ),
    "note_delete": dict(
        name="Delete Notification", method="DELETE", endpoint="/sleiman-koumaira/notifications/{id}",
        purpose="Removes a notification.", roles="Security Administrator",
        params=f"`id` (path, integer). {AUTH}.", body="None.",
        response='200 OK: `{"status": "success", "message": "Notification {id} deleted successfully"}`',
        errors=f"404 no notification with this ID | {AUTH_ERRORS}",
    ),
}


def describe(api_key, scenario, expected):
    if api_key is None:
        return f"**Setup request (Service 1, Theana Mansour).** {scenario}\n\n**Expected status:** {expected}"
    d = API_DOCS[api_key]
    return (
        f"**Owner:** {OWNER}\n\n**API:** {d['name']}\n\n**Purpose:** {d['purpose']}\n\n"
        f"**Method:** {d['method']}  \n**Endpoint:** `{d['endpoint']}`  \n**Allowed roles:** {d['roles']}\n\n"
        f"**Required parameters:** {d['params']}\n\n**Request body:** {d['body']}\n\n"
        f"**Success response:** {d['response']}\n\n**Possible error responses:** {d['errors']}\n\n"
        f"---\n**This request:** {scenario}  \n**Expected status:** {expected}"
    )


def raw_json(body):
    """JSON text where "@@name@@" placeholders become unquoted Postman variables {{name}} (numbers)."""
    text = json.dumps(body, indent=2)
    for key in ("admin_user_id", "analyst_user_id", "auditor_user_id", "employee_user_id"):
        text = text.replace(f'"@@{key}@@"', "{{" + key + "}}")
    return text


def request(name, api_key, method, base_var, path, token_var, expected, scenario,
            body=None, query=None, saves=None, prefix=PREFIX, owner=OWNER):
    path = prefix + path
    url = {"raw": "{{" + base_var + "}}" + path, "host": ["{{" + base_var + "}}"], "path": path.strip("/").split("/")}
    if query:
        url["raw"] += "?" + "&".join(f"{k}={v}" for k, v in query)
        url["query"] = [{"key": k, "value": v} for k, v in query]
    req = {"method": method, "url": url, "header": [], "description": describe(api_key, scenario, expected)}
    req["auth"] = ({"type": "bearer", "bearer": [{"key": "token", "value": "{{" + token_var + "}}", "type": "string"}]}
                   if token_var else {"type": "noauth"})
    if body is not None:
        req["header"].append({"key": "Content-Type", "value": "application/json"})
        req["body"] = {"mode": "raw", "raw": raw_json(body), "options": {"raw": {"language": "json"}}}
    test = [f'pm.test("Status code is {expected}", function () {{', f"    pm.response.to.have.status({expected});", "});"]
    if saves:
        test.append(f"if (pm.response.code === {expected}) {{")
        for variable, json_path in saves.items():
            test.append(f'    pm.collectionVariables.set("{variable}", pm.response.json().{json_path});')
        test.append("}")
    return {"name": f"{owner} - {name}", "request": req,
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": test}}]}


# =============================== 0. Setup: log in ===============================

def login(role_label, prefix_var):
    return request(
        f"Log in as {role_label}", None, "POST", "users_url", "/users/login", None, 200,
        f"Logs in with Service 1 and saves the token into `{prefix_var}_token` and the user ID into `{prefix_var}_user_id`.",
        body={"login": "{{" + prefix_var + "_login}}", "password": "{{" + prefix_var + "_password}}"},
        saves={f"{prefix_var}_token": "token", f"{prefix_var}_user_id": "user_id"},
        prefix="/theana-mansour", owner="Setup",
    )


setup = [
    login("Security Administrator", "admin"),
    login("Security Analyst", "analyst"),
    login("Auditor", "auditor"),
    login("Regular Employee", "employee"),
]

# =============================== Service 4 ===============================

IP = {"threat_type": "IP Address", "threat_value": "203.0.113.45", "description": "Command-and-control server of a botnet", "severity": "High", "source": "AbuseIPDB"}
DOMAIN = {"threat_type": "Domain", "threat_value": "secure-bank-login.example", "description": "Phishing site copying a bank login page", "severity": "Critical", "source": "PhishTank"}
HASH = {"threat_type": "File Hash", "threat_value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "description": "EICAR antivirus test file (SHA-256)", "severity": "Low", "source": "VirusTotal"}
SIG = {"threat_type": "Malware Signature", "threat_value": "Trojan.GenericKD.4614", "description": "Generic trojan detection signature", "severity": "Medium", "source": "Internal SOC"}
OTHER = {"threat_type": "Other Indicators", "threat_value": "powershell -EncodedCommand", "description": "Obfuscated PowerShell command often used by attackers", "severity": "Medium", "source": "Internal SOC"}


def threat(name, api_key, method, path, token, expected, scenario, **kwargs):
    return request(name, api_key, method, "threat_url", path, token, expected, scenario, **kwargs)


threat_main = [
    threat("Add Threat Indicator (IP Address)", "threat_add", "POST", "/threats", "admin_token", 201, "Adds a High malicious IP; a threat alert is sent to the active administrators and analysts. Saves threat_id.", body=IP, saves={"threat_id": "data.threat_id"}),
    threat("Add Threat Indicator (Domain)", "threat_add", "POST", "/threats", "admin_token", 201, "Adds a Critical phishing domain (stored in lowercase); threat alerts are sent.", body=DOMAIN),
    threat("Add Threat Indicator (File Hash)", "threat_add", "POST", "/threats", "admin_token", 201, "Adds a Low SHA-256 hash; no alert for Low.", body=HASH),
    threat("Add Threat Indicator (Malware Signature)", "threat_add", "POST", "/threats", "admin_token", 201, "Adds a Medium malware signature.", body=SIG),
    threat("Add Threat Indicator (Other Indicators)", "threat_add", "POST", "/threats", "admin_token", 201, "Adds an Other Indicators entry. Saves delete_threat_id.", body=OTHER, saves={"delete_threat_id": "data.threat_id"}),
    threat("Retrieve All Threat Indicators", "threat_get_all", "GET", "/threats", "analyst_token", 200, "Security Analyst lists every threat."),
    threat("Retrieve Specific Threat Indicator", "threat_get_one", "GET", "/threats/{{threat_id}}", "auditor_token", 200, "Auditor reads one threat. Also the 'before' and 'after' evidence for the update."),
    threat("Search Threat Indicators (by type)", "threat_search", "GET", "/threats/search", "analyst_token", 200, "Exact match on type.", query=[("threat_type", "Domain")]),
    threat("Search Threat Indicators (by severity)", "threat_search", "GET", "/threats/search", "analyst_token", 200, "Exact match on severity.", query=[("severity", "Medium")]),
    threat("Search Threat Indicators (by source, partial)", "threat_search", "GET", "/threats/search", "admin_token", 200, "Source contains 'internal', ignoring case.", query=[("source", "internal")]),
    threat("Search Threat Indicators (by value, partial)", "threat_search", "GET", "/threats/search", "admin_token", 200, "Value contains 203.0.113.", query=[("threat_value", "203.0.113")]),
    threat("Search Threat Indicators (multiple criteria)", "threat_search", "GET", "/threats/search", "auditor_token", 200, "Type, severity and source must all match.", query=[("threat_type", "Other Indicators"), ("severity", "Medium"), ("source", "Internal SOC")]),
    threat("Update Threat Information", "threat_update", "PUT", "/threats/{{threat_id}}", "admin_token", 200, "Severity High -> Critical, new description and source.", body={"severity": "Critical", "description": "Confirmed command-and-control server", "source": "CERT"}),
    threat("Delete Threat Indicator", "threat_delete", "DELETE", "/threats/{{delete_threat_id}}", "admin_token", 200, "Deletes the Other Indicators entry."),
]

threat_errors = [
    threat("Reject Duplicate Threat", "threat_add", "POST", "/threats", "admin_token", 409, "Same type and value as an existing threat.", body=DOMAIN),
    threat("Reject Duplicate Written in Capitals", "threat_add", "POST", "/threats", "admin_token", 409, "Domains are normalized to lowercase.", body={**DOMAIN, "threat_value": "SECURE-BANK-LOGIN.example"}),
    threat("Reject Invalid IP Address", "threat_add", "POST", "/threats", "admin_token", 400, "999 is not a valid IPv4 number.", body={**IP, "threat_value": "999.10.10.10"}),
    threat("Reject Invalid Domain", "threat_add", "POST", "/threats", "admin_token", 400, "Spaces are not allowed in a domain.", body={**DOMAIN, "threat_value": "not a domain"}),
    threat("Reject Invalid File Hash", "threat_add", "POST", "/threats", "admin_token", 400, "Not hexadecimal and wrong length.", body={**HASH, "threat_value": "xyz123"}),
    threat("Reject Invalid Threat Type", "threat_add", "POST", "/threats", "admin_token", 400, "'URL' is not a supported type.", body={**IP, "threat_type": "URL", "threat_value": "198.51.100.10"}),
    threat("Reject Invalid Severity", "threat_add", "POST", "/threats", "admin_token", 400, "Severity must be Low, Medium, High or Critical.", body={**IP, "threat_value": "198.51.100.7", "severity": "Extreme"}),
    threat("Reject Missing Required Fields", "threat_add", "POST", "/threats", "admin_token", 400, "Lists every missing field.", body={"threat_type": "IP Address"}),
    threat("Reject Empty Request Body", "threat_add", "POST", "/threats", "admin_token", 400, "An empty JSON object is rejected.", body={}),
    threat("Reject Request Without Token", "threat_get_all", "GET", "/threats", None, 401, "No Authorization header."),
    threat("Reject Invalid Token", "threat_get_all", "GET", "/threats", "invalid_token", 401, "Service 1 does not recognise the token."),
    threat("Reject Analyst Adding Threat", "threat_add", "POST", "/threats", "analyst_token", 403, "Compare with 'Add Threat Indicator' (same API, administrator, 201).", body={**IP, "threat_value": "198.51.100.8"}),
    threat("Reject Regular Employee Viewing Threats", "threat_get_all", "GET", "/threats", "employee_token", 403, "Compare with 'Retrieve All Threat Indicators' (same API, analyst, 200)."),
    threat("Reject Auditor Updating Threat", "threat_update", "PUT", "/threats/{{threat_id}}", "auditor_token", 403, "Auditors are read-only.", body={"severity": "Low"}),
    threat("Reject Analyst Deleting Threat", "threat_delete", "DELETE", "/threats/{{threat_id}}", "analyst_token", 403, "Only the administrator may delete. Then send 'Retrieve Specific Threat Indicator': it still exists."),
    threat("Retrieve Non-existing Threat", "threat_get_one", "GET", "/threats/99999", "admin_token", 404, "No threat with this ID."),
    threat("Reject Changing Threat Value", "threat_update", "PUT", "/threats/{{threat_id}}", "admin_token", 400, "Type and value cannot be updated.", body={"threat_value": "198.51.100.9"}),
    threat("Reject Invalid Severity in Update", "threat_update", "PUT", "/threats/{{threat_id}}", "admin_token", 400, "Update validation.", body={"severity": "Extreme"}),
    threat("Reject Search Without Criteria", "threat_search", "GET", "/threats/search", "admin_token", 400, "At least one parameter is required."),
]

# =============================== Service 2 ===============================

SERVER = {"asset_name": "Main Web Server", "asset_type": "Server", "ip_address": "192.0.2.10", "operating_system": "Ubuntu 22.04", "owner_id": "@@admin_user_id@@", "department": "IT", "location": "Beirut Data Center", "criticality": "Critical"}
LAPTOP = {"asset_name": "HR Laptop 07", "asset_type": "Workstation", "ip_address": "192.0.2.57", "operating_system": "Windows 11", "owner_id": "@@employee_user_id@@", "department": "Human Resources", "location": "Floor 2", "criticality": "Low"}
DATABASE = {"asset_name": "Customer Database", "asset_type": "Database", "ip_address": "198.51.100.20", "operating_system": "Red Hat Enterprise Linux 9", "owner_id": "@@admin_user_id@@", "department": "IT", "location": "Beirut Data Center", "criticality": "High", "status": "Under Maintenance"}
APPLICATION = {"asset_name": "Payroll Application", "asset_type": "Application", "ip_address": "198.51.100.35", "owner_id": "@@analyst_user_id@@", "department": "Finance", "criticality": "High"}
ROUTER = {"asset_name": "Core Router", "asset_type": "Network Device", "ip_address": "192.0.2.1", "operating_system": "Cisco IOS XE", "owner_id": "@@admin_user_id@@", "department": "IT", "location": "Server Room A", "criticality": "Critical"}
CLOUD = {"asset_name": "Backup Cloud Storage", "asset_type": "Cloud Resource", "ip_address": "2001:db8::25", "owner_id": "@@analyst_user_id@@", "department": "Finance", "location": "AWS eu-central-1", "criticality": "Medium", "status": "Inactive"}


def asset(name, api_key, method, path, token, expected, scenario, **kwargs):
    return request(name, api_key, method, "asset_url", path, token, expected, scenario, **kwargs)


asset_main = [
    asset("Add New Asset (Server)", "asset_add", "POST", "/assets", "admin_token", 201, "Critical web server owned by the administrator. Saves asset_id.", body=SERVER, saves={"asset_id": "data.asset_id"}),
    asset("Add New Asset (Workstation)", "asset_add", "POST", "/assets", "admin_token", 201, "Low laptop owned by the regular employee.", body=LAPTOP),
    asset("Add New Asset (Database)", "asset_add", "POST", "/assets", "admin_token", 201, "High database, status Under Maintenance.", body=DATABASE),
    asset("Add New Asset (Application)", "asset_add", "POST", "/assets", "admin_token", 201, "No OS or location; status defaults to Active.", body=APPLICATION),
    asset("Add New Asset (Network Device)", "asset_add", "POST", "/assets", "admin_token", 201, "Critical core router.", body=ROUTER),
    asset("Add New Asset (Cloud Resource)", "asset_add", "POST", "/assets", "admin_token", 201, "Inactive cloud resource with an IPv6 address. Saves delete_asset_id.", body=CLOUD, saves={"delete_asset_id": "data.asset_id"}),
    asset("Retrieve All Assets", "asset_get_all", "GET", "/assets", "auditor_token", 200, "Auditor lists every asset with criticality and status."),
    asset("Retrieve Specific Asset", "asset_get_one", "GET", "/assets/{{asset_id}}", "analyst_token", 200, "Analyst reads one asset. Also the 'before' and 'after' evidence for the update."),
    asset("Search Assets (by name, partial)", "asset_search", "GET", "/assets/search", "analyst_token", 200, "Name contains 'server'.", query=[("asset_name", "server")]),
    asset("Search Assets (by type)", "asset_search", "GET", "/assets/search", "analyst_token", 200, "Exact match on type.", query=[("asset_type", "Database")]),
    asset("Search Assets (by IP address, partial)", "asset_search", "GET", "/assets/search", "auditor_token", 200, "Every asset in the 192.0.2. subnet.", query=[("ip_address", "192.0.2.")]),
    asset("Search Assets (by department)", "asset_search", "GET", "/assets/search", "auditor_token", 200, "Department contains 'finance'.", query=[("department", "finance")]),
    asset("Search Assets (by criticality)", "asset_search", "GET", "/assets/search", "admin_token", 200, "Exact match on criticality.", query=[("criticality", "Critical")]),
    asset("Search Assets (multiple criteria)", "asset_search", "GET", "/assets/search", "admin_token", 200, "Department IT AND criticality High.", query=[("department", "IT"), ("criticality", "High")]),
    asset("Update Asset Information", "asset_update", "PUT", "/assets/{{asset_id}}", "admin_token", 200, "Changes all five updatable fields; the new owner is the analyst.", body={"asset_name": "Main Web Server (Primary)", "owner_id": "@@analyst_user_id@@", "department": "Security Operations", "criticality": "High", "status": "Under Maintenance"}),
    asset("Delete Asset", "asset_delete", "DELETE", "/assets/{{delete_asset_id}}", "admin_token", 200, "Deletes the cloud resource."),
]

asset_errors = [
    asset("Reject Invalid IP Address", "asset_add", "POST", "/assets", "admin_token", 400, "999 is not a valid IPv4 number.", body={**SERVER, "ip_address": "999.1.1.1"}),
    asset("Reject Invalid Asset Type", "asset_add", "POST", "/assets", "admin_token", 400, "'Printer' is not a supported type.", body={**SERVER, "asset_type": "Printer"}),
    asset("Reject Invalid Criticality", "asset_add", "POST", "/assets", "admin_token", 400, "Criticality must be Low, Medium, High or Critical.", body={**SERVER, "criticality": "Extreme"}),
    asset("Reject Invalid Status", "asset_add", "POST", "/assets", "admin_token", 400, "Status must be Active, Inactive or Under Maintenance.", body={**SERVER, "status": "Broken"}),
    asset("Reject Invalid Owner ID", "asset_add", "POST", "/assets", "admin_token", 400, "The owner must be a whole number.", body={**SERVER, "owner_id": "abc"}),
    asset("Reject Owner That Does Not Exist", "asset_add", "POST", "/assets", "admin_token", 400, "Service 1 has no user 99999.", body={**SERVER, "owner_id": 99999}),
    asset("Reject Missing Required Fields", "asset_add", "POST", "/assets", "admin_token", 400, "Lists every missing field.", body={"asset_name": "Lonely Asset"}),
    asset("Reject Empty Request Body", "asset_add", "POST", "/assets", "admin_token", 400, "An empty JSON object is rejected.", body={}),
    asset("Retrieve Non-existing Asset", "asset_get_one", "GET", "/assets/99999", "admin_token", 404, "No asset with this ID."),
    asset("Update Non-existing Asset", "asset_update", "PUT", "/assets/99999", "admin_token", 404, "No asset with this ID.", body={"status": "Inactive"}),
    asset("Delete Non-existing Asset", "asset_delete", "DELETE", "/assets/99999", "admin_token", 404, "No asset with this ID."),
    asset("Reject Updating IP Address", "asset_update", "PUT", "/assets/{{asset_id}}", "admin_token", 400, "The IP address is not updatable.", body={"ip_address": "192.0.2.99"}),
    asset("Reject Invalid Criticality in Update", "asset_update", "PUT", "/assets/{{asset_id}}", "admin_token", 400, "Update validation.", body={"criticality": "Extreme"}),
    asset("Reject Search Without Criteria", "asset_search", "GET", "/assets/search", "admin_token", 400, "At least one parameter is required."),
    asset("Reject Unknown Search Parameter", "asset_search", "GET", "/assets/search", "admin_token", 400, "A misspelled parameter is rejected.", query=[("criticallity", "High")]),
    asset("Reject Request Without Token", "asset_get_all", "GET", "/assets", None, 401, "No Authorization header."),
    asset("Reject Invalid Token", "asset_get_all", "GET", "/assets", "invalid_token", 401, "Service 1 does not recognise the token."),
    asset("Reject Analyst Retrieving All Assets", "asset_get_all", "GET", "/assets", "analyst_token", 403, "Analysts may only retrieve specific assets and search. Compare with the auditor's 200."),
    asset("Reject Regular Employee Searching Assets", "asset_search", "GET", "/assets/search", "employee_token", 403, "Regular employees have no access to assets.", query=[("criticality", "Critical")]),
    asset("Reject Analyst Adding Asset", "asset_add", "POST", "/assets", "analyst_token", 403, "Only the administrator adds assets.", body={**LAPTOP, "asset_name": "Analyst Laptop"}),
    asset("Reject Auditor Updating Asset", "asset_update", "PUT", "/assets/{{asset_id}}", "auditor_token", 403, "Auditors are read-only.", body={"status": "Inactive"}),
    asset("Reject Analyst Deleting Asset", "asset_delete", "DELETE", "/assets/{{asset_id}}", "analyst_token", 403, "Only the administrator may delete. Then send 'Retrieve Specific Asset': it still exists."),
]

# =============================== Service 8 ===============================

INCIDENT = {"user_id": "@@analyst_user_id@@", "title": "New incident assigned", "message": "Incident 12 (Phishing attack) was assigned to you.", "notification_type": "Incident Assignment", "severity": "High"}
SECURITY = {"user_id": "@@employee_user_id@@", "title": "Suspicious login detected", "message": "A login to your account was blocked from an unknown device.", "notification_type": "Security Alert", "severity": "Medium"}
SYSTEM = {"user_id": "@@employee_user_id@@", "title": "Password policy updated", "message": "Passwords must now be changed every 90 days.", "notification_type": "System Notification", "severity": "Low"}
VULNERABILITY = {"user_id": "@@admin_user_id@@", "title": "Critical vulnerability found", "message": "CVE-2024-3400 affects the Main Web Server.", "notification_type": "Vulnerability Alert", "severity": "Critical"}


def note(name, api_key, method, path, token, expected, scenario, **kwargs):
    return request(name, api_key, method, "notification_url", path, token, expected, scenario, **kwargs)


note_main = [
    note("Create Notification (Incident Assignment)", "note_create", "POST", "/notifications", "admin_token", 201, "For the analyst. Saves analyst_notification_id.", body=INCIDENT, saves={"analyst_notification_id": "data.notification_id"}),
    note("Create Notification (Security Alert)", "note_create", "POST", "/notifications", "admin_token", 201, "For the regular employee. Saves employee_notification_id.", body=SECURITY, saves={"employee_notification_id": "data.notification_id"}),
    note("Create Notification (System Notification)", "note_create", "POST", "/notifications", "admin_token", 201, "For the regular employee. Saves delete_notification_id.", body=SYSTEM, saves={"delete_notification_id": "data.notification_id"}),
    note("Create Notification (Vulnerability Alert)", "note_create", "POST", "/notifications", "admin_token", 201, "For the administrator.", body=VULNERABILITY),
    note("Retrieve User Notifications (analyst, own)", "note_user", "GET", "/notifications/user/{{analyst_user_id}}", "analyst_token", 200, "The analyst sees the incident assignment and the automatic Threat Alerts sent by Service 4."),
    note("Retrieve User Notifications (auditor views employee)", "note_user", "GET", "/notifications/user/{{employee_user_id}}", "auditor_token", 200, "Auditors may view any user's notifications."),
    note("Retrieve User Notifications (empty result)", "note_user", "GET", "/notifications/user/{{auditor_user_id}}", "auditor_token", 200, "The auditor has no notifications: an empty list, not an error."),
    note("Retrieve Specific Notification", "note_get_one", "GET", "/notifications/{{employee_notification_id}}", "employee_token", 200, "The employee reads their own notification (before and after marking it as read)."),
    note("Mark Notification as Read", "note_read", "PUT", "/notifications/{{employee_notification_id}}/read", "employee_token", 200, "Status Unread -> Read; read_at records the time (UTC)."),
    note("Search Notifications (by user)", "note_search", "GET", "/notifications/search", "admin_token", 200, "All notifications of the employee.", query=[("user_id", "{{employee_user_id}}")]),
    note("Search Notifications (by type)", "note_search", "GET", "/notifications/search", "auditor_token", 200, "Every Threat Alert.", query=[("notification_type", "Threat Alert")]),
    note("Search Notifications (by severity)", "note_search", "GET", "/notifications/search", "admin_token", 200, "Every Critical notification.", query=[("severity", "Critical")]),
    note("Search Notifications (by status)", "note_search", "GET", "/notifications/search", "auditor_token", 200, "Every unread notification.", query=[("status", "Unread")]),
    note("Search Notifications (multiple criteria)", "note_search", "GET", "/notifications/search", "admin_token", 200, "The employee's read notifications.", query=[("user_id", "{{employee_user_id}}"), ("status", "Read")]),
    note("Search Notifications (analyst, own only)", "note_search", "GET", "/notifications/search", "analyst_token", 200, "An analyst's search only returns their own notifications.", query=[("severity", "High")]),
    note("Delete Notification", "note_delete", "DELETE", "/notifications/{{delete_notification_id}}", "admin_token", 200, "Deletes the System Notification."),
]

note_errors = [
    note("Reject Invalid Notification Type", "note_create", "POST", "/notifications", "admin_token", 400, "'Reminder' is not a supported type.", body={**SYSTEM, "notification_type": "Reminder"}),
    note("Reject Invalid Severity", "note_create", "POST", "/notifications", "admin_token", 400, "Severity must be Low, Medium, High or Critical.", body={**SYSTEM, "severity": "Extreme"}),
    note("Reject Missing Required Fields", "note_create", "POST", "/notifications", "admin_token", 400, "Lists every missing field.", body={"title": "Only a title"}),
    note("Reject Recipient That Does Not Exist", "note_create", "POST", "/notifications", "admin_token", 400, "Service 1 has no user 99999.", body={**SYSTEM, "user_id": 99999}),
    note("Reject Empty Request Body", "note_create", "POST", "/notifications", "admin_token", 400, "An empty JSON object is rejected.", body={}),
    note("Retrieve Non-existing Notification", "note_get_one", "GET", "/notifications/99999", "admin_token", 404, "No notification with this ID."),
    note("Mark Non-existing Notification as Read", "note_read", "PUT", "/notifications/99999/read", "admin_token", 404, "No notification with this ID."),
    note("Delete Non-existing Notification", "note_delete", "DELETE", "/notifications/99999", "admin_token", 404, "No notification with this ID."),
    note("Reject Search Without Criteria", "note_search", "GET", "/notifications/search", "admin_token", 400, "At least one parameter is required."),
    note("Reject Invalid Search Status", "note_search", "GET", "/notifications/search", "admin_token", 400, "Status must be Unread or Read.", query=[("status", "Seen")]),
    note("Reject Request Without Token", "note_user", "GET", "/notifications/user/{{employee_user_id}}", None, 401, "No Authorization header."),
    note("Reject Invalid Token", "note_user", "GET", "/notifications/user/{{employee_user_id}}", "invalid_token", 401, "Service 1 does not recognise the token."),
    note("Reject Analyst Creating Notification", "note_create", "POST", "/notifications", "analyst_token", 403, "Only administrators (and internal services) create notifications.", body=SYSTEM),
    note("Reject Employee Viewing Another User's Notifications", "note_user", "GET", "/notifications/user/{{analyst_user_id}}", "employee_token", 403, "Regular employees only see their own notifications."),
    note("Reject Employee Reading Another User's Notification", "note_get_one", "GET", "/notifications/{{analyst_notification_id}}", "employee_token", 403, "The analyst's notification is private."),
    note("Reject Auditor Marking as Read", "note_read", "PUT", "/notifications/{{analyst_notification_id}}/read", "auditor_token", 403, "Auditors are read-only."),
    note("Reject Employee Searching Notifications", "note_search", "GET", "/notifications/search", "employee_token", 403, "Regular employees cannot search.", query=[("status", "Unread")]),
    note("Reject Analyst Searching Another User", "note_search", "GET", "/notifications/search", "analyst_token", 403, "Analysts may only search their own notifications.", query=[("user_id", "{{employee_user_id}}")]),
    note("Reject Analyst Deleting Notification", "note_delete", "DELETE", "/notifications/{{analyst_notification_id}}", "analyst_token", 403, "Only the administrator may delete."),
    note("Confirm Notification Still Exists", "note_get_one", "GET", "/notifications/{{analyst_notification_id}}", "analyst_token", 200, "After the blocked delete, the analyst's notification is still there."),
]

CREDENTIAL_VARIABLES = [f"{role}_{part}" for role in ("admin", "analyst", "auditor", "employee") for part in ("login", "password")]

collection = {
    "info": {
        "name": "Sleiman Koumaira - Services 2, 4, 8",
        "description": (
            "Requests for the services implemented by Sleiman Koumaira (every route starts with /sleiman-koumaira).\n\n"
            "Before running: start Service 1 (Theana Mansour, port 5001) and Services 2, 4 and 8, fill in the "
            "test accounts' login and password variables, then send the four requests in '0. Setup - Log in'. "
            "They save each role's token and user ID into the collection variables."
        ),
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "item": [
        {"name": "0. Setup - Log in (Service 1, Theana Mansour)", "item": setup},
        {"name": "Service 4 - Threat Intelligence (Sleiman Koumaira)",
         "description": "Threat Intelligence Service, implemented by Sleiman Koumaira. Base URL: http://127.0.0.1:5004/sleiman-koumaira",
         "item": [{"name": "1. Main requests", "item": threat_main},
                  {"name": "2. Validation, permission and error tests", "item": threat_errors}]},
        {"name": "Service 2 - Asset Management (Sleiman Koumaira)",
         "description": "Asset Management Service, implemented by Sleiman Koumaira. Base URL: http://127.0.0.1:5002/sleiman-koumaira",
         "item": [{"name": "1. Main requests", "item": asset_main},
                  {"name": "2. Validation, permission and error tests", "item": asset_errors}]},
        {"name": "Service 8 - Notifications and Alerts (Sleiman Koumaira)",
         "description": "Notification and Alert Management Service, implemented by Sleiman Koumaira. Base URL: http://127.0.0.1:5008/sleiman-koumaira",
         "item": [{"name": "1. Main requests", "item": note_main},
                  {"name": "2. Validation, permission and error tests", "item": note_errors}]},
    ],
    "variable": (
        [{"key": "users_url", "value": "http://127.0.0.1:5001"},
         {"key": "asset_url", "value": "http://127.0.0.1:5002"},
         {"key": "threat_url", "value": "http://127.0.0.1:5004"},
         {"key": "notification_url", "value": "http://127.0.0.1:5008"}]
        + [{"key": key, "value": ""} for key in CREDENTIAL_VARIABLES]
        + [{"key": f"{role}_{part}", "value": ""} for role in ("admin", "analyst", "auditor", "employee") for part in ("token", "user_id")]
        + [{"key": "invalid_token", "value": "this-is-not-a-valid-token"},
           {"key": "threat_id", "value": ""}, {"key": "delete_threat_id", "value": ""},
           {"key": "asset_id", "value": ""}, {"key": "delete_asset_id", "value": ""},
           {"key": "analyst_notification_id", "value": ""}, {"key": "employee_notification_id", "value": ""},
           {"key": "delete_notification_id", "value": ""}]
    ),
}

if __name__ == "__main__":
    with open(sys.argv[1], "w") as f:
        json.dump(collection, f, indent=2)
    counts = {"setup": len(setup), "Service 4": len(threat_main) + len(threat_errors),
              "Service 2": len(asset_main) + len(asset_errors), "Service 8": len(note_main) + len(note_errors)}
    print(f"requests: {counts}, total {sum(counts.values())}")
