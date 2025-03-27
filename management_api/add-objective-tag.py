import csv
import json
import requests
from datetime import datetime, timedelta
from config import BEARER_TOKEN, HOST, CSV_FILE

# --- NOTICE ---
# YOU MUST CREATE A config.py in this folder with


#   BEARER_TOKEN = "Your_Bearer_Token"  # Replace with actual token
#   HOST = "https://YOURCUSTOMER.nonamesec.com" #replace with your tenant hostname
#   CSV_FILE = "MY.csv" #the csv file that contains your objectives and findings mapping

#
#  DO NOT SHARE OR UPLOAD your config.py PUBILICY. That would be BAD
#

TAGS_API_URL = f"{HOST}/api/v4/tags"
FINDINGS_API_URL = f"{HOST}/api/v4/findings"
LOG_FILE = "tagging_log.csv"
DRY_RUN = False
PAGE_LIMIT = 500

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# --- Helpers ---
def get_last_day_finding_params():
    return {
        "sortDesc": "true",
        "limit": PAGE_LIMIT,
        "offset": 0,
        "hoursAgo": 24,
        "returnFields": [
            "id", "title", "url", "typeId", "apiId", "module", "host", "path", "method",
            "resourceGroupName", "status", "severity", "owaspTags", "complianceFrameworkTags",
            "vulnerabilityFrameworkTags", "detectionTime", "lastUpdate", "triggeredOn",
            "description", "impact", "remediation", "investigate", "comments", "tickets",
            "externalTickets", "evidence", "source", "hasRelatedIncidents", "tagsIds", "relatedApiIds"
        ]
    }

def fetch_all_paginated(url, headers, limit=PAGE_LIMIT, extra_params=None):
    offset = 0
    all_items = []
    while True:
        params = {"limit": limit, "offset": offset}
        if extra_params:
            params.update(extra_params)
        response = requests.get(url, headers=headers, params=params)
        try:
            data = response.json()
            items = data.get("entities", data if isinstance(data, list) else [])
            more = data.get("moreEntities", False)
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            break
        if not items:
            break
        all_items.extend(items)
        offset += limit
        if not more:
            break
    return all_items

# --- Load tags ---
print("📥 Fetching existing tags...")
response = requests.get(TAGS_API_URL, headers=headers)
if response.status_code != 200:
    print(f"❌ Failed to fetch tags: {response.status_code} - {response.text}")
    exit(1)
existing_tags = response.json()
tag_lookup = {tag['name'].lower(): tag['id'] for tag in existing_tags}
print(f"✅ Loaded {len(tag_lookup)} tags.\n")

# --- Load CSV mappings ---
policy_to_objectives = {}
with open(CSV_FILE, mode="r", newline='') as file:
    reader = csv.reader(file)
    header = next(reader)
    for row in reader:
        if len(row) < 3:
            continue
        policy = row[1].strip()
        if policy.lower().endswith("- default"):
            policy = policy[:policy.lower().rfind("- default")].strip()
        objectives = set(obj.strip() for cell in row[2:] for obj in cell.split(",") if obj.strip())
        if policy:
            policy_to_objectives.setdefault(policy, set()).update(objectives)

# --- Ensure all tags exist ---
for objectives in policy_to_objectives.values():
    for obj in objectives:
        key = obj.lower()
        if key not in tag_lookup:
            if DRY_RUN:
                print(f"🔎 DRY RUN: Would create tag: {obj}")
                tag_lookup[key] = f"simulated-{key}"
            else:
                payload = {"name": obj, "type": "objective"}
                r = requests.post(TAGS_API_URL, headers=headers, json=payload)
                if r.status_code == 201:
                    tag = r.json()
                    tag_lookup[key] = tag['id']
                    print(f"✅ Created tag: {obj} (ID: {tag['id']})")
                else:
                    print(f"❌ Failed to create tag {obj}: {r.status_code} - {r.text}")

# --- Fetch findings ---
print("📥 Fetching findings from the last 24 hours...")
finding_filter = get_last_day_finding_params()
findings = fetch_all_paginated(FINDINGS_API_URL, headers, extra_params=finding_filter)
findings_by_id = {f['id']: f for f in findings if isinstance(f, dict)}
print(f"✅ Retrieved {len(findings)} recent findings.\n")

# --- Tag findings ---
log_entries = []
print("🏷️ Tagging matching findings...")

for finding in findings:
    title = finding.get("title", "")
    finding_id = finding.get("id")
    existing_tags = set(finding.get("tagsIds", []))

    if title in policy_to_objectives:
        objectives = policy_to_objectives[title]
        tag_ids = [tag_lookup[o.lower()] for o in objectives if o.lower() in tag_lookup]
        updated_tags = list(existing_tags.union(tag_ids))

        if DRY_RUN:
            print(f"🔎 DRY RUN: Would PATCH finding {finding_id} with tags: {updated_tags}")
            log_entries.append([f"Finding-{finding_id}", "Would Patch Finding", ",".join(objectives)])
        else:
            patch_url = f"{FINDINGS_API_URL}/{finding_id}/tags"
            r = requests.patch(patch_url, headers=headers, json={"tagIds": updated_tags})
            if r.status_code == 200:
                print(f"✅ Patched finding {finding_id}")
                log_entries.append([f"Finding-{finding_id}", "Patched Finding", ",".join(objectives)])
            else:
                print(f"❌ Failed to patch finding {finding_id}: {r.status_code}")
                log_entries.append([f"Finding-{finding_id}", "Patch Failed", ""])

# --- Write audit log ---
with open(LOG_FILE, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Policy/Item", "Status", "Objectives"])
    writer.writerows(log_entries)

print("\n✅ Complete!")
if DRY_RUN:
    print("🚫 DRY RUN mode — no changes were made.")
print(f"📄 Log saved to: {LOG_FILE}")
