import csv
import json
import requests
from datetime import datetime, timedelta
from config import BEARER_TOKEN, HOST, CSV_FILE

DRY_RUN = False
PAGE_LIMIT = 10
HOURS_AGO = 2400
TAGS_API_URL = f"{HOST}/api/v4/tags"
FINDINGS_API_URL = f"{HOST}/api/v4/findings"
LOG_FILE = "tagging_log.csv"

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def get_last_day_finding_params():
    return {
        "sortDesc": "true",
        "limit": PAGE_LIMIT,
        "hoursAgo": HOURS_AGO,
        "returnFields": [
            "id", "title", "url", "typeId", "apiId", "module", "host", "path", "method",
            "resourceGroupName", "status", "severity", "owaspTags", "complianceFrameworkTags",
            "vulnerabilityFrameworkTags", "detectionTime", "lastUpdate", "triggeredOn",
            "description", "impact", "remediation", "investigate", "comments", "tickets",
            "externalTickets", "evidence", "source", "hasRelatedIncidents", "tagsIds", "relatedApiIds"
        ]
    }

def fetch_all_paginated(url, headers, limit=PAGE_LIMIT, extra_params=None):
    all_items = []
    offset = 0
    while True:
        params = {"limit": limit, "offset": offset}
        if extra_params:
            params.update(extra_params)
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            items = data.get("entities", data if isinstance(data, list) else [])
            more = data.get("moreEntities", False)
        except requests.exceptions.RequestException as e:
            print(f"❌ HTTP request failed: {e}")
            break
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
try:
    response = requests.get(TAGS_API_URL, headers=headers)
    response.raise_for_status()
    existing_tags = response.json()
    tag_lookup = {tag['name'].upper(): tag['id'] for tag in existing_tags}
    tag_reverse_lookup = {tag['id']: tag['name'].upper() for tag in existing_tags}
    print(f"✅ Loaded {len(tag_lookup)} tags.\n")
except requests.exceptions.RequestException as e:
    print(f"❌ Failed to fetch tags: {e}")
    exit(1)

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
        raw_objectives = [obj.strip().upper() for cell in row[2:] for obj in cell.split(",") if obj.strip()]
        objectives = set()
        for obj in raw_objectives:
            if not obj.startswith("API-"):
                print(f"⚠️ Skipping invalid tag (must start with 'API-'): {obj}")
                continue
            objectives.add(obj)
        if policy:
            policy_to_objectives.setdefault(policy, set()).update(objectives)

# --- Ensure all tags exist ---
for objectives in policy_to_objectives.values():
    for obj in objectives:
        key = obj.upper()
        if key not in tag_lookup:
            if DRY_RUN:
                print(f"🔎 DRY RUN: Would create tag: {key}")
                tag_lookup[key] = f"{key}"
            else:
                try:
                    payload = {"name": key, "type": "objective"}
                    r = requests.post(TAGS_API_URL, headers=headers, json=payload)
                    r.raise_for_status()
                    tag = r.json()
                    tag_lookup[key] = tag['id']
                    tag_reverse_lookup[tag['id']] = tag['name'].upper()
                    print(f"✅ Created tag: {key} (ID: {tag['id']})")
                except requests.exceptions.RequestException as e:
                    print(f"❌ Failed to create tag {key}: {e}")

# --- Fetch findings ---
print(f"📥 Fetching posture findings from the last {HOURS_AGO} hours...")
finding_filter = get_last_day_finding_params()
findings = fetch_all_paginated(FINDINGS_API_URL, headers, extra_params=finding_filter)
print(f"✅ Retrieved {len(findings)} recent findings.\n")

# --- Tag findings ---
log_entries = []
print("🏷️ Tagging matching findings (only replacing API- tags)...")

for finding in findings:
    title = finding.get("title", "")
    finding_id = finding.get("id")
    module = finding.get("module", "")
    host = finding.get("host", "")
    path = finding.get("path", "")
    existing_tags = set(finding.get("tagsIds", []))

    if title in policy_to_objectives:
        objectives = policy_to_objectives[title]
        new_tag_ids = [tag_lookup[o.upper()] for o in objectives if o.upper() in tag_lookup]

        # Extract API- tags
        api_tag_ids = {tid for tid in existing_tags if tag_reverse_lookup.get(tid, "").startswith("API-")}
        non_api_tag_ids = existing_tags - api_tag_ids
        updated_tags = list(non_api_tag_ids.union(new_tag_ids))

        if set(updated_tags) == existing_tags:
            print(f"🔄 No update required for finding {finding_id} (API- tags already match).")
            log_entries.append([f"Finding-{finding_id}", "No Update", ",".join(objectives)])
            continue

        if DRY_RUN:
            print(f"🔎 DRY RUN: Would update Finding ID: {finding_id}")
            print(f"    • Title: {title}")
            print(f"    • Module: {module}")
            print(f"    • Host/Path: {host}{path}")
            print(f"    • Existing Tags: {[tag_reverse_lookup.get(t, t) for t in existing_tags]}")
            print(f"    • API- Tags Being Replaced: {[tag_reverse_lookup.get(t, t) for t in api_tag_ids]}")
            print(f"    • New API- Tags: {[tag_reverse_lookup.get(t, t) for t in new_tag_ids]}")
            print(f"    • Final Tags: {[tag_reverse_lookup.get(t, t) for t in updated_tags]}")
            print("------------------------------------------------------------")
            log_entries.append([f"Finding-{finding_id}", "Would Replace API- Tags", ",".join(objectives)])
        else:
            patch_url = f"{FINDINGS_API_URL}/{finding_id}/tags"
            try:
                r = requests.patch(patch_url, headers=headers, json={"tagIds": updated_tags})
                r.raise_for_status()
                print(f"✅ Updated Finding ID: {finding_id}")
                print(f"    • Title: {title}")
                print(f"    • Final Tags: {[tag_reverse_lookup.get(t, t) for t in updated_tags]}")
                print("------------------------------------------------------------")
                log_entries.append([f"Finding-{finding_id}", "Replaced API- Tags", ",".join(objectives)])
            except requests.exceptions.RequestException as e:
                print(f"❌ Failed to patch finding {finding_id}: {e}")
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

