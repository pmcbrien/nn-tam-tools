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

#    FORMAT FOR YOUR CSV FILE. 
#    Posture,Weak Authentication Method - default,MyTag
#
#  DO NOT SHARE OR UPLOAD your config.py PUBILICY. That would be BAD
#

TAGS_API_URL = f"{HOST}/api/v4/tags"
FINDINGS_API_URL = f"{HOST}/api/v4/findings"
LOG_FILE = "tagging_log.csv"
DRY_RUN = False
PAGE_LIMIT = 10  # Fetch 10 findings at a time
HOURS_AGO = 2400  # Default is 2400 hours ago (last 100 days), change as needed

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# --- Helpers ---
def get_last_day_finding_params():
    # Don't include `offset` here since it will be dynamically set in the fetch function
    return {
        "sortDesc": "true",
        "limit": PAGE_LIMIT,
        "hoursAgo": HOURS_AGO,  # Use the variable HOURS_AGO
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
    offset = 0  # Start at the first offset

    while True:
        params = {"limit": limit, "offset": offset}
        if extra_params:
            params.update(extra_params)
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()  # Raise HTTPError for bad responses
            data = response.json()
            items = data.get("entities", data if isinstance(data, list) else [])
            more = data.get("moreEntities", False)  # Check if more results exist
        except requests.exceptions.RequestException as e:
            print(f"❌ HTTP request failed: {e}")
            break
        except Exception as e:
            print(f"❌ Failed to parse JSON: {e}")
            break

        if not items:
            break  # No more items, stop the loop

        all_items.extend(items)  # Add the current batch of items
        offset += limit  # Increment offset to fetch the next page of results

        if not more:  # If no more entities, exit loop
            break

    return all_items

# --- Load tags ---
print("📥 Fetching existing tags...")
try:
    response = requests.get(TAGS_API_URL, headers=headers)
    response.raise_for_status()  # Raise HTTPError for bad responses
    existing_tags = response.json()
    tag_lookup = {tag['name'].lower(): tag['id'] for tag in existing_tags}
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
                try:
                    payload = {"name": obj, "type": "objective"}
                    r = requests.post(TAGS_API_URL, headers=headers, json=payload)
                    r.raise_for_status()  # Raise HTTPError for bad responses
                    tag = r.json()
                    tag_lookup[key] = tag['id']
                    print(f"✅ Created tag: {obj} (ID: {tag['id']})")
                except requests.exceptions.RequestException as e:
                    print(f"❌ Failed to create tag {obj}: {e}")

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

        # Skip the update if the tag is already applied
        if set(updated_tags) == existing_tags:
            print(f"🔄 No update required for finding {finding_id} (tags already applied).")
            log_entries.append([f"Finding-{finding_id}", "No Update", ",".join(objectives)])
            continue

        if DRY_RUN:
            print(f"🔎 DRY RUN: Would PATCH finding {finding_id} with tags: {updated_tags}")
            log_entries.append([f"Finding-{finding_id}", "Would Patch Finding", ",".join(objectives)])
        else:
            patch_url = f"{FINDINGS_API_URL}/{finding_id}/tags"
            try:
                r = requests.patch(patch_url, headers=headers, json={"tagIds": updated_tags})
                r.raise_for_status()  # Raise HTTPError for bad responses
                print(f"✅ Patched finding {finding_id}")
                log_entries.append([f"Finding-{finding_id}", "Patched Finding", ",".join(objectives)])
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
