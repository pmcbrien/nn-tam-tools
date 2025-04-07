import requests
from datetime import datetime, timedelta
from config import API_BASE_URL, API_KEY, DRY_RUN, DAYS_LOOKBACK

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Date range from now back DAYS_LOOKBACK days
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=DAYS_LOOKBACK)

def isoformat(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def get_all_recent_incidents():
    all_incidents = []
    offset = 0
    limit = 50

    while True:
        params = {
            "returnFields": ["id", "responseCodes", "status"],
            "detectionStartDate": isoformat(start_date),
            "detectionEndDate": isoformat(end_date),
            "lastUpdateStartDate": isoformat(start_date),
            "lastUpdateEndDate": isoformat(end_date),
            "lastActivityStartDate": isoformat(start_date),
            "lastActivityEndDate": isoformat(end_date),
            "sortDesc": "true",
            "limit": limit,
            "offset": offset
        }

        try:
            response = requests.get(f"{API_BASE_URL}/api/v4/incidents", headers=HEADERS, params=params)
            response.raise_for_status()
            if not response.text.strip():
                print("[Warning] Empty response body received.")
                break
            data = response.json()
            entities = data.get("entities", [])
            if not entities:
                break
            all_incidents.extend(entities)
            offset += len(entities)
        except requests.exceptions.RequestException as e:
            print(f"[Error] Failed to fetch incidents: {e}\nResponse content: {response.text}")
            break

    return all_incidents

def update_incident_to_resolved(incident_id):
    if DRY_RUN:
        print(f"[Dry Run] Would mark incident {incident_id} as resolved.")
        return

    payload = {"status": "resolved"}
    try:
        response = requests.patch(f"{API_BASE_URL}/api/v4/incidents/{incident_id}", headers=HEADERS, json=payload)
        response.raise_for_status()
        print(f"Incident {incident_id} marked as resolved.")
    except requests.exceptions.RequestException as e:
        print(f"[Error] Failed to update incident {incident_id}: {e}\nResponse content: {response.text}")

def main():
    incidents = get_all_recent_incidents()
    for incident in incidents:
        incident_id = incident.get("id")
        response_codes = incident.get("responseCodes", [])
        status = incident.get("status")

        print(f"Checking incident {incident_id} - Status: {status}, Response Codes: {response_codes}")
        
        if 403 in response_codes and status != "resolved":
            update_incident_to_resolved(incident_id)

if __name__ == "__main__":
    main()
