import json
import os

# Load the alert JSON
input_path = "alerts/alert1.json"
output_folder = "triage-reports"

# Ensure output folder exists
os.makedirs(output_folder, exist_ok=True)

# Read JSON file
with open(input_path, "r") as f:
    alert = json.load(f)

# Parse fields
agent = alert["_source"]["agent"]
eventdata = alert["_source"]["data"]["win"]["eventdata"]
system = alert["_source"]["data"]["win"]["system"]
rule = alert["_source"]["rule"]
timestamp = alert["_source"]["timestamp"]

# Format the triage output
triage_output = f"""SOC 1 Triage Summary - Sysmon Event ID {system["eventID"]}

[Agent Information]
Hostname     : {agent["name"]}
IP Address   : {agent["ip"]}
Agent ID     : {agent["id"]}

[Process Information]
Executable   : {eventdata.get("image")}
Command Line : {eventdata.get("commandLine")}
User         : {eventdata.get("user")}
Parent       : {eventdata.get("parentImage")}
Integrity    : {eventdata.get("integrityLevel")}

[Detection Rule]
Rule ID      : {rule["id"]}
Description  : {rule["description"]}
Severity     : {rule["level"]}
MITRE TTPs   : {", ".join(rule["mitre"]["id"])} ({", ".join(rule["mitre"]["technique"])})

[Sysmon Metadata]
Channel      : {system["channel"]}
Computer     : {system["computer"]}
Provider     : {system["providerName"]}
Timestamp    : {timestamp}

[Analyst Notes]
- Check if this command was executed as part of a routine task.
- Review user session history and admin group membership.
- Escalate to Tier 2 if unauthorized or linked to lateral movement.
"""

# Write to text file
filename = f"triage_sysmon_event_{system['eventID']}_{agent['name']}.txt"
filepath = os.path.join(output_folder, filename)

with open(filepath, "w") as f:
    f.write(triage_output)

print(f"Triage summary saved to: {filepath}")

