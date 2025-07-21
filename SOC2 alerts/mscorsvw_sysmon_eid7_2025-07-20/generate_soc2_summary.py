import json
from datetime import datetime

# Load your JSON alert from the correct file path
with open("../json/wazuh_sysmon_alert_071925_2335.json", "r", encoding="utf-8-sig") as f:
    data = json.load(f)

alert = data["_source"]

# Extract core fields
agent_name = alert["agent"]["name"]
agent_ip = alert["agent"]["ip"]
user = alert["data"]["win"]["eventdata"]["user"]
image = alert["data"]["win"]["eventdata"]["image"]
image_loaded = alert["data"]["win"]["eventdata"]["imageLoaded"]
signed = alert["data"]["win"]["eventdata"]["signed"]
event_id = alert["data"]["win"]["system"]["eventID"]
timestamp = alert["timestamp"]
rule = alert["rule"]
severity = rule["level"]
rule_description = rule["description"]
mitre_id = ", ".join(rule.get("mitre", {}).get("id", ["N/A"]))
firedtimes = rule["firedtimes"]

# Timestamp formatting (Jira readable)
parsed_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
readable_time = parsed_time.strftime("%Y-%m-%d %H:%M:%S %Z")

# Evaluation logic
true_positive = (
    severity >= 10 and
    "PowerShell" in rule_description and
    signed.lower() == "false" and
    user.upper().startswith("NT AUTHORITY\\SYSTEM") and
    firedtimes > 100
)

# Format summary
summary = {
    "Summary": f"[SOC2 Escalation] PowerShell Execution Detected on {agent_name}",
    "Host": agent_name,
    "IP Address": agent_ip,
    "User": user,
    "Process": image,
    "Module Loaded": image_loaded,
    "Signed": signed,
    "MITRE ID": mitre_id,
    "Rule": rule_description,
    "Event ID": event_id,
    "Severity": severity,
    "Fired Times": firedtimes,
    "Timestamp": readable_time,
    "True Positive": "Yes" if true_positive else "No",
    "Escalation Recommendation": "Escalate to SOC2 IR Team" if true_positive else "Monitor in Tier 1"
}

# Output to console
print("\n=== SOC2 Jira Summary ===\n")
for key, value in summary.items():
    print(f"{key}: {value}")

# Save to file for Jira copy/paste
with open("jira_soc2_summary.txt", "w", encoding="utf-8") as f:
    for key, value in summary.items():
        f.write(f"{key}: {value}\n")
