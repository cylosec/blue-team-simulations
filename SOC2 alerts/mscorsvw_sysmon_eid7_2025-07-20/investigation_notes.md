# SOC2 Investigation Notes – Alert 92151

## Summary
A Wazuh rule (ID 92151) triggered on 2025-07-20 due to the .NET optimization service (`mscorsvw.exe`) loading `System.Management.Automation.ni.dll`, the native image of the PowerShell automation engine. The alert was marked high severity due to the use of PowerShell-related DLLs, execution under SYSTEM context, and the absence of a digital signature.

## Observables
- **Process:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe`
- **DLL Loaded:** `System.Management.Automation.ni.dll`
- **User:** NT AUTHORITY\SYSTEM
- **Event Type:** Sysmon Event ID 7 (Image Load)
- **ProcessGuid:** {9bc59194-63c8-687c-d80a-000000000b00}
- **Fired Times:** 466

## Investigation Timeline
- Correlated Event ID 7 with local Sysmon logs; no associated Event ID 1 for `mscorsvw.exe` found.
- Verified the executable hash:
  - `mscorsvw.exe` matched known Microsoft SHA256: `BCA992FE050C6B360BB2233F4FB5F2EFA6F670A39AEF844B36F70F029CFFB6CF`
- Located `System.Management.Automation.ni.dll` in both 32- and 64-bit NativeImages cache:
  - `C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\9c1109ca86952b79f69f46b91e900677\System.Management.Automation.ni.dll`
  - LastWriteTime: 07/19/2025 11:33 PM (3 hours before alert)

## Analysis
- `mscorsvw.exe` is a legitimate .NET optimization binary, part of normal runtime operations.
- The DLL path and file size are consistent with expected behavior from native image compilation.
- No outbound network activity, encoded PowerShell commands, or lateral movement detected during this period.
- Frequent alerting (466 times) is likely due to repeated .NET optimization jobs or telemetry overcollection.

## Verdict
**Benign True Positive** – Legitimate system behavior mistaken as suspicious due to use of PowerShell DLLs in a native image context.

## Recommendations
- Suppress future alerts for `mscorsvw.exe` loading `System.Management.Automation.ni.dll` via `local_rules.xml` if repeated in non-malicious context.
- Continue to alert on similar DLL loads initiated by suspicious binaries (e.g., `wmic.exe`, `regsvr32.exe`, `rundll32.exe`).
- Add correlation with Sysmon Event ID 1 and Event ID 3 for full parent-child and network context in future triage cases.
