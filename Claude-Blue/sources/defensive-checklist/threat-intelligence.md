# Threat Intelligence — IOC Enrichment & Integration

## Overview
IOC enrichment, KQL for ThreatIntelligenceIndicator table, STIX/TAXII feed integration, Microsoft Defender TI, IOC lifecycle management.

## Shortcut

- `ThreatIntelligenceIndicator` table in Sentinel = correlate with DeviceNetworkEvents, SigninLogs.
- STIX 2.1 / TAXII 2.1 = standard feed format; import into Sentinel via TI connector.
- VirusTotal API: `POST /files/{hash}/analyse` for file hash enrichment.
- MISP: open source TI platform; push IOCs to Sentinel via TAXII.
- IOC age matters: 30-day default TTL; expire stale IOCs to reduce FP rate.

---

## TI Sources

| Source | Type | Integration |
|---|---|---|
| Microsoft Defender TI | IOCs, threat actor profiles | Native Sentinel connector |
| MISP | STIX/TAXII feed | Sentinel TAXII connector |
| VirusTotal | File/URL/IP enrichment | Logic App / Playbook |
| AlienVault OTX | Community IOCs | TAXII connector |
| ISAC feeds | Sector-specific IOCs | TAXII connector |
| Government CISA | Critical infrastructure | TAXII / manual CSV |

---

## KQL — Sentinel ThreatIntelligenceIndicator

### Active IOCs from Last 7 Days

```kusto
ThreatIntelligenceIndicator
| where TimeGenerated > ago(7d)
| where Active == true
| summarize Count=count() by ThreatType, IndicatorType
| order by Count desc
```

### Correlate IP IOCs with Network Connections

```kusto
let MaliciousIPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where IndicatorType == "ip"
    | project NetworkIP;
DeviceNetworkEvents
| where RemoteIP in (MaliciousIPs)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, RemoteUrl
| order by TimeGenerated desc
```

### Correlate File Hash IOCs

```kusto
let MaliciousHashes = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where IndicatorType == "file"
    | project FileHashValue;
DeviceFileEvents
| where SHA256 in (MaliciousHashes) or MD5 in (MaliciousHashes)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated desc
```

---

## IOC Lifecycle

| Stage | Action |
|---|---|
| Ingest | Import via TAXII/CSV; validate format |
| Enrich | Add context: threat actor, campaign, confidence |
| Correlate | Run queries against telemetry |
| Expire | Set TTL (30 days default); auto-expire |
| Retrospect | Hunt historical data for IOC matches |

---

## MITRE ATT&CK

| Technique | ID | Notes |
|---|---|---|
| Indicator Removal | T1070 | Detect log/IOC tampering |
| Command and Control | T1071 | IOC correlation for C2 IPs |
