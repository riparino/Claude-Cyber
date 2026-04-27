---
name: defensive-threat-intelligence
description: "Threat intelligence operations: IOC enrichment, ThreatIntelligenceIndicator KQL correlation, STIX/TAXII feed integration, Microsoft Defender TI, IOC lifecycle management. Correlate file hash, IP, and URL IOCs against MDE telemetry. Use for SOC TI operations and hunt campaigns."
---

# SKILL: Threat Intelligence

## Metadata
- **Skill Name**: defensive-threat-intelligence
- **Folder**: Skills/defensive-threat-intelligence
- **Source**: sources/defensive-checklist/threat-intelligence.md

## Trigger Phrases
Use this skill when the conversation involves any of:
`threat intelligence, IOC enrichment, ThreatIntelligenceIndicator KQL, STIX TAXII, MISP integration, IOC correlation, file hash IOC, IP IOC, threat actor indicators, Defender TI`

## Instructions for Claude

When this skill is active:
1. KQL: join ThreatIntelligenceIndicator with DeviceNetworkEvents and DeviceFileEvents for correlation
2. IOC age matters: expire after 30 days to prevent FP storm from stale indicators
3. Correlate retroactively: run IOC queries against 30-day historical data
4. Enrich all IOCs: add threat actor, campaign, confidence score before operationalizing
5. STIX/TAXII: use Sentinel TAXII connector for MISP and commercial feeds

---

## Full Methodology

# Threat Intelligence

## Shortcut

- `ThreatIntelligenceIndicator | where Active == true` = active IOCs in Sentinel.
- Join with `DeviceNetworkEvents` on IP or with `DeviceFileEvents` on hash.
- Expire stale IOCs: TTL 30 days default; 7 days for volatile IOCs.
- Confidence score <50 = low confidence; do not auto-block; alert only.

---

## TI Sources

| Source | Type | Method |
|---|---|---|
| Defender TI | IOCs, threat actors | Native Sentinel connector |
| MISP | STIX/TAXII | Sentinel TAXII connector |
| VirusTotal | Hash/URL/IP | Logic App enrichment |
| ISAC feeds | Sector IOCs | TAXII connector |

---

## KQL — TI Correlation

### IP IOC Correlation

```kusto
let MaliciousIPs = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where IndicatorType == "ip"
    | project NetworkIP;
DeviceNetworkEvents
| where RemoteIP in (MaliciousIPs)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated desc
```

### File Hash IOC Correlation

```kusto
let MaliciousHashes = ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where IndicatorType == "file"
    | project FileHashValue;
DeviceFileEvents
| where SHA256 in (MaliciousHashes)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256
| order by TimeGenerated desc
```

---

## IOC Lifecycle

| Stage | Action |
|---|---|
| Ingest | Import via TAXII; validate format |
| Enrich | Actor, campaign, confidence |
| Correlate | Query historical telemetry |
| Expire | 30-day TTL; auto-expire |
| Retrospect | Historical hunt on new IOCs |

---

## MITRE ATT&CK

| Technique | ID | TI Coverage |
|---|---|---|
| Command and Control | T1071 | C2 IP correlation |
| Indicator Removal | T1070 | Log tampering detection |
