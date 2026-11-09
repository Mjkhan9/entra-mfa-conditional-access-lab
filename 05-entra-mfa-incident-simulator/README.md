# Microsoft Entra MFA Incident Response Simulator

Dual-mode incident detection system for MFA authentication failures in Microsoft Entra ID: supports both **live detection** from sign-in logs and **simulation mode** for testing and demos.

This is the Microsoft counterpart of my AWS MFA incident simulator: same three scenarios, same detect → store → alert → respond workflow, rebuilt on Entra ID and Azure. I built it to demonstrate incident response workflows—not just infrastructure building, but the operational thinking required to detect, diagnose, and resolve authentication failures in production environments.

## Operating Modes

| Mode | Trigger | Use Case |
|------|---------|----------|
| **Detector** | Real Entra sign-in log records streamed by diagnostic settings to an event hub | Production monitoring |
| **Simulator** | HTTP invoke with a test payload | Demos, testing, development |

The same handler decides the mode from the payload shape: a `SignInLogs` record goes through detection, a `scenario` payload through simulation.

[![Azure](https://img.shields.io/badge/Microsoft%20Entra%20ID-Sign--in%20logs%20|%20Event%20Hubs%20|%20Functions-0078D4)](https://entra.microsoft.com/)

---

## What This Does

Simulates **3 real-world MFA failure scenarios** with:

| Component | Purpose |
|-----------|---------|
| **Incident Simulator** | Azure Function that generates realistic authentication failures |
| **Real-time Detection** | Entra diagnostic settings → Event Hub → function processing sign-in records as they arrive |
| **Post-hoc Analysis** | KQL queries over `SigninLogs` in Log Analytics for investigation |
| **Alerting Pipeline** | Azure Monitor alert rules → action group email on incident detection |
| **Incident Tracking** | Automated status updates in Cosmos DB and alerting for response teams |
| **Incident Runbooks** | Step-by-step resolution documentation with portal evidence |

---

## Incident Scenarios

### 1. MFA Authentication Failure (Consistent with an Expired Code)

**What happens:** User enters the correct password, MFA validation fails because the verification code expired, the clock drifted or the code was mistyped.

**Detection signal:**
- Sign-in error `500121` – *Authentication failed during strong authentication request*
- `AuthenticationRequirement = multiFactorAuthentication`
- Authentication details step: `MFA denied; invalid mobile app verification code`
- Optional: Prior successful MFA sign-in within short window

**Response:** User must re-authenticate. No automated remediation (user action required).

---

### 2. Smart Lockout / Account Lockout

**What happens:** Multiple failed sign-in attempts trigger Entra smart lockout.

**Detection signal:**
- 5+ failed sign-ins within 60-second window
- Same `UserPrincipalName`
- Same `IPAddress`
- Followed by sign-in error `50053` – *IdsLocked*

**Response:** Automated incident tracking—status updated in Cosmos DB after cooldown, notification sent, event logged for investigation. *Tracks and alerts; does not modify the Entra user, reset the password or revoke sessions.*

---

### 3. Policy Mismatch (MFA Satisfied but Access Blocked)

**What happens:** User satisfies MFA but a Conditional Access policy blocks access because another grant control is not met (for example *Require all the selected controls* where *Require one of* was intended).

**Detection signal:**
- Sign-in error `53003` – *BlockedByConditionalAccess* (or `53000` / `53001`)
- `ConditionalAccessStatus = failure` with the failing policy and its `enforcedGrantControls`
- MFA step `succeeded = true` in `AuthenticationDetails`

**Response:** Admin intervention required. Runbook guides policy review with the What If tool.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Detection Pipeline                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐                                                    │
│  │ DETECTOR    │  Entra sign-in logs ──▶ Event Hub ──┐              │
│  │ MODE        │  (Diagnostic settings)  (Stream)    │              │
│  └─────────────┘                                     ▼              │
│  ┌─────────────┐                        Azure Function ──▶ Cosmos DB│
│  │ SIMULATOR   │  HTTP invoke ─────────▶ (Dual Mode)     (Incidents)│
│  │ MODE        │  (Test payload)               │                    │
│  └─────────────┘                               ▼                    │
│                                      Application Insights           │
│                                       (events + metrics)            │
│                                                │                    │
│                                                ▼                    │
│                               Action Group ◀── Alert Rules          │
│                                 (Email)      (Azure Monitor)        │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                           Analysis Layer                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Log Analytics (KQL) ──────▶ Post-hoc queries over SigninLogs       │
│  Azure Workbook ───────────▶ Situational awareness (4 tiles)        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Dual-mode detection:**
- **Detector Mode**: Processes real sign-in log JSON from the event hub
- **Simulator Mode**: Accepts test payloads for demos and development

**Design separation:**
- **Event Hub trigger** = Real-time detection
- **Log Analytics / KQL** = Post-hoc analysis / investigation
- **Workbook** = Situational awareness

**Identity model:** the function app uses its managed identity for Cosmos DB (keys disabled) and Event Hubs. No connection strings or secrets in code or settings.

---

## Workbook Tiles

| Tile | Purpose |
|------|---------|
| Incidents by scenario (24h) | Volume awareness |
| Incident volume over time | Trend detection |
| Simulated resolution time | Workflow efficiency |
| Recent incident activity | Current state |

---

## Quick Start

### Prerequisites
- Azure CLI signed in (`az login`) with Contributor on the subscription
- Terraform >= 1.5
- Azure Functions Core Tools v4
- Python 3.12
- For live detection only: Microsoft Entra ID P1 and the Security Administrator role (set `enable_entra_log_export = true`)

### Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply

cd ../functions
func azure functionapp publish $(terraform -chdir=../terraform output -raw function_app_name) --python
```

### Trigger Test Incident

```bash
# From the 05-entra-mfa-incident-simulator folder: get the function key and call the simulator
APP=$(terraform -chdir=terraform output -raw function_app_name)
RG=$(terraform -chdir=terraform output -raw resource_group_name)
KEY=$(az functionapp function keys list -g "$RG" -n "$APP" --function-name simulate --query default -o tsv)

curl -s -X POST "https://$APP.azurewebsites.net/api/simulate?code=$KEY" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "smart_lockout", "user": "test-user"}'
```

`terraform output invoke_commands` prints all three scenarios ready to paste.

---

## Project Structure

```
entra-mfa-incident-simulator/
├── README.md
├── incident-dashboard.html     # Static demo dashboard (GitHub Pages)
│
├── functions/                  # One function app, three triggers
│   ├── function_app.py         # simulate (HTTP) · detect (Event Hub) · respond (Timer)
│   ├── simulator.py            # Incident generation and detection logic
│   ├── responder.py            # Assisted remediation
│   ├── common.py               # Cosmos DB access, alerts, metrics
│   ├── host.json
│   ├── requirements.txt
│   └── local.settings.json.example
│
├── terraform/
│   ├── main.tf                 # Provider, resource group, Log Analytics, App Insights
│   ├── function_app.tf         # Function app, managed identity, role assignments
│   ├── eventhub.tf             # Event hub + Entra diagnostic setting
│   ├── cosmosdb.tf             # Incident storage
│   ├── action_group.tf         # Alert notifications
│   ├── alerts.tf               # Alert rules
│   ├── workbook.tf             # 4-tile workbook
│   ├── variables.tf
│   └── outputs.tf
│
├── incidents/
│   ├── incident-01-mfa-auth-failure.md
│   ├── incident-02-smart-lockout.md
│   └── incident-03-policy-mismatch.md
│
├── queries/
│   ├── mfa-auth-failure.kql
│   ├── smart-lockout.kql
│   └── policy-mismatch.kql
│
├── screenshots/
│   └── (portal evidence captured during incidents)
│
└── LICENSE
```

---

## Service Mapping

Same workflow, Microsoft services:

| Role in the pipeline | AWS version | This version |
|----------------------|-------------|--------------|
| Authentication events | CloudTrail `ConsoleLogin` | Entra ID sign-in logs (`SigninLogs`) |
| Real-time delivery | EventBridge rules | Diagnostic settings → Event Hubs |
| Processing | Lambda (dual mode) | Azure Functions (dual mode) |
| Incident storage | DynamoDB (TTL, GSI) | Cosmos DB serverless (TTL, partition by scenario) |
| Alerting | SNS topic + email | Azure Monitor alert rules + action group |
| Metrics and dashboard | CloudWatch metrics + dashboard | Application Insights + Azure Workbook |
| Investigation queries | CloudWatch Logs Insights | Log Analytics KQL |
| Scheduled remediation | EventBridge schedule | Timer trigger |
| Permissions | IAM role | Managed identity + Azure RBAC |

---

## Planned Extensions

- **Risky sign-in correlation:** Join incidents with Entra ID Protection risk detections (atypical travel, unfamiliar sign-in properties)
- **Method strength:** Flag MFA failures where the registered method is SMS / voice rather than Authenticator or a passkey
- **Microsoft Sentinel:** Forward incidents as Sentinel incidents and attach the runbooks as playbooks

---

## What I Learned

- **Operational thinking:** Detection, diagnosis, and resolution—not just building
- **Signal precision:** Entra ID doesn't log "code expired" either; you read error 500121 plus the authentication-details step and corroborate with earlier sign-ins
- **Scope discipline:** 3 clean scenarios > 5 half-baked ones
- **Interview framing:** Language matters—"consistent with" vs "caused by"
- **Platform mapping:** The workflow ports cleanly between clouds once you separate the pipeline roles from the service names

---

## Author

**Mohammad Khan**  
IT Specialist | Microsoft Certified: Identity and Access Administrator Associate  
University of Houston

[LinkedIn](https://linkedin.com/in/mohammad-jkhan/) · [GitHub](https://github.com/Mjkhan9)

---

## License

MIT License - Created for educational and portfolio purposes.
