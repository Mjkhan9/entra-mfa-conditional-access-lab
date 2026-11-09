# Microsoft Entra MFA & Conditional Access Lab

[![CI](https://github.com/Mjkhan9/entra-mfa-conditional-access-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Mjkhan9/entra-mfa-conditional-access-lab/actions/workflows/ci.yml)

Identity threat detection and Conditional Access posture for Microsoft Entra ID. Eight sign-in detections mapped to MITRE ATT&CK, a Conditional Access posture check against Microsoft's baseline, and an analyst playbook (Microsoft Graph calls and Graph PowerShell cmdlets) for every incident. Deployed with Terraform to Azure Functions, built to run at **$0/month**.

**Demo dashboard:** https://mjkhan9.github.io/entra-mfa-conditional-access-lab/

---

## What it detects

Every detection runs over Microsoft Entra sign-in logs (`SigninLogs`): real ones pulled from Log Analytics, or synthetic attack records from the simulator. Same engine, same code path: [`functions/detections.py`](functions/detections.py).

| Detection | MITRE ATT&CK | Severity | Signal | Runbook |
|---|---|---|---|---|
| Password spray | T1110.003 | HIGH, **CRITICAL** if a sprayed account then signs in | One IP, 5+ accounts, `50126` inside 30 min | [04](runbooks/incident-04-password-spray.md) |
| MFA fatigue (push bombing) | T1621 | HIGH | 3+ push prompts denied / unanswered for one user in 10 min, or one fraud report (`500121`) | [05](runbooks/incident-05-mfa-fatigue.md) |
| Smart lockout | T1110.001 | HIGH | `50053` after repeated `50126`; assisted resolution after cooldown | [02](runbooks/incident-02-smart-lockout.md) |
| Legacy authentication sign-in | T1078.004 | HIGH | Successful sign-in over IMAP / POP / SMTP AUTH / EAS / "Other clients" (no MFA possible) | [06](runbooks/incident-06-legacy-auth.md) |
| Admin signed in with password only | T1078.004 | HIGH | `singleFactorAuthentication` success by a holder of one of Microsoft's 14 admin roles (looked up live in Graph) | [07](runbooks/incident-07-privileged-single-factor.md) |
| Emergency access (break-glass) account used | T1078.004 | **CRITICAL** | Any sign-in or attempt by a break-glass account | [08](runbooks/incident-08-break-glass.md) |
| Conditional Access policy mismatch | - | MEDIUM | MFA succeeded, CA still blocked (`53003`): grant-control design error | [03](runbooks/incident-03-policy-mismatch.md) |
| Single MFA failure | - | LOW | One `500121` not part of a fatigue burst (expired / mistyped code) | [01](runbooks/incident-01-mfa-auth-failure.md) |

Signal precision choices:
- `50074` / `50076` ("MFA required") are routine interrupts, not failures, and never raise incidents.
- An MFA fatigue incident absorbs the individual `500121` failures for that user: one incident, not five.
- Incident IDs are derived from the sign-in ID (or attacker IP / user plus a time bucket for burst detections), so re-running detection over overlapping windows never duplicates an incident.

Every detection has a KQL hunting query in [`queries/`](queries/) with the same thresholds.

---

## Conditional Access posture check

`GET /api/posture` reads the tenant's Conditional Access policies and security defaults through Microsoft Graph (read-only) and reports the gaps an attacker would use: [`functions/ca_posture.py`](functions/ca_posture.py).

| Check | Severity | Finds |
|---|---|---|
| CA-01 | CRITICAL | No MFA baseline at all (no enabled policy, security defaults off) |
| CA-02 | HIGH | No enabled policy requires MFA for all users and all resources |
| CA-03 | HIGH | Which of Microsoft's 14 recommended admin roles no enabled MFA policy covers (role exclusions honoured) |
| CA-04 | HIGH | Legacy authentication not blocked (and names a block policy left in report-only) |
| CA-05 | MEDIUM | Enabled policies that do not exclude the emergency access account (lockout risk) |
| CA-06 | MEDIUM | "Require all" grants mixing MFA with device compliance for all users (the cause of policy mismatch incidents) |
| CA-07 | LOW | Policies stuck in report-only |
| CA-08 | LOW | No sign-in / user risk policy (Entra ID P2) |
| CA-09 | LOW | Device code flow not blocked |

The detections and the posture check meet in the middle: CA-04 says legacy auth is not blocked, `legacy_auth_sign_in` shows who is using it; CA-05 keeps the break-glass account excluded, `break_glass_sign_in` watches it.

---

## Response playbooks

Every incident carries its playbook: ordered steps, each with the Microsoft Graph request and the Graph PowerShell cmdlet ([`functions/playbooks.py`](functions/playbooks.py)), for example:

| Action | Microsoft Graph | Graph PowerShell |
|---|---|---|
| Revoke sessions | `POST /users/{id}/revokeSignInSessions` | `Revoke-MgUserSignInSession` |
| Force password change | `PATCH /users/{id}` (`passwordProfile.forceChangePasswordNextSignIn`) | `Update-MgUser` |
| Mark compromised (P2) | `POST /identityProtection/riskyUsers/confirmCompromised` | `Confirm-MgRiskyUserCompromised` |
| Review MFA methods | `GET /users/{id}/authentication/methods` | `Get-MgUserAuthenticationMethod` |
| Block a source range | `POST /identity/conditionalAccess/namedLocations` | `New-MgIdentityConditionalAccessNamedLocation` |

**Nothing changes an identity automatically.** Revoking, resetting or blocking affects real people and stays an analyst decision (`automated: false` on every step). The only automated response is the smart lockout responder, which updates the incident after the cooldown and never touches the account.

---

## Architecture

```
 Microsoft Entra ID ──diagnostic settings──▶ Log Analytics (SigninLogs)
                                                   │
             POST /api/detect  ── pulls last N min ┘        POST /api/simulate
                     │                                       (synthetic attacks)
                     ▼                                              │
               ┌────────────────────────── detections.py ◀──────────┘
               │   8 detections · MITRE ATT&CK · playbooks
               ▼
        Cosmos DB (incidents) ──platform metrics──▶ Azure Monitor metric alerts ──▶ Action group (email)
               │
               └──▶ Application Insights ──▶ Workbook (by detection, technique, severity)

 GET /api/posture ──Microsoft Graph (Policy.Read.All)──▶ Conditional Access findings CA-01…CA-09
```

### Identity and access model (least privilege)

| Identity | Permission | Why |
|---|---|---|
| Function app managed identity | Microsoft Graph `Policy.Read.All` (application, read-only) | Conditional Access policies, security defaults |
| Function app managed identity | Microsoft Graph `RoleManagement.Read.Directory` (application, read-only) | Who holds an admin role |
| Function app managed identity | Azure RBAC `Log Analytics Reader` on the workspace | Pull `SigninLogs` |
| Function app managed identity | Cosmos DB Built-in Data Contributor (data plane) | Read / write incidents; Cosmos keys disabled |
| Callers | Function keys | Every endpoint is `AuthLevel.FUNCTION` |

No connection strings or client secrets in code or settings. The managed identity cannot change a user, a policy or a role.

---

## Run it without Azure

```bash
git clone https://github.com/Mjkhan9/entra-mfa-conditional-access-lab.git
cd entra-mfa-conditional-access-lab/functions

python simulator.py all                 # every attack scenario through the detections
python simulator.py mfa_fatigue --playbook
python ca_posture.py --demo             # posture check on samples/ca-policies-sample.json
python ca_posture.py --file export.json # your tenant: Invoke-MgGraphRequest -Uri /v1.0/identity/conditionalAccess/policies -OutputType Json

cd .. && pip install pytest && pytest -q tests
```

## Deploy

Prerequisites: Azure CLI (`az login`), Terraform ≥ 1.5, Azure Functions Core Tools v4, Python 3.12. Granting the Graph permissions needs Privileged Role Administrator; exporting sign-in logs needs Microsoft Entra ID P1 and Security Administrator.

```bash
cd terraform
cat > terraform.tfvars <<'EOF'
alert_email             = "secops@contoso.com"
break_glass_upns        = ["emergency@contoso.com"]
break_glass_object_ids  = ["<object-id>"]
enable_entra_log_export = true
EOF
terraform init && terraform apply

cd ../functions
func azure functionapp publish "$(terraform -chdir=../terraform output -raw function_app_name)" --python
```

| Endpoint | Purpose |
|---|---|
| `POST /api/simulate` `{"scenario": "password_spray"}` | One attack scenario (`all` runs every scenario) |
| `POST /api/detect` `{"minutes": 60}` | Detections over the last N minutes of real sign-ins |
| `GET /api/posture` (`?demo=1` for the sample) | Conditional Access posture |
| `POST /api/respond` | Resolve smart lockouts past their cooldown |

`terraform output invoke_commands` prints every call with the key lookup.

---

## Results

Measured on 2026-11-09 in a lab tenant (Microsoft Entra ID with trial licences, Azure pay-as-you-go subscription):

- `pytest -q tests`: 37 passed (Python 3.12).
- All 8 KQL queries parse and type-check in Log Analytics.
- `POST /api/simulate {"scenario": "all"}`: 8 incidents, one per detection (2 CRITICAL, 4 HIGH, 1 MEDIUM, 1 LOW), each with its MITRE technique and playbook.
- `GET /api/posture` on the live lab tenant: score 11/100. CA-01 CRITICAL (0 Conditional Access policies, security defaults off), CA-02/03/04 HIGH (0 of 14 admin roles covered), CA-08/09 LOW. The check reports exactly the state the tenant is in.
- Smart lockout: the responder resolved the simulated lockout once its 300-second cooldown had passed.

## Cost design

Built to cost nothing while idle. The first version (an event hub, a timer and log search alert rules) measured about USD 19/month, almost all fixed charges.

| Component | Choice | Why it is free |
|---|---|---|
| Compute | Functions Flex Consumption, HTTP triggers only | Monthly free grant (250,000 executions, 100,000 GB-s); no timer or listener, so the app scales to zero |
| Detection source | Diagnostic settings → Log Analytics, pulled by `detect` | An Event Hubs namespace bills every hour it exists; ingestion stays inside the 5 GB monthly free allowance and queries are free |
| Ingestion guard | Workspace daily cap 0.15 GB | Caps a month at about 4.5 GB, below the free allowance |
| Incident store | Cosmos DB serverless | Billed per request unit; a lab's traffic is a fraction of a cent |
| Alerting | Metric alerts on Cosmos DB and Application Insights platform metrics (6 time series) | First 10 monitored time series are free; log search alerts bill per rule |
| Notifications | Action group email | First 1,000 emails per month are free |

---

## Project structure

```
├── index.html                    # Demo dashboard (GitHub Pages)
├── functions/
│   ├── function_app.py           # simulate · detect · respond · posture (HTTP)
│   ├── detections.py             # 8 detections, MITRE mapping, incident model
│   ├── ca_posture.py             # Conditional Access posture check (CA-01…CA-09)
│   ├── playbooks.py              # Response steps: Graph + Graph PowerShell
│   ├── scenarios.py              # Synthetic attack sign-ins
│   ├── simulator.py · detector.py · pipeline.py · responder.py · graph.py · common.py
│   └── samples/ca-policies-sample.json
├── queries/                      # KQL hunting queries, one per detection
├── runbooks/                     # Incident runbooks 01–08
├── tests/                        # pytest, runs offline
└── terraform/                    # Functions, Cosmos DB, Log Analytics, alerts, workbook,
                                  # Graph app-role grants, Entra diagnostic setting
```

## What I learned

- **Pivot on the right entity.** A spray is noise per account and obvious per source IP; fatigue is the opposite.
- **A detection is only as good as what it suppresses.** `50074` is not a failure; five denied pushes are one incident.
- **Posture and detection are two halves.** The policy gap and the sign-in that uses it should point at each other.
- **Least privilege includes the tooling.** The detector reads Graph and logs; containment stays with a human.
- **Cost is architecture.** Idle resources cost more than the workload; pull + HTTP triggers + metric alerts took the bill to zero.

---

## Author

**Mohammad Khan**  
IT Specialist | Microsoft Certified: Identity and Access Administrator Associate  
University of Houston

[LinkedIn](https://linkedin.com/in/mohammad-jkhan/) · [GitHub](https://github.com/Mjkhan9)

## License

MIT License - Created for educational and portfolio purposes.
