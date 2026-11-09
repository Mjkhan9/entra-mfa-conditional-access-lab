# Microsoft Entra MFA & Conditional Access Lab

[![CI](https://github.com/Mjkhan9/entra-mfa-conditional-access-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Mjkhan9/entra-mfa-conditional-access-lab/actions/workflows/ci.yml)

A lab I run against my own Microsoft Entra test tenant. It does two things:

1. **Detects identity attacks in Entra sign-in logs**: password spray, MFA fatigue, legacy authentication, break-glass account use and a few others, each mapped to MITRE ATT&CK.
2. **Checks Conditional Access**: reads the tenant's policies through Microsoft Graph and lists the gaps (no MFA for admins, legacy auth not blocked, and so on).

Python on Azure Functions, deployed with Terraform. Demo page (static, fake data): https://mjkhan9.github.io/entra-mfa-conditional-access-lab/

## Detections

| Detection | MITRE | Triggers on |
|---|---|---|
| Password spray | T1110.003 | One IP, 5+ accounts failing with `50126` in 30 min. CRITICAL if one of those accounts then signs in |
| MFA fatigue | T1621 | 3+ denied or unanswered push prompts (`500121`) for one user in 10 min, or a fraud report |
| Smart lockout | T1110.001 | `50053` after repeated bad passwords |
| Legacy auth sign-in | T1078.004 | Successful sign-in over IMAP, POP, SMTP AUTH, EAS or "Other clients" |
| Admin password-only sign-in | T1078.004 | An admin account signs in with `singleFactorAuthentication` |
| Break-glass account used | T1078.004 | Any sign-in attempt by the emergency access account (CRITICAL) |
| CA policy mismatch | - | MFA passed but Conditional Access still blocked (`53003`) |
| Single MFA failure | - | One `500121` that is not part of a fatigue burst |

The code is in [`functions/detections.py`](functions/detections.py). Each detection has a matching KQL query in [`queries/`](queries/) and a runbook in [`runbooks/`](runbooks/). The thresholds are values I picked for a small tenant, not tuned against real attack traffic.

Things I had to work out while writing them:
- `50074` / `50076` ("MFA required") show up on almost every normal sign-in, so they never raise an incident.
- One push-bombing attempt kept turning into six incidents (the fatigue one plus every single failure). Now the fatigue incident absorbs the single failures for that user.
- Incident IDs come from the sign-in ID (or IP/user plus a time bucket), so running detection twice over the same window does not create duplicates.

## Conditional Access check

`GET /api/posture` reads the Conditional Access policies and security defaults (Graph `Policy.Read.All`, read-only) and reports nine checks, CA-01 to CA-09 in [`functions/ca_posture.py`](functions/ca_posture.py): no MFA baseline at all, no MFA policy for all users, admin roles not covered by MFA, legacy auth not blocked, break-glass account not excluded, "require all" grants that mix MFA and compliant device, policies left in report-only, no risk policy, device code flow not blocked.

My lab tenant scores 11/100: it has no Conditional Access policies and security defaults are off.

## Response steps

Each incident comes with suggested next steps and the Graph request / Graph PowerShell cmdlet for each (revoke sessions, force a password change, review MFA methods, block an IP range). None of them run automatically. The only automatic action is closing a smart lockout incident after the 5-minute cooldown, and that never touches the account.

## How it works

```
Entra sign-in logs -> Log Analytics -> POST /api/detect -> detections.py -> Cosmos DB -> metric alert -> email
                         POST /api/simulate (fake attack sign-ins) -^
GET /api/posture -> Microsoft Graph -> CA-01..CA-09 findings
```

| Endpoint | What it does |
|---|---|
| `POST /api/simulate` `{"scenario": "password_spray"}` | Runs one fake attack (`all` runs every one) through the detections |
| `POST /api/detect` `{"minutes": 60}` | Runs the detections over the last N minutes of real sign-ins |
| `GET /api/posture` | Conditional Access check (`?demo=1` uses the sample policies) |
| `POST /api/respond` | Closes smart lockout incidents past their cooldown |

The function app uses a managed identity: Log Analytics Reader on the workspace, Cosmos DB data contributor (keys are disabled) and Graph `Policy.Read.All`. No secrets or connection strings in code or settings.

## Run it locally (no Azure needed)

```bash
cd functions
python simulator.py all                  # every attack scenario through the detections
python simulator.py mfa_fatigue --playbook
python ca_posture.py --demo              # posture check on samples/ca-policies-sample.json
cd .. && pip install pytest && pytest -q tests
```

## Deploy

Needs Azure CLI, Terraform 1.5+, Azure Functions Core Tools v4 and Python 3.12. Exporting sign-in logs needs Entra ID P1; granting the Graph permission needs Privileged Role Administrator.

```bash
cd terraform
# terraform.tfvars: alert_email, break_glass_upns, break_glass_object_ids,
#                   privileged_upns, enable_entra_log_export = true
terraform init && terraform apply
cd ../functions
func azure functionapp publish "$(terraform -chdir=../terraform output -raw function_app_name)" --python
```

## Results (2026-11-09)

- `pytest`: 37 passed.
- `simulate all`: 8 incidents, one per detection.
- `detect` on real sign-in logs: one HIGH incident for my own Global Admin account, 21 password-only sign-ins in a day. That's correct for this tenant (see the posture score above).
- `posture` on the real tenant: 11/100.
- Both metric alerts (incident created, incident resolved) fired.

## Problems I ran into

- **No quota on the Consumption plan.** A new subscription had zero quota for Linux Consumption (Y1), so I moved the function app to Flex Consumption.
- **It cost about $19/month doing nothing.** The first version streamed sign-ins through an Event Hub (~$11/month just for existing) and used 5 log search alert rules ($1.50 each). I switched to pulling from Log Analytics when `detect` is called and to metric alerts, which are free for the first 10 time series. It now costs $0 at lab volume, and the workspace has a 0.15 GB/day ingestion cap.
- **The resolved alert never fired.** Cosmos DB request metrics count creates but not patch operations, so updating an incident to RESOLVED was invisible to the alert. The responder now writes a small record to a `resolutions` container and the alert watches that.
- **The admin detection never fired on real logs.** The Graph role lookup returned an empty list in Azure without an error. I replaced it with a configured list of admin accounts.
- **The sign-in log export is slow to start and doesn't backfill.** The first rows arrived about 40 minutes after I turned it on. Two test sign-ins I made on the break-glass account before that never reached the workspace.
- `first` and `last` are reserved words in KQL. Took me a minute.

## Not done yet

- Break-glass detection has only been tested with simulated sign-ins. I still need to repeat the real test now that the export is running.
- Detection runs when `/api/detect` is called, not on a schedule (a timer would keep the app from scaling to zero).
- The admin account list is manual.

## Layout

```
functions/   Azure Functions app: detections, posture check, simulator, responder
queries/     KQL query per detection
runbooks/    Runbook per detection
terraform/   Function app, Cosmos DB, Log Analytics, alerts, workbook, Graph permission, sign-in log export
tests/       pytest, runs offline
index.html   Demo page (GitHub Pages)
```

## Author

**Mohammad Khan**  
IT Specialist | Microsoft Certified: Identity and Access Administrator Associate  
University of Houston

[LinkedIn](https://linkedin.com/in/mohammad-jkhan/) | [GitHub](https://github.com/Mjkhan9)

MIT License
