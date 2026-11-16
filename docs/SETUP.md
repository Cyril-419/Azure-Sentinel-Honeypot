# Setup guide

Step-by-step build for the honeypot lab. Plan on about **2 hours of setup**, then let the honeypot run **24–72 hours**, then about **2 hours** for detections, investigation and write-up.

> Azure and the Defender portal change their menus often. If a button has moved, search for the same name in the portal's search bar. The concepts stay the same.

As you go, take the screenshots listed in each step's 📸 note and save them in `screenshots/`. **Blur your own public IP address and your subscription ID** before you commit them.

---

## 0. Before you start: cost and safety

**Cost**
- A new Log Analytics workspace gets the Sentinel free trial: the first 10 GB/day is free for 31 days. This lab uses a tiny fraction of that.
- The VM costs money for every hour it runs. A `B2s` size for 2–3 days usually costs a few dollars. Check the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your region.
- **Set a budget alert first:** Azure portal → *Cost Management* → *Budgets* → *Add*, for example $10 with an email alert at 50%.

**Safety rules for a honeypot**
- Put everything in **one new resource group** so you can delete it all in one click.
- **Never reuse a real password.** Use a long, random password from a password manager and a username that isn't obvious (not `admin` or `administrator`).
- Put **nothing personal** on the VM, and don't sign in to any of your real accounts from it.
- Only open **RDP (3389)**, not all ports. That's enough to attract attacks, and every port you open is more attack surface.
- **Delete the resource group** when you're done (step 13).

---

## 1. Create a resource group

Azure portal → *Resource groups* → *Create*
- Name: `rg-honeypot-lab`
- Region: pick one near you (for example *South Central US*) and use it for everything below

## 2. Create the Log Analytics workspace

Azure portal → *Log Analytics workspaces* → *Create*
- Resource group: `rg-honeypot-lab`
- Name: `law-honeypot`
- Same region

This is where the VM's security logs will be stored.

## 3. Turn on Microsoft Sentinel

Azure portal → *Microsoft Sentinel* → *Create* → select `law-honeypot` → *Add*.

New workspaces are automatically onboarded to the **Microsoft Defender portal** (https://security.microsoft.com). After this step, do the Sentinel work there: open it and find **Microsoft Sentinel** in the left menu. If the Defender portal doesn't show Sentinel yet, the same steps work in the Azure portal's Sentinel page.

📸 Sentinel overview page showing the free trial.

## 4. Create the honeypot VM

Azure portal → *Virtual machines* → *Create* → *Azure virtual machine*
- Resource group: `rg-honeypot-lab`
- Name: `honeypot-vm`
- Image: **Windows Server 2022 Datacenter** (or 2025)
- Size: **B2s**
- Administrator account: a non-obvious username and a strong, random password
- Inbound port rules: **Allow selected ports → RDP (3389)**
- Leave the other defaults and create the VM.

Azure warns that RDP is open to the internet. For this lab, that's the point.

📸 VM overview page (blur the public IP).

## 5. Check the network security group (NSG)

VM → *Networking* → *Network settings*. You should see an inbound rule allowing **TCP 3389 from Any**. Don't add an allow-everything rule.

> **Interview point:** many older versions of this lab tell you to open all ports and turn off the Windows firewall. That isn't needed: automated scanners hit 3389 within minutes either way, and keeping the attack surface to one port is the safer design.

📸 The inbound 3389 rule.

## 6. Sign in once and note your own IP

RDP into the VM from your PC (VM → *Connect* → *RDP*). Then look up your own public IP (search "what is my IP"). Your logons will appear in the logs, and you'll want to tell them apart from attackers.

Also try **one wrong password** on purpose before signing in correctly. That gives you a known 4625 event to look for in step 8.

## 7. Connect the VM's security logs to Sentinel

Defender portal → *Microsoft Sentinel* → *Content management* → *Content hub*
1. Search **Windows Security Events**, select it, click **Install**.
2. Go to *Microsoft Sentinel* → *Configuration* → *Data connectors* → **Windows Security Events via AMA** → *Open connector page*.
3. Click **+ Create data collection rule**:
   - Name: `dcr-honeypot-security`
   - Resources: select `honeypot-vm`
   - Collect: **All Security Events**
4. Create it. This installs the **Azure Monitor Agent** on the VM and sends its Security log to `law-honeypot` (the `SecurityEvent` table).

📸 The connector page showing **Connected** with 1 resource.

## 8. Confirm logs are arriving (10–30 minutes)

Defender portal → *Investigation & response* → *Hunting* → **Advanced hunting** (or Azure portal → `law-honeypot` → *Logs*):

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
| order by TimeGenerated desc
```

You should see your deliberate wrong password from step 6. If nothing shows after 30 minutes, check the VM is running and the DCR in step 7 is linked to it (Azure portal → *Monitor* → *Data Collection Rules*).

📸 Query results showing 4625 events.

## 9. Let it run (24–72 hours)

Write down the exact time the VM went online; hunting query 2 uses it. Attacks usually begin within minutes to a few hours. Check in a few times with query 1 in `hunting/hunting_queries.kql`.

## 10. Create the analytics rules

Defender portal → *Microsoft Sentinel* → *Configuration* → **Analytics** → *+ Create* → **Scheduled query rule**. Do this once for each file in `detections/`:

| File | Name | Severity | Run every | Look back | Tactic |
|---|---|---|---|---|---|
| `01_brute_force.kql` | Honeypot - RDP brute force | Medium | 5 min | 10 min | Credential Access |
| `02_password_spray.kql` | Honeypot - Password spraying | High | 5 min | 10 min | Credential Access |
| `03_success_after_failures.kql` | Honeypot - Success after failed logons | High | 10 min | 1 hour | Credential Access, Initial Access |

For each one:
- **Rule logic:** paste the query.
- **Entity mapping:** *IP* → `IpAddress`; *Host* → `Computer` (and *Account* → `LoggedOnAs` on rule 03).
- **Alert threshold:** generate an alert when results > 0.
- **Suppression:** on, for 1 hour. The same attacker keeps going, and you want one incident per burst, not one every 5 minutes. (This is the same "one alert per burst" idea as the Python analyzer.)
- **Incident settings:** create incidents on; alert grouping by matching entities.

📸 The Analytics page listing your 3 rules.

## 11. Build the attack map workbook

Defender portal → *Microsoft Sentinel* → *Threat management* → **Workbooks** → *+ Add workbook* → **Edit** → the **</>** (Advanced Editor) button → replace everything with the contents of `workbook/attack_map_workbook.json` → *Apply* → **Save** as "Honeypot attack map" in `rg-honeypot-lab`.

**If the import gives an error**, build it by hand: *Add* → *Add query* → paste `workbook/attack_map.kql` → set **Visualization: Map** → *Map settings*: Location info = **Latitude/Longitude**, Latitude = `Latitude`, Longitude = `Longitude`, Size by = `FailedLogons`, Label = `Label` → *Done editing* → *Save*.

📸 The attack map (this is the screenshot people remember).

## 12. Investigate and collect results

**Triage at least one incident.** Defender portal → *Incidents & alerts* → *Incidents*. Open one of your honeypot incidents and note:
- which rule fired, the attacker IP and its country
- how many attempts, over what time span, and which usernames were tried
- the 4625 *SubStatus*: did the attacker guess usernames that don't exist, or a real username with wrong passwords? (hunting query 7)
- whether that IP ever logged on successfully (hunting query 8). On a honeypot it should only be you.
- what you'd do in a real company: block the IP at the firewall, restrict RDP to a VPN or Azure Bastion, enforce account lockout, require MFA

Then mark the incident **Closed**: *True positive*, with a short comment summarizing your findings.

📸 An incident's details page, and your closing comment.

**Run hunting queries 1–8** in `hunting/hunting_queries.kql` and copy the numbers into `RESULTS.md`.

**Cross-check with the Python analyzer** (optional but a great interview story):
1. Run hunting query 9 → export the results as CSV → save as `honeypot_export.csv`.
2. `python scripts/sentinel_to_analyzer.py honeypot_export.csv -o honeypot_events.json`
3. From your Security-Log-Analyzer folder: `python -m loganalyzer analyze path/to/honeypot_events.json --format windows`
4. Compare the IPs it flags with the incidents Sentinel created, and note any differences in `RESULTS.md`.

Don't commit the raw export. It contains your own IP and VM name; keep only the summarized results.

## 13. Tear it down

Once you have your results and screenshots:

Azure portal → *Resource groups* → `rg-honeypot-lab` → **Delete resource group** → type the name to confirm.

This deletes the VM, its disk, public IP, NSG, the workspace and the data collection rule, so nothing keeps billing. Check *Cost Management* a day later to confirm charges have stopped.
