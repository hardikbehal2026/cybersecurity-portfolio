# MISP threat intelligence lab

MCSC-6003 (Advanced Threat Intelligence & Analysis), November 2026. I deployed MISP on Azure, turned on threat feeds, and built a custom event for a phishing campaign.

## Deployment

- Azure for Students subscription, resource group `RG-MISP-Lab`, region Canada Central.
- The subscription had 0 vCPU quota for regular VMs, so I used a **Spot VM**: Standard_D2s_v7 (2 vCPU, 8 GB RAM), Ubuntu Server 22.04 LTS, 64 GB disk, public IP `20.220.210.117`.
- MISP **2.4.222** installed with the official installer (all components, unattended). Apache and MariaDB verified running; login page reachable over HTTPS (port 443 opened in the network security group).
- The admin password was changed from the default, and the base URL was set to the VM's public IP.
- The VM was stopped (deallocated) after the lab, so nothing is still running.

## Threat feeds (Part 5)

I loaded the 88 default feeds, then enabled and fetched three of them, covering all three required categories:

| Feed | Category | Result |
| --- | --- | --- |
| Tor exit nodes (Feed 5) | IP / network | 1 event imported — 2,141 attributes |
| Phishtank online valid phishing (Feed 8) | URL / phishing | 1 event imported — 42,645 attributes |
| Threatview.io — MD5 Hash Blocklist (Feed 80) | Malware hash | 1 event imported — 9,761 attributes |

Real indicators pulled from the feeds included the URLs `https://acesso.chatcomgerente.digital/`, `https://bradesco.solucaoempresa.digital/`, `https://bradesco.renovacaoempresa.pro/`; the IPs `102.130.113.9`, `102.130.117.167`, `102.130.127.117`; and MD5s starting `0000a3de…`, `0010c09e…`, `001364f4…`.

**What didn't work:** the MalwareBazaar (Feed 64) and URLhaus (Feed 65) feeds failed. abuse.ch retired those free file exports on 21 October 2026 — the URLs now return HTTP 410 Gone and need a free abuse.ch auth key. The Threatview MD5 feed covered the malware category instead.

## Custom event (Part 6)

Created a phishing campaign event — **Event 4, "LAB-Phishing Campaign - 2026-11-24"**, distribution "Your organization only", analysis Complete, not published. It has all six indicators from the lab manual:

| Attribute | Type | Value |
| --- | --- | --- |
| File hash | MD5 (Payload installation) | `d41d8cd98f00b204e9800998ecf8427e` |
| Source IP | ip-src | `203.0.113.25` |
| Destination IP | ip-dst | `198.51.100.42` |
| Domain | domain | `secure-login-example.test` |
| Domain | domain | `update-service-example.test` |
| Context | text | Phishing campaign targeting finance users, credential harvesting via a fake login page, compromised account used for remote access |

## Honest limits

- SSH from my own laptop never connected — the network security group only allowed SSH from one IP, and mine had changed. The install and the feed/event work were done through the Azure portal's Run Command instead, and the event itself was created through the MISP REST API, not the web UI.
- The MISP web UI never rendered in my browser (self-signed certificate interstitial), so the work was verified through the API and the server logs.
- First Seen / Last Seen was not recorded for the custom event.
- I could not log in to MISP as a normal user to take the "Add Event" form screenshot the manual asks for, for the same certificate reason.
