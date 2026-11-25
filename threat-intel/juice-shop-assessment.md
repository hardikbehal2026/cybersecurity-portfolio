# Vulnerability assessment: OWASP Juice Shop

MCSC-6001 (Advanced Network Security), Fall 2026. My part of a group project on protecting an online store without breaking it: a static vulnerability assessment of OWASP Juice Shop, to answer which weaknesses a WAF (ModSecurity / OWASP CRS) can mitigate and which need an application fix.

## Target and method

- **Target:** https://github.com/juice-shop/juice-shop, commit `1618a611b173b4bf114028e6e02549950606e29d` (2026-08-10)
- **Scan date:** 2026-10-03
- **Scan type:** static analysis only — no running application was attacked.
- **Tools:** Semgrep 1.176.0 (javascript, typescript, nodejs, owasp-top-ten, secrets rule packs) and Trivy 0.75.0 (vulnerability, secret, and misconfiguration scanners).

## Results at a glance

| Source | Findings |
| --- | --- |
| Dependency vulnerabilities (Trivy) | **84** — 9 Critical, 42 High, 28 Medium, 5 Low (78 unique advisories, 26 packages) |
| Static analysis (Semgrep) | **43** — 13 ERROR, 28 WARNING, 2 MEDIUM |
| IaC / Dockerfile misconfigurations (Trivy) | **89** |
| Secrets (Trivy) | **5** |

Worst packages by advisory count: tar (12), multer (11), jsonwebtoken (10), sanitize-html (9), lodash (5), decompress (4).

## Critical dependency findings

- **crypto-js** (CVE-2023-46233) — PBKDF2 1,000× weaker than specified; fix in 4.2.0.
- **jsonwebtoken** (CVE-2015-9235) — signature-verification bypass with an altered token; fix in 4.2.2.
- **lodash** (CVE-2019-10744) — prototype pollution in `defaultsDeep`; fix in 4.17.12.
- **marsdb** — command injection, **no fix available**.
- **decompress** — path traversal via symlink chain, **no fix available**.
- **tar** (CVE-2026-59873) — denial of service via crafted gzip bomb; fix in 7.5.19.

## Code findings (confirmed by reading the flagged lines)

| Weakness | Location |
| --- | --- |
| SQL injection (login) | `routes/login.ts:34` — query built with a template string containing `req.body.email` |
| SQL injection (search) | `routes/search.ts:23` — LIKE clause built from `req.query.q` |
| Code injection via `eval()` | `routes/userProfile.ts:65` — `eval()` on user-derived input |
| Path / file access | `routes/fileServer.ts` and others — `res.sendFile` with a user-supplied file name |
| Directory listing enabled | `server.ts:268-300` — serve-index mounted on `/ftp`, `/encryptionkeys`, `/support/logs`, and more |
| Open redirect | `routes/redirect.ts:18` — substring allow-list check that can be bypassed |
| Hard-coded JWT signing key | `lib/insecurity.ts:21` and `:54` — RSA private key committed in source |

Also found: shell injection in GitHub Actions workflows, a `curl | sh` install step in `ci.yml:359`, 7 third-party actions pinned to mutable tags, and private keys in `terraform/networking.tf:171`. Top IaC issue: unrestricted egress (AWS-0104, 15× CRITICAL).

## What this means for the WAF question

**Defence in depth — fix the code first, and use the WAF as a compensating control while fixes ship. Never "just a WAF."**

| Weakness | Can ModSecurity/CRS help? | Real fix |
| --- | --- | --- |
| SQL injection | Yes for common payloads (CRS 942xxx) | Parameterized queries / ORM bindings |
| Reflected / DOM XSS | Partly (CRS 941xxx) | Output encoding, CSP headers |
| Path traversal via sendFile | Yes for `../` variants (CRS 930xxx) | Resolve and verify paths stay under the base directory |
| `eval()` on user input | Partly, only if a signature matches — not reliable | Remove `eval()`; use a safe parser |
| Directory listing, hard-coded key | No — these are valid requests or internal flaws | Disable serve-index; load keys from a secret store; rotate |
| Vulnerable dependencies | Only virtual patching of known exploit strings | Upgrade packages; commit a lockfile; scan automatically |

## Limitations — read these first

- Juice Shop is an **intentionally insecure training application**. Most findings are deliberate and match its built-in hacking challenges. This report treats them as real defects to answer the project question.
- The lockfile was generated in a scratch copy (`package-lock=false` in the repo), so installed versions on a real deployment may differ.
- Semgrep reported **41 parse/timeout errors**, mostly in challenge snippets and frontend files — those files were not fully analyzed.
- Counts are inflated by duplicate Terraform directories, and **10 of the 43 Semgrep findings are in teaching codefixes** (`data/static/codefixes/`).
- Nothing was verified dynamically. Findings are scanner output; only the items in the table above were confirmed by reading the source. Scanners can produce false positives.
