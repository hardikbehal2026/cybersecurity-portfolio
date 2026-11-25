# cybersecurity-portfolio

Cybersecurity coursework from my Master of Computer Science (Cybersecurity Operations and Management) at Humber Polytechnic, Toronto.

I'm Hardik Behal, a master's student working towards a SOC analyst role. This repo holds the hands-on work from my first two semesters — the code I wrote, not just the theory.

## What's inside

| Folder | What it is |
| --- | --- |
| `secure-python-labs/` | Six Python labs from MCSC-6002 (Cybersecurity Architecture, Design & Secure Software Development): secure storage, authentication, access control, input validation, hashing/anti-tampering, and public-key cryptography. |
| `devsecops-assignment/` | MCSC-6002 assignment: fixing a vulnerable Python app (Bandit scan to zero findings) and building a small secure patient-registration app with tests. |
| `threat-intel/` | Write-ups from MCSC-6003 (Advanced Threat Intelligence & Analysis): deploying MISP on Azure and using threat feeds, plus a static vulnerability assessment of OWASP Juice Shop. |

## A note on the code

These are coursework lab prototypes, written in pure Python standard library so they run anywhere. They are **teaching demos, not production code**. Where a lab uses demo cryptography — for example a SHA-256 keystream XOR in place of real encryption, or PBKDF2 as a stand-in for bcrypt — the file says so in its own header, and the folder READMEs say it again. In a real system you would use a vetted library, proper key management, and audited code. Don't copy these into anything that handles real data.

## Tools used

Python 3 (standard library only), Bandit, pytest, Semgrep, Trivy, MISP 2.4, Microsoft Azure.
