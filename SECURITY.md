# Security Policy

## Reporting a vulnerability

**Do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.** A public report gives an attacker a head start and
a permanent public record of an unfixed issue.

Please report privately through GitHub's **"Report a vulnerability"** link on
this repository's Security tab (**Security → Report a vulnerability**). That
route creates a private advisory visible only to the maintainers, which is the
recommended channel for any repository hosted on GitHub and requires no email
address to be published in this file.

If private advisory reporting has been disabled on this repository, contact the
project maintainer directly using the contact details published on the
repository owner's GitHub profile.

Please include, to the extent you can:

- what the issue is, and which crate or component it affects;
- how to reproduce it (a test, a sequence of commands, or a configuration);
- what an attacker gains, and what access they need to get it;
- any crash output, logs, or protocol traces you captured.

## What to expect

- An acknowledgement of receipt.
- An assessment of severity and exploitability.
- A statement of whether the report is accepted, and a target for remediation
  or for further discussion.

There is currently no formal bug-bounty programme. That is a known gap, tracked
in `CipherSettle_Audit_Remediation_Roadmap.md`.

## Known open security items

This project does not claim to be production-ready, and its own assessments
list open findings. Before relying on it, read these in full:

- `SECURITY_REVIEW.md` — technical security assessment, with findings R-1
  through R-7 and a cryptographic peer-review checklist.
- `docs/security/THREAT_MODEL.md` — assets, actors, trust boundaries, and the
  attack-path table (T-1 … T-12).
- `CipherSettle_Audit_Remediation_Roadmap.md` — findings A1–A15 and their
  remediation status, including an open architectural gap (§6a) that is
  load-bearing for the system's central claim.
- `README.md` §"What's real vs. still open".

Independent cryptographic peer review has not yet been performed. This is
stated plainly rather than omitted, and is the single largest gap in the
project's assurance case.

## Scope

This project is **infrastructure software, not a regulated financial service.**
It does not move money, does not decide invoice validity, and does not perform
double-financing checks — those belong to the factoring company and to Egypt's
Financial Regulatory Authority respectively. See `README.md` §"What this
project claims — and deliberately does not".

Security reports about it should be understood in that light: the confidentiality
of invoice terms from infrastructure operators, and the integrity of the
tamper-evident access record, are what is in scope.