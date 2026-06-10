# Helios Robotics Employee Handbook

## Our Mission

Helios Robotics builds autonomous inspection and logistics robots for industrial environments. Our mission is to eliminate dangerous and repetitive human labor through intelligent, safe, and reliable automation. Every team member is responsible for this mission — from the engineers building firmware to the operators deploying fleets in the field.

## Getting Started

New team members receive a laptop, badge, and access credentials on day one. Your onboarding buddy will walk you through our development environment, VPN setup, and fleet management console. All source code lives in our internal Git server. Ask your lead for repository access by your second morning.

Key accounts to set up on day one: SSO, VPN, fleet console, incident dashboard, and your Helios email alias.

## Communication Standards

We default to written communication. Use #engineering for technical discussions, #general for announcements, and direct messages only for personal matters. Meeting notes must be posted to the relevant channel within one hour. Decisions affecting more than one team require a written proposal posted at least 24 hours before any vote.

All external communications — press, partners, customers — must be reviewed by the communications team before sending. When in doubt, ask before you send.

## Security Policy

Helios handles sensitive robotics telemetry, customer fleet data, and operational credentials. All of this data is classified at minimum as `internal`. Data that could affect active deployments is `confidential`. Authentication credentials, signing keys, and customer contracts are `restricted`.

Access follows least-privilege: you get the minimum access needed for your role, and access is reviewed quarterly. Service credentials must be rotated every 90 days. Report any suspected breach immediately via the incident dashboard — do not wait until your next standup.

## Release Process

All production releases follow a four-step gate: feature freeze, code freeze, staging deployment, and a 48-hour soak. No exceptions without written sign-off from both the engineering lead and the platform architect. Hotfixes skip the 48-hour soak but still require two approvals and must be followed by a full postmortem within 72 hours.

Releases are tagged in Git and automatically archived in the release registry. Rollback procedures are documented per service in the engineering spec.

## Incident Response

When something breaks in production, time to triage matters more than certainty. Open an incident ticket immediately — even if you only have a hunch. Use the P1/P2/P3 severity scale: P1 means robots are stopped or data is at risk, P2 means degraded service, P3 means minor nuisance.

All P1 and P2 incidents result in a postmortem within five business days. The postmortem template lives in the incident dashboard. Past postmortems are searchable in the incidents crux — read them before you write a new one.
