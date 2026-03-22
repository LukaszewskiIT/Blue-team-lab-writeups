# KC7 Cyber Detective Game – Rap Beef

## Overview
This write-up documents my work on **Rap Beef**, an introductory investigation on the KC7 platform.

The scenario is built around a fictional feud between two hip-hop artists. What starts as a themed and slightly humorous case turns into a basic security investigation involving phishing, exposed sensitive information, and account compromise.

For me, this lab felt more like a guided walkthrough than a difficult challenge, but it was still a good way to explore how KC7 presents investigations and how KQL can be used in that workflow.

---

## Scenario Summary
In this scenario, I took the role of a security analyst at **OWL Records**. The investigation focused on suspicious activity connected to a rap feud, where oversharing in song lyrics and follow-up phishing activity eventually led to unauthorized access.

The lab revolved around:
- reviewing email activity for phishing indicators,
- identifying suspicious domains and IP addresses,
- connecting exposed personal information to account compromise.

---

## What the Lab Covered
This investigation introduced several basic blue team concepts, including:

- using **KQL** to query available data,
- analyzing emails for phishing-related activity,
- tracking infrastructure used by the threat actor,
- following the chain from information exposure to account takeover.

---

## Investigation Notes
### Email and Phishing Analysis
Briefly describe how you reviewed the available email-related data and what stood out.

### Threat Infrastructure
Add notes here about the suspicious IP addresses, domains, and how they were connected to the phishing activity.

### Key Finding
One of the more memorable parts of the scenario was that sensitive information was exposed in a rap verse, which later played a role in the compromise of the account.

---

## Queries Used
```kql
// Paste your KQL queries here
