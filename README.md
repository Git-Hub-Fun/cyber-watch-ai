# Cyber Watch AI — Free Cloud Edition

A GitHub Actions scheduled public-source security intelligence collector and static dashboard. It checks RSS feeds and CISA's KEV JSON catalog every 15 minutes, stores history in SQLite, generates a source-filterable landing page, and optionally sends Telegram summaries.

## Sources / tabs
CISA advisories, CISA KEV, NVD CVE RSS, BleepingComputer, The Hacker News, Krebs on Security, SANS ISC, Google Security Blog, Microsoft Security Blog, Cisco Security, Exploit-DB, Packet Storm.

## Setup
1. Create a **public** GitHub repository (for easiest free scheduled Actions use; review GitHub's current limits/policies).
2. Upload the contents of this folder into the repository root, including `.github/workflows/watch.yml` and `docs/`.
3. In Actions, enable workflows and run **Cyber Watch AI** once manually.
4. For Telegram, set repository Actions secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
5. To publish dashboard, Settings → Pages → Deploy from a branch → `main` → `/docs`.

The workflow runs on a 15-minute cron (GitHub schedule timing is not guaranteed). It commits `state.db` and the dashboard snapshot back into the repository to retain deduplication/history between runs. Feed failures are logged and skipped.

Priority score is keyword-based and is not a CVSS rating. Dashboard items are public-source information. Do not put private incident data or secrets into the repository. This is passive feed collection; it does not scan or exploit systems.
