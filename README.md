# Cyber Watch AI - Free Cloud Edition

Runs as a scheduled GitHub Actions workflow (every four hours by default). Monitors public security feeds + CISA Known Exploited Vulnerabilities catalog, scores items using transparent keyword heuristics, deduplicates using a SQLite database cached between workflow runs, sends new-item Telegram notifications (optional), and publishes a simple static dashboard snapshot in `docs/index.html`.

## Zero-cost deployment

1. Create a **public GitHub repository** (public repos are eligible for free GitHub Actions runners; GitHub free quotas/policies can change).
2. Upload the contents of this package into the repository root, including `.github/workflows/watch.yml` and `docs/`.
3. In repository **Settings → Pages**, select **Deploy from a branch**, branch `main`, folder `/docs`. Save. The dashboard will be at `https://YOURNAME.github.io/REPOSITORY/` once Pages is enabled.
4. (Optional Telegram) Create a bot via Telegram's `@BotFather`. Obtain your chat ID. Add repository secrets under **Settings → Secrets and variables → Actions**: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`. Both must be set for alerts.
5. Under **Actions**, enable workflows if prompted. Open **Cyber Watch AI** and choose **Run workflow** to test. Scheduled runs follow UTC; the workflow is every four hours at minute 15.

## What it watches

CISA advisories and news; BleepingComputer; The Hacker News; Krebs on Security; SANS ISC; Google Security Blog; Microsoft Security Blog; Cisco Security; Ubuntu security notices; CISA KEV JSON.

## Free tier / limitations

- No paid AI API or paid service is required. Its “AI” categorization is rules-based scoring; it does not claim LLM-generated analysis.
- GitHub Pages and Actions free usage/limits are subject to GitHub's current terms. Public repository runner usage is typically free.
- RSS/API sources may be down, change format, rate-limit, or fail. A run can still complete with partial sources.
- SQLite state is restored and cached across runs. Cache availability/retention isn't guaranteed; duplicates may reappear if cache is evicted.
- Dashboard is a public static page. Do not put secrets or private incident information in it.
- Heuristic scores are NOT CVSS severity. Validate advisories, exploit status and applicability against vendor/CISA sources.

## Modify cadence

Edit the `cron` expression in `.github/workflows/watch.yml`. GitHub Actions scheduled workflows may be delayed and are not real-time guarantees.

## Local manual run

`python watch.py` (Python 3.9+; standard library only). Without Telegram secrets it generates the dashboard and logs the run.
