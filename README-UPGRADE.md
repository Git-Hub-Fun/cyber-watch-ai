# Cyber Watch AI — free cloud agent upgrade

This upgrade adds:
- SQLite-persisted feed health (last attempt/success, status, count, error, consecutive failures).
- Retry-on-failure with exponential backoff for feed fetches.
- EPSS enrichment via FIRST API for detected CVE IDs.
- Optional Gemini AI analyst summary (key supplied via GitHub secret).
- Optional Telegram alerts for newly detected items meeting priority threshold (default 8/10).
- Dashboard sections for agent status, feed health, AI analysis, and EPSS information.

## Deploy (GitHub Actions)
1. Copy `watch.py` and `.github/workflows/monitor.yml` into the root of your repository, replacing the prior collector and workflow.
2. Repository Settings → Actions → General → Workflow permissions: select **Read and write permissions**.
3. GitHub Actions workflow runs every 15 minutes and can also be manually started from Actions.
4. Enable GitHub Pages: Settings → Pages → Deploy from branch → `main` / `docs`.
5. Repository Settings → Secrets and variables → Actions → add optional secrets described below.

## Optional secrets
- `TELEGRAM_BOT_TOKEN`: bot token from BotFather.
- `TELEGRAM_CHAT_ID`: your chat or group ID. Send the bot a message first; use Telegram's bot API to obtain the chat ID.
- `GEMINI_API_KEY`: Gemini API key for AI analysis. AI is optional; without it the dashboard explains the setting is absent.

Telegram notifications only trigger on newly collected items whose heuristic priority is >= 8 by default. Adjust `TELEGRAM_MIN_SCORE` in workflow if desired.

## Important limits / safety
- This is a scheduled cloud collector (not a permanently resident process); GitHub scheduled jobs may be delayed, and free quotas/availability can change.
- AI analysis is best-effort and may fail when API quota is exhausted. Treat generated recommendations as analyst assistance, not verified facts.
- EPSS is best-effort; missing EPSS values are not treated as zero-risk.
- Dashboard hosted on GitHub Pages is public. Do not place secrets, private indicators, internal telemetry, or sensitive incident data in this feed or dashboard.
- SQLite is persisted by committing `state.db` into the repository. This is suitable for this lightweight collector, not a production multi-user database.
- Monitor GitHub Actions runs for errors and periodically back up the repository.
