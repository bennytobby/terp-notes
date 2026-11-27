---
name: verify
description: Boot terp-notes locally with a throwaway database and drive one real flow (sign in, find a note, check phone width) before saying a change is done. Use before calling any terp-notes change finished, and when asked to check that the app still works.
---

# Verify terp-notes

Checks passing is not the same as the app working. Before you say a change is done, boot the app and use it like a student would. This file is kept next to the code: when a flow changes, change this skill and `e2e/verify.spec.js` in the same PR.

## 1. Boot and drive the flow

```sh
NODE_ENV=development npm install --include=dev   # once per worktree
npm run verify
```

`npm run verify` (`scripts/verify.js`) starts an in-memory MongoDB, starts the app on port 3311 with test-only settings (the same as `playwright.config.js`), and runs `e2e/verify.spec.js`:

1. A verified student signs in and lands on the dashboard with their name in the sidebar.
2. Two classmates' notes are there; searching "dijkstra" narrows the list to one.
3. At 390 px wide the page still shows the note and nothing scrolls sideways.

It saves `test-results/verify/dashboard-desktop.png` and `dashboard-phone.png`. **Open both and look at them**; a passing run with a broken-looking page is a failure.

Nothing real is touched: no Atlas, S3, email or VirusTotal. The first run downloads a MongoDB binary (~80 MB) into `~/.cache/mongodb-binaries`.

## 2. Drive the flow you changed

The verify flow is the floor. If your change touched another flow, drive that one too:

- **An existing spec covers it:** `npm run verify -- e2e/<name>.spec.js` runs it against the same throwaway database (`npm run verify -- e2e/` runs them all). Specs that need S3 (upload, dashboard, direct upload, study buddy) skip unless `AWS_S3_ENDPOINT` points at an S3 stand-in, which CI has and this Mac doesn't; say so in your wrap-up rather than claiming they ran.
- **By hand:** `npm run verify -- --serve` keeps the app up at http://127.0.0.1:3311 and prints a test sign-in. Click through with Nova's browser (`browser_open`, `browser_screenshot`) or Playwright, then stop it with Ctrl-C (or kill that process by its PID).
- **A flow students rely on changed shape:** update `e2e/verify.spec.js` and this file so the next agent checks the new shape.

## 3. Report it

Put what you saw in the PR and your wrap-up: the `N passed` line, the two screenshots (or what they showed), and anything you couldn't drive and why. Then name it on the `Verified by:` line, for example `Verified by: e2e, manual: verify skill (sign in, search, 390 px)`.

## Rules

- Never point this at production or the real database: no `BASE_URL`, no Atlas connection string. `npm run test:live` is the read-only check for production.
- Don't fake a service inside the app to make a flow pass. If something needs S3 or email, test what you can and say what you didn't.
- Never weaken sign-in, the UMD email check, file-type allow-listing or virus scanning to make the flow work.

## If it won't boot

- **`Cannot find module 'mongodb-memory-server-core'` or `@playwright/test`:** your shell has `NODE_ENV=production`, so npm skipped dev dependencies. Run the install line above.
- **Port 3311 or 3399 in use:** another run is still up; stop it, or wait for it.
- **Playwright can't find a browser:** `npx playwright install chromium`, or set `CHROME_PATH` to an installed Chrome.
- **Node version warning:** the app targets Node 22 (`engines`); Node 26 worked on 2026-11-26. If something fails only on a newer Node, say so.
