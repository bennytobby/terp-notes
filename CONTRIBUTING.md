# Contributing to Terp Notes

Thanks for helping out. This guide covers running the app on your own machine. For what the app does, see the [README](README.md).

## Prerequisites

- **Node.js 18 or newer** (`node -v` to check)
- **npm** (comes with Node)
- **A MongoDB database.** A free [MongoDB Atlas](https://www.mongodb.com/atlas) cluster works, or a local `mongod` (`mongodb://localhost:27017`).
- **An AWS S3 bucket** and an IAM key that can read and write to it. File uploads and downloads go straight to S3, so without one you can browse the app but can't upload.

Optional, for specific features:

- [Resend](https://resend.com) API key: sends verification and notification emails
- [VirusTotal](https://www.virustotal.com) API key: scans uploaded files
- Google, Microsoft and Notion OAuth apps: power the Integrations page

## 1. Clone and install

```bash
git clone https://github.com/bennytobby/terp-notes.git
cd terp-notes
npm install
```

There's no lockfile in the repo (`package-lock.json` is gitignored), so `npm install` resolves fresh versions.

## 2. Create a `.env` file

The server reads environment variables from a `.env` file in the repo root. It's gitignored, so never commit it and never paste real keys into issues or PRs.

```bash
# --- Required ---
MONGO_CONNECTION_STRING=mongodb+srv://<user>:<password>@<cluster>/?retryWrites=true&w=majority
MONGO_DB_NAME=terpnotes_dev
MONGO_FILECOLLECTION=files
MONGO_USERCOLLECTION=users

AWS_ACCESS_KEY_ID=<your-key-id>
AWS_SECRET_ACCESS_KEY=<your-secret>
AWS_REGION=us-east-1
AWS_S3_BUCKET=<your-dev-bucket>

# Signs session cookies and JWTs. Any long random string, e.g. `openssl rand -hex 32`
SECRET_KEY=<random-string>

# --- Recommended ---
BASE_URL=http://localhost:3000
PORT=3000

# --- Optional ---
RESEND_API_KEY=            # emails (verification, upload confirmations)
VIRUSTOTAL_API_KEY=        # virus scanning; disabled when unset
ADMIN_EMAIL=               # where support and moderation emails go
CRON_SECRET=               # protects /api/cron/* endpoints

# Integrations (Google Docs, OneNote, Notion)
OAUTH_STATE_SECRET=<random-string>
INTEGRATION_ENCRYPTION_KEY=<random-string>
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
MICROSOFT_CLIENT_ID=
MICROSOFT_CLIENT_SECRET=
NOTION_CLIENT_ID=
NOTION_CLIENT_SECRET=
```

Notes:

- **Use separate dev resources.** Point `MONGO_DB_NAME` and `AWS_S3_BUCKET` at a database and bucket you can safely wipe, not production.
- **Keep `BASE_URL` on `http://`** locally. If it starts with `https`, or `NODE_ENV=production` is set, session cookies are marked `secure` and the browser won't send them over plain HTTP, so you'll keep getting logged out.
- **Leave `NODE_ENV` unset** locally. In production mode, verification links are built from `VERCEL_URL` instead of your local host.
- **S3 CORS:** uploads go straight from the browser to S3 using presigned URLs, so the dev bucket's CORS config must allow `PUT` and `GET` from `http://localhost:3000`.
- **OAuth redirect URIs** are `${BASE_URL}/auth/google/callback`, `/auth/microsoft/callback` and `/auth/notion/callback`. Register those with each provider if you're working on integrations.

If a required variable is missing, the server logs `Missing required environment variables: ...` on startup.

## 3. Run it

```bash
npm run dev     # auto-restarts on file changes (nodemon)
# or
npm start       # plain `node server.js`
```

Then open <http://localhost:3000>. You should see `Terp Notes Server running on port 3000` in the terminal. If MongoDB can't be reached, the process exits during integration setup, so check your connection string first.

## 4. Create a test account

Sign-up only accepts `@umd.edu` and `@terpmail.umd.edu` addresses, and new accounts must verify their email before they can log in.

- **With `RESEND_API_KEY` set:** register with your UMD email and click the link you get.
- **Without it:** no email is sent. Register, then mark the user as verified in MongoDB:

  ```js
  // mongosh, against your dev database
  db.users.updateOne({ userid: "<your-username>" }, { $set: { isVerified: true } })
  ```

New users get the `contributor` role. To try the admin dashboard (`/admin`), set `role: "admin"` on your user the same way.

Use the collection name you set in `MONGO_USERCOLLECTION` if it isn't `users`.

## Course and professor data

Autocomplete for classes and professors comes from the JSON files in `data/`, built from the public [UMD.io](https://umd.io) API. A GitHub Action refreshes them on a schedule, so you usually don't need to touch them. To rebuild them yourself:

```bash
node scripts/generate-optimized-cache.js
```

It makes a lot of API calls and takes a while. Don't commit regenerated cache files in an unrelated PR.

## Making changes

1. Branch off `main`: `git checkout -b <short-description>`.
2. Keep each PR to one change.
3. There's no automated test suite or linter yet. Before opening a PR, start the server, click through every flow you touched, and check the page at phone width (390 px) as well as desktop. Put what you tested, plus screenshots for UI changes, in the PR description.
4. If you change uploads, S3 or `multer`, test a real upload and download end to end.
5. Don't weaken the UMD email check, the file-type allow-list or virus scanning. Open an issue to discuss first if you think one of them needs to change.

## Project layout

| Path | What's there |
| --- | --- |
| `server.js` | The Express app: routes, auth, uploads, admin, cron endpoints |
| `views/` | EJS templates (`views/mobile/` holds the mobile variants) |
| `public/`, `styles/` | Static assets and CSS |
| `integrations/` | Google Docs, OneNote and Notion clients plus the OAuth manager |
| `models/` | MongoDB models (encrypted integration tokens) |
| `middleware/`, `utils/` | Session timeout, password rules, file conversion |
| `emails/templates.js` | HTML email templates |
| `data/`, `scripts/` | Cached UMD.io data and the script that builds it |
| `vercel.json` | Vercel deployment and cron config |

## Reporting bugs

Open a GitHub issue with steps to reproduce, what you expected, and what happened. For security problems, use the [contact form](https://terp-notes.org/contact) instead of a public issue.
