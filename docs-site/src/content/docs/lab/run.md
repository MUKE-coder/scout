---
title: Run the lab
description: Clone the Scout repo and start the deliberately-vulnerable lab app on localhost.
---

The lab lives in the Scout repo under `lab/`. It is a Next.js app that runs on
port 4000.

:::danger
Localhost only. The lab is intentionally insecure — never deploy or expose it.
:::

## Start it

```bash
git clone https://github.com/MUKE-coder/scout
cd scout/lab
npm install
npm run dev        # http://localhost:4000
```

Open [http://localhost:4000](http://localhost:4000) and click a lab. Each page
explains its weakness and the fix.

## What you should see

A dark landing page listing the labs (IDOR, BAC, XSS, CSRF, JWT, redirect, CORS)
and, behind the scenes, a set of deliberately-vulnerable API routes and exposed
files that the Scout checks target.

## Now scan it

With the lab running, from the repo root:

```bash
# black-box scan of the running app
go run ./cmd/scout scan --target http://localhost:4000 --mode active --env dev

# source scan: committed secrets, the insecure Dockerfile, weak crypto …
go run ./cmd/scout scan --repo ./lab --mode safe --env dev
```

Continue with [Black-box scan](/lab/black-box/) and [Source scan](/lab/source/).
