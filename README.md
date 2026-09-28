# BnB — PhishGuard

This repository contains **PhishGuard**, a real-time, fully local, deterministic phishing
detection system. The application lives in the [`phishguard/`](phishguard/) directory.

## Get started

The complete, copy-paste run instructions (Linux **and** Windows) are in:

**➡️ [`phishguard/README.md`](phishguard/README.md)**

Fast path (Docker, from a fresh clone):

```bash
git clone https://github.com/Bharaths31/BnB.git
cd BnB/phishguard
cp .env.example .env          # Windows PowerShell: Copy-Item .env.example .env
docker compose up -d --build
```

Then open the dashboard at <http://localhost:3000>, Roundcube at <http://localhost:8080>
(`victim@demo.local` / `changeme`), and the API docs at <http://localhost:8000/docs>.

## Contents

| Path | Description |
|---|---|
| `phishguard/` | The application (backend, detection pipeline, dashboard, plugin, tests). See its [README](phishguard/README.md). |
| [`extension_plan.md`](extension_plan.md) | Implementation & improvement plan (13 workstreams, phased). |
| [`implementation_plan.md`](implementation_plan.md) | Original detailed build plan. |
| [`PSN013_phishing_detection_build_plan.md`](PSN013_phishing_detection_build_plan.md) | Source specification. |

## Principles

- CPU-only, local, Docker-compatible, deterministic where possible.
- No generative LLM / chatbot / autonomous agent / prompt-based classifier.
- Email content is **untrusted data**, never instructions.
- Every detector emits typed evidence; every verdict is explainable.
