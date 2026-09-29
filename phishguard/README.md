# PhishGuard

PhishGuard is a **real-time, fully local, deterministic** phishing-detection system. It connects
directly to an IMAP mailbox, monitors it for new mail, and evaluates every message with a
modular, CPU-only detection pipeline. It is designed to be **explainable**, **reproducible**,
and **immune to prompt injection** (no generative LLM is used anywhere).

- Runs entirely on **CPU**, locally, inside Docker.
- Every detector emits structured **evidence**; every verdict carries reasons.
- Deterministic fallbacks mean the pipeline still runs when an optional dependency (ONNX model,
  OCR runtime, `mailparser`, …) is unavailable.

---

## Table of contents

1. [Architecture](#architecture)
2. [Repository layout](#repository-layout)
3. [Prerequisites](#prerequisites)
4. [Quick start (Docker) — Linux](#quick-start-docker--linux)
5. [Quick start (Docker) — Windows](#quick-start-docker--windows)
6. [Accessing the services](#accessing-the-services)
7. [Everyday operations](#everyday-operations)
8. [Configuration](#configuration)
9. [Optional: export the ONNX models](#optional-export-the-onnx-models)
10. [Sending demo emails](#sending-demo-emails)
11. [Running without Docker (local dev)](#running-without-docker-local-dev)
12. [Running the test suite](#running-the-test-suite)
13. [Troubleshooting](#troubleshooting)
14. [Security notes](#security-notes)
15. [Training / fine-tuning models](#training--fine-tuning-models)

---

## Architecture

| Service | Image / runtime | Purpose | Port(s) |
|---|---|---|---|
| `mailserver` | `mailserver/docker-mailserver` (Postfix + Dovecot) | Test IMAP/SMTP server | 25, 143, 587, 993 |
| `roundcube` | `roundcube/roundcubemail` | Webmail UI + PhishGuard banner plugin | 8080 |
| `backend` | Python 3.11 + Uvicorn (FastAPI) | IMAP IDLE watcher + detection pipeline + API | 8000 |
| `dashboard` | Node 20 + Vite/React | Live verdict dashboard | 3000 |

**Detection pipeline** (`guard/`):

- **Header / authentication rules** — SPF/DKIM/DMARC and header anomalies.
- **Text classifier** — DistilBERT phishing classifier via ONNX (deterministic keyword fallback
  when the model is not present).
- **URL analysis** — lexical features + lookalike/brand distance.
- **Cross-modal consistency** (`guard/multimodal/`) — display-vs-href, Reply-To, brand/domain
  lookalikes, OCR/QR vs text, subject/body, attachment context.
- **HTML structural analysis** (`guard/html/`) — static (never executes JS) forms, obfuscation,
  hidden text, external resources, contextualised so complexity alone is never malicious.
- **Attachment analysis** (`guard/attachment/`) — magic-byte sniffing, Office/PDF/SVG static
  inspection, archive bomb protection (never executes attachments).
- **Behavioral profiling** (`guard/behavioral/`) — per-sender and per-relationship history using
  robust median/MAD statistics, persisted in SQLite, with poisoning-prevention update policy.
- **Intent features** (`guard/nlp/intent.py`) — canonical tactic labels + derived intent scores.
- **Evidence system** (`guard/evidence/`) — every finding is a typed `Evidence` object.
- **Fusion + uncertainty** (`guard/fusion/`) — calibrated probability, component agreement,
  and decision levels `ALLOW` / `FLAG` / `REVIEW` / `BLOCK`.
- **Explanation engine** (`guard/explainer/`) — deterministic, evidence-ranked explanations.

---

## Repository layout

```
BnB/                              ← git repository root
├── .gitignore
├── extension_plan.md             ← implementation & improvement plan
├── implementation_plan.md
├── PSN013_phishing_detection_build_plan.md
└── phishguard/                   ← the application (run everything from here)
    ├── docker-compose.yml
    ├── Dockerfile.backend
    ├── Dockerfile.dashboard
    ├── manage.py                 ← convenience wrapper (start/stop/models/demo)
    ├── requirements.txt
    ├── .env.example              ← copy to .env (required by docker compose)
    ├── config/
    │   ├── policy.yaml           ← thresholds, brands, limits
    │   └── mailserver/           ← demo mail accounts
    ├── guard/                    ← backend + detection pipeline
    │   ├── api/                  ← FastAPI app & routes
    │   ├── watcher/              ← IMAP IDLE watcher
    │   ├── parse/  headers/  nlp/  url/
    │   ├── evidence/  html/  attachment/  behavioral/  multimodal/
    │   ├── fusion/  explainer/  store/
    │   ├── component.py  pipeline.py  models.py  config.py
    ├── dashboard/                ← React (Vite) dashboard
    ├── roundcube_plugin/         ← Roundcube plugin
    ├── scripts/                  ← demo mail, model export, setup
    └── tests/                    ← pytest suite
```

---

## Prerequisites

Install these **before** you start. Docker is the only hard requirement for the full stack.

| Tool | Minimum | Needed for | Check |
|---|---|---|---|
| Git | 2.30+ | cloning | `git --version` |
| Docker Engine + Compose v2 | Docker 20.10+ / Desktop 4+ | full stack | `docker --version` and `docker compose version` |
| Python | 3.11+ | local backend / tests / model export | `python --version` |
| Node.js | 20+ | local dashboard only | `node --version` |
| Free disk | ~4 GB | images + model export | — |
| Free ports | 25, 143, 587, 993, 3000, 8000, 8080 | service binding | — |

### Install prerequisites

**Linux (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl

# Docker Engine + Compose plugin (official convenience script)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"      # log out / back in for this to apply
docker --version
docker compose version
```

**Windows (PowerShell, run as Administrator):**

```powershell
# Install via winget (Windows 11 / updated Windows 10)
winget install --id Git.Git -e
winget install --id Python.Python.3.11 -e
winget install --id OpenJS.NodeJS.LTS -e
winget install --id Docker.DockerDesktop -e

# Then launch Docker Desktop once so the engine starts, and re-open your terminal.
docker --version
docker compose version
```

> **Windows + Docker:** enable the **WSL 2** backend in *Docker Desktop → Settings → General*.
> "\<command not found\>" for `docker`/`python` usually means the terminal was opened before the
> PATH was updated — close and reopen it.

---

## Quick start (Docker) — Linux

Copy/paste these blocks in order.

### 1. Clone and enter the project

```bash
git clone https://github.com/Bharaths31/BnB.git
cd BnB/phishguard
```

### 2. Create the environment file

`docker compose` reads `.env` (which is intentionally **not** committed). Create it from the
template:

```bash
cp .env.example .env
```

### 3. Build and start the stack

```bash
docker compose up -d --build
```

First run downloads/builds images (this can take several minutes).

### 4. Wait for the backend to be healthy

```bash
# follow backend logs until you see "Watchers started"
docker compose logs -f backend
# press Ctrl+C to stop following (containers keep running)
```

### 5. (Optional) export the ONNX text model

The system runs without it (deterministic fallback). Export it for the full model:

```bash
python3 manage.py setup_models
```

### 6. Send the demo emails

```bash
python3 scripts/send_demo_mail.py --type all --smtp-host localhost
```

### 7. Open the UI

- Dashboard: <http://localhost:3000>
- Webmail (Roundcube): <http://localhost:8080> — log in as `victim@demo.local` / `changeme`
- API docs: <http://localhost:8000/docs>

---

## Quick start (Docker) — Windows

> Run these in **PowerShell**. Docker Desktop must be running (whale icon in the tray).

### 1. Clone and enter the project

```powershell
git clone https://github.com/Bharaths31/BnB.git
cd BnB\phishguard
```

### 2. Create the environment file

```powershell
Copy-Item .env.example .env
```

*(Command Prompt alternative: `copy .env.example .env`)*

### 3. Build and start the stack

```powershell
docker compose up -d --build
```

### 4. Wait for the backend to be healthy

```powershell
docker compose logs -f backend
# press Ctrl+C to stop following (containers keep running)
```

### 5. (Optional) export the ONNX text model

```powershell
python manage.py setup_models
```

### 6. Send the demo emails

The bundled `manage.py demo` uses a bash script, so on Windows call the Python sender directly:

```powershell
python scripts\send_demo_mail.py --type all --smtp-host localhost
```

### 7. Open the UI

- Dashboard: <http://localhost:3000>
- Webmail (Roundcube): <http://localhost:8080> — log in as `victim@demo.local` / `changeme`
- API docs: <http://localhost:8000/docs>

---

## Accessing the services

| What | URL | Credentials |
|---|---|---|
| Dashboard (live verdicts) | <http://localhost:3000> | — |
| Roundcube webmail | <http://localhost:8080> | `victim@demo.local` / `changeme` |
| Backend API | <http://localhost:8000> | — |
| Health check | <http://localhost:8000/health> | — |
| Events feed | <http://localhost:8000/api/events> | — |
| OpenAPI docs | <http://localhost:8000/docs> | — |
| Mailserver (IMAP) | `localhost:143` (no TLS) / `993` (TLS) | any `@demo.local` account |
| Mailserver (SMTP) | `localhost:25` / `587` | — |

Demo mailboxes (password `changeme`): `victim@demo.local`, `attacker@demo.local`,
`boss@demo.local`, `admin@demo.local`.

### Logging into Roundcube (webmail)

Roundcube runs in its own container and talks to the mailserver over IMAP. You log in with a
**full email address** (not just the username).

1. Confirm the stack is up and the mailserver is healthy:

   ```bash
   # Linux
   docker compose ps
   docker compose logs --tail=20 mailserver
   ```
   ```powershell
   # Windows
   docker compose ps
   docker compose logs --tail=20 mailserver
   ```

2. Open <http://localhost:8080> in your browser.

3. Fill in the login form:

   | Field | Value |
   |---|---|
   | **Username** | `victim@demo.local` *(use the full address — the `@demo.local` part is required)* |
   | **Password** | `changeme` |
   | **Server** | leave the prefilled value (`mailserver`) — do **not** change it to `localhost` |

   > The server name comes from `ROUNDCUBEMAIL_DEFAULT_HOST=imap://mailserver:143` in
   > `docker-compose.yml`. Inside the Docker network the mailserver is reachable as `mailserver`,
   > not `localhost`.

4. Click **Login**. You should land in the INBOX.

5. What to expect:

   - A **Quarantine** folder is created automatically the first time the backend blocks a message.
   - Blocked mail is moved to **Quarantine**; flagged mail stays in the INBOX with a `$Phishing`
     keyword and a warning banner from the PhishGuard plugin.
   - The detection watchers start automatically when the **backend** starts, for
     `victim@demo.local`, `boss@demo.local`, and `admin@demo.local`.

6. Send a test message and watch it happen (see [Sending demo emails](#sending-demo-emails)):

   ```bash
   # Linux
   python3 scripts/send_demo_mail.py --type phish --smtp-host localhost
   ```
   ```powershell
   # Windows
   python scripts\send_demo_mail.py --type phish --smtp-host localhost
   ```

7. If login fails:

   - **"Login failed" / cannot connect to IMAP** → the mailserver is still starting. Wait for
     `(healthy)` in `docker compose ps` and retry.
   - **Wrong username format** → always use the full address (`victim@demo.local`).
   - **Account missing** → the accounts live in `config/mailserver/postfix-accounts.cf`
     (`victim`, `attacker`, `boss`, `admin`, all `@demo.local`, password `changeme`).
   - **Blank page / 502** → check `docker compose logs -f roundcube`.
   - **Stale session** → clear cookies for `localhost:8080`, or open an incognito window.

---

## Everyday operations

### Status & logs

```bash
# Linux
docker compose ps
docker compose logs -f backend        # backend logs
docker compose logs -f dashboard
docker compose logs -f mailserver
```

```powershell
# Windows
docker compose ps
docker compose logs -f backend
docker compose logs -f dashboard
docker compose logs -f mailserver
```

### Stop / start

```bash
# Linux
docker compose stop        # stop containers, keep them
docker compose start       # start them again
docker compose down         # stop and remove containers (keeps data volumes)
```

```powershell
# Windows
docker compose stop
docker compose start
docker compose down
```

### Stop everything (all Docker containers)

Use this when you want to shut down **every** container that has been started, not just
PhishGuard's.

**Preferred method — cross-platform `manage.py` action:**

```bash
# Linux / macOS
cd BnB/phishguard
python3 manage.py stop_all
```

```powershell
# Windows
cd BnB\phishguard
python manage.py stop_all
```

`stop_all` first tears down the PhishGuard stack (`docker compose down --remove-orphans`), then
runs `docker stop` on every other running container on the machine.

**Raw one-liners (if you prefer not to use `manage.py`):**

```bash
# Linux / macOS
cd BnB/phishguard
docker compose down --remove-orphans     # stop + remove this project's containers
docker stop $(docker ps -q)              # stop every other running container
```

```powershell
# Windows PowerShell
cd BnB\phishguard
docker compose down --remove-orphans
docker ps -q | ForEach-Object { docker stop $_ }
```

```bat
:: Windows Command Prompt (cmd.exe)
cd BnB\phishguard
docker compose down --remove-orphans
for /f "tokens=*" %i in ('docker ps -q') do docker stop %i
```

> **Warning:** `docker stop $(docker ps -q)` / the loop above stops **all** running containers
> system-wide, including any unrelated to PhishGuard. To remove the PhishGuard volumes and
> images too (destroys mail + database state), use `docker compose down -v --remove-orphans`.

### Full reset (wipes mail + database state)

```bash
# Linux
docker compose down -v
docker compose up -d --build
```

```powershell
# Windows
docker compose down -v
docker compose up -d --build
```

> `-v` deletes the named volumes (`mailserver-data`, `backend-data`, …). Use it when you want a
> clean mailbox and a fresh SQLite database.

### Rebuild after changing dependencies

```bash
# Linux
docker compose build --no-cache backend dashboard
docker compose up -d
```

```powershell
# Windows
docker compose build --no-cache backend dashboard
docker compose up -d
```

> **Dashboard note:** only `dashboard/src` is bind-mounted into the container. So editing React
> components hot-reloads, but changes to `package.json`, `postcss.config.js`, `tailwind.config.js`,
> or `vite.config.js` require rebuilding the dashboard image
> (`docker compose build dashboard && docker compose up -d dashboard`).

### `manage.py` convenience wrapper

Works on both platforms (run from `phishguard/`):

```bash
python manage.py start          # docker compose up -d
python manage.py stop           # docker compose down (this project)
python manage.py stop_all       # this project + EVERY running container
python manage.py status         # docker compose ps
python manage.py setup_models   # export ONNX models inside the backend container
python manage.py demo           # send demo emails (Linux/macOS or Git Bash)
python manage.py setup_all      # start + models + demo
```

> On Windows, `python manage.py demo` needs **Git Bash/WSL** for `bash`. Prefer the direct
> `python scripts\send_demo_mail.py --type all --smtp-host localhost` command instead.

---

## Configuration

### `.env` (created from `.env.example`)

| Variable | Default | Meaning |
|---|---|---|
| `MAIL_DOMAIN` | `demo.local` | Mail domain |
| `MAIL_ADMIN_USER` / `MAIL_ADMIN_PASS` | `admin@demo.local` / `changeme` | Admin account |
| `DOVECOT_MASTER_USER` / `DOVECOT_MASTER_PASS` | `backend` / `changeme` | Dovecot master user for backend IMAP access |
| `SQLITE_PATH` | `/data/phishguard.db` | SQLite database path (inside container) |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `TEXT_MODEL` | `cybersectony/phishing-email-detection-distilbert_v2.1` | Text model ID |
| `SECURITY_ENCODER` | `ehsanaghaei/SecureBERT` | Embeddings model ID |
| `URL_PHISH_MODEL` | `ealvaradob/bert-finetuned-phishing` | URL model ID |

### `config/policy.yaml`

Thresholds (`block`/`flag`), fusion `review_threshold`, brand dictionary, and safety limits for
HTML/attachment/behavioral analysis. Calibrated thresholds can be supplied via
`data/processed/calibrated_policy.json`, which overrides the `policy.yaml` fallbacks when present.

---

## Optional: export the ONNX models

PhishGuard is fully functional without the ONNX model (deterministic fallback), but the trained
classifier improves accuracy. Two ways to export it:

**A. Inside the running backend container (recommended):**

```bash
# Linux
python3 manage.py setup_models
```

```powershell
# Windows
python manage.py setup_models
```

**B. Locally (no Docker), then the file is reused by the container via the `./data` mount:**

```bash
# Linux
python3 -m venv .venv
source .venv/bin/activate
pip install "optimum[onnxruntime]" transformers torch
optimum-cli export onnx \
  --model cybersectony/phishing-email-detection-distilbert_v2.1 \
  --task text-classification data/processed/text_classifier_onnx
```

```powershell
# Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install "optimum[onnxruntime]" transformers torch
optimum-cli export onnx `
  --model cybersectony/phishing-email-detection-distilbert_v2.1 `
  --task text-classification data\processed\text_classifier_onnx
```

Then restart the backend so it loads the model:

```bash
# Linux
docker compose restart backend
```

```powershell
# Windows
docker compose restart backend
```

---

## Sending demo emails

Five message types are available: `phish`, `ceo_fraud`, `homoglyph`, `qr`, `legit`, `all`.

```bash
# Linux — send every type to the victim mailbox
python3 scripts/send_demo_mail.py --type all --smtp-host localhost

# a single type
python3 scripts/send_demo_mail.py --type ceo_fraud --smtp-host localhost

# different recipient
python3 scripts/send_demo_mail.py --type phish --to boss@demo.local --smtp-host localhost
```

```powershell
# Windows
python scripts\send_demo_mail.py --type all --smtp-host localhost
python scripts\send_demo_mail.py --type ceo_fraud --smtp-host localhost
```

**Alternatively, send from inside the mailserver/backend network:**

```bash
# Linux
docker compose exec backend python scripts/send_demo_mail.py --type all --smtp-host mailserver
```

```powershell
# Windows (same command works in PowerShell)
docker compose exec backend python scripts/send_demo_mail.py --type all --smtp-host mailserver
```

Within a few seconds the dashboard shows the verdicts and Roundcube moves blocked mail to the
`Quarantine` folder.

---

## Running without Docker (local dev)

Useful for iterating on the backend or dashboard without rebuilding containers.

### Backend

```bash
# Linux
cd phishguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# point the watcher at the host-published IMAP port
export DOVECOT_HOST=localhost
uvicorn guard.api.app:app --host 0.0.0.0 --port 8000 --reload
```

```powershell
# Windows
cd phishguard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:DOVECOT_HOST = "localhost"
uvicorn guard.api.app:app --host 0.0.0.0 --port 8000 --reload
```

> The backend still needs a running mailserver. Start just that service with
> `docker compose up -d mailserver`.

### Dashboard

```bash
# Linux
cd phishguard/dashboard
npm install
npm run dev -- --host 0.0.0.0 --port 3000
```

```powershell
# Windows
cd phishguard\dashboard
npm install
npm run dev -- --host 0.0.0.0 --port 3000
```

The dashboard fetches `http://localhost:8000/api/events`, so keep the backend reachable on
`localhost:8000`.

---

## Running the test suite

The tests are self-contained and do not need Docker or a mailserver.

### Full dependency install

```bash
# Linux
cd phishguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests -q
```

```powershell
# Windows
cd phishguard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest tests -q
```

### Lightweight install (only what the tests need)

Useful if a heavy optional wheel fails to build on your machine:

```bash
# Linux
pip install pytest structlog pydantic pydantic-settings numpy networkx beautifulsoup4 pyyaml
pytest tests -q
```

```powershell
# Windows
pip install pytest structlog pydantic pydantic-settings numpy networkx beautifulsoup4 pyyaml
pytest tests -q
```

Expected result: all tests pass (e.g. `79 passed`).

Run a single file / verbose:

```bash
pytest tests/test_behavioral.py -v
```

---

## Troubleshooting

**`docker compose` says `env file .env not found`**
You skipped step 2. Create it: `cp .env.example .env` (Linux) / `Copy-Item .env.example .env` (Windows).

**`Port is already allocated` / port already in use**
Something already listens on 25, 143, 587, 993, 3000, 8000, or 8080. Find and free it:
- Linux: `sudo ss -ltnp | grep ':8000'` then stop that process.
- Windows: `netstat -ano | findstr :8000` then `taskkill /PID <pid> /F`.
Or change the left-hand side of the port mapping in `docker-compose.yml` (e.g. `"18000:8000"`).

**Dashboard shows a Vite overlay: `[plugin:vite:css] [postcss] It looks like you're trying to use \`tailwindcss\` directly as a PostCSS plugin`**
Cause: Tailwind CSS **v4** moved its PostCSS plugin into a separate package. This repo is already
fixed — `dashboard/postcss.config.js` uses `@tailwindcss/postcss`, `dashboard/src/index.css`
starts with `@import "tailwindcss";`, and `@tailwindcss/postcss` is listed in
`dashboard/package.json`. If you still see it, you are running an old dashboard image. Rebuild it:

```bash
# Linux
docker compose build dashboard
docker compose up -d dashboard
```
```powershell
# Windows
docker compose build dashboard
docker compose up -d dashboard
```

Then hard-refresh the browser (`Ctrl+Shift+R`). If it persists, confirm the installed versions:

```bash
docker compose exec dashboard npm ls tailwindcss @tailwindcss/postcss
```

**`permission denied` running `./manage.py` (Linux)**
Run it through Python (`python3 manage.py ...`) or `chmod +x manage.py`.

**`bash: command not found` on Windows during `manage.py demo`**
Use `python scripts\send_demo_mail.py --type all --smtp-host localhost`, or run inside Git Bash/WSL.

**Dashboard shows "No recent events found."**
The backend watchers only start once the backend is up and can reach the mailserver. Check
`docker compose logs -f backend` for `Watchers started`, then send a demo email. Confirm
<http://localhost:8000/api/events> returns data.

**Mail is not processed**
Ensure `mailserver` is healthy (`docker compose ps`), the `.env` credentials are set, and send a
test with `--smtp-host localhost` from the host (or `--smtp-host mailserver` from inside).

**Model export fails / is very slow**
Skip it — PhishGuard uses the deterministic fallback. Exporting DistilBERT needs a large
download and `torch`; run it on a machine with more resources if needed.

**Windows: `\scripts\setup_demo.sh` line-ending errors**
Open the repo with Git Bash/WSL, or set `git config --global core.autocrlf input` and re-checkout.
Shell scripts must keep LF line endings.

**Clean slate**
`docker compose down -v && docker compose up -d --build` (Linux) or the same commands in
PowerShell on Windows.

---

## Security notes

- **No generative LLM, chatbot, or autonomous agent.** All detection is statistical
  (median/MAD, MinHash, edit distance, token/embedding similarity) or deterministic rules.
- **Email content is untrusted data**, never executable instructions.
- **JavaScript is never executed**; HTML is parsed statically.
- **Attachments are never executed**; archives are inspected with depth/size/ratio limits
  (decompression-bomb protection).
- **Behavioral profiles do not learn from blocked mail** by default (poisoning prevention),
  configurable in `policy.yaml`.
- All state (SQLite) and models stay **local**; no email content leaves the machine.

---

## Training / fine-tuning models

If you want to fine-tune the text classifier on your own data:

1. Create a GPU environment (a Windows laptop with a dedicated GPU works well).
2. Set up a virtual environment and install the training extras:
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: .\venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   pip install "optimum[onnxruntime]" transformers torch datasets
   ```
3. Use the notebooks in `notebooks/` (e.g. `train_text_model.ipynb`) with datasets such as
   `ealvaradob/phishing-dataset` or SpamAssassin.
4. Export the fine-tuned model to ONNX:
   ```bash
   optimum-cli export onnx --model path/to/your/fine-tuned-model \
     --task text-classification data/processed/text_classifier_onnx
   ```
5. Restart the backend (`docker compose restart backend`) — PhishGuard loads the model from
   `data/processed/text_classifier_onnx` automatically and falls back deterministically if it is
   missing.
