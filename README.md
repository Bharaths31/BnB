# 🛡️ PhishGuard — Real-Time AI Phishing Detection System

> **GDG Bit N Build Hackathon 2026 · Team PSN013**
>
> A real-time, fully local, CPU-only phishing detection system that monitors live email inboxes and catches sophisticated phishing attacks — including LLM-crafted spear-phish, homoglyph evasion, QR-code lures, and redirect chains — with explainable verdicts in seconds.

---

## 📌 Project Description

PhishGuard is an **intelligent email security system** that plugs directly into a real IMAP mailbox and analyzes every incoming email through a multi-layered, AI-powered detection pipeline. Unlike traditional blacklist-based spam filters, PhishGuard uses **semantic NLP analysis**, **graph-based threat intelligence**, **cross-modal consistency checks**, and **behavioral profiling** to catch modern phishing attacks that evade conventional defenses.

### The Problem

Phishing remains the #1 cyber-attack vector worldwide. Modern phishing emails are:
- **AI-generated** — grammatically perfect, context-aware, and indistinguishable from legitimate mail
- **Evasion-engineered** — using homoglyphs, zero-width characters, QR codes, image-only bodies, and redirect chains
- **Targeted** — CEO fraud, HR/payroll lures, and brand impersonation tailored to the victim

Traditional signature/blacklist filters miss these. PhishGuard doesn't.

### Our Solution

**Log into your webmail → PhishGuard starts protecting you automatically.**

Every incoming email is evaluated by 8+ specialized detectors working in parallel. Verdicts are delivered in under 500ms. Phishing emails are quarantined with a full explanation of *why* they were flagged — visible both in the webmail client and a live dashboard.

### Key Features

| Feature | Description |
|---|---|
| 🔍 **Multi-Layer Detection** | Header auth (SPF/DKIM/DMARC), NLP text classifier, URL analysis, graph engine, behavioral profiling, HTML structural analysis, attachment inspection, and cross-modal consistency |
| 🧠 **Semantic NLP** | DistilBERT-based phishing classifier (ONNX-optimized for CPU) that understands *intent* — urgency, authority impersonation, credential requests — not just keywords |
| 🕸️ **Graph-Based Threat Intelligence** | Heterogeneous knowledge graph (sender ↔ domain ↔ URL ↔ IP ↔ brand) with community detection, campaign clustering, and reputation propagation |
| ⚡ **Real-Time IMAP IDLE** | Monitors the mailbox live; verdicts arrive within seconds of email delivery |
| 🛡️ **Evasion Resistant** | Handles homoglyphs, zero-width chars, QR codes, image-only mails, redirect chains, and HTML obfuscation |
| 📊 **Live Dashboard** | React-based real-time dashboard with verdict feed, threat graph visualization, and feedback controls |
| 🔌 **MCP Server** | Model Context Protocol server with tools for programmatic email analysis and mailbox management |
| 🔒 **Fully Local & Private** | All processing happens on-device; no email content ever leaves the machine |
| ↩️ **Reversible Actions** | Quarantine is never destructive — false positives can be restored with one click |
| 📝 **Explainable Verdicts** | Every verdict comes with top contributing reasons and structured evidence |

---

## 🏗️ Architecture

```
Sender ───SMTP──▶ Mail Server (Postfix + Dovecot) ◀──IMAP── Roundcube Webmail
                            │
                            │ IMAP IDLE (push)
                            ▼
                   ┌──────────────────┐
                   │  Watcher/Ingestor │
                   └────────┬─────────┘
                            ▼
                   ┌──────────────────┐
                   │ Parser & Feature  │  headers, body, HTML, URLs,
                   │    Extraction     │  attachments, QR/OCR
                   └────────┬─────────┘
        ┌──────────┬────────┼────────┬──────────┬──────────┐
        ▼          ▼        ▼        ▼          ▼          ▼
   Header/Auth   URL     Text     Graph    Behavioral  HTML/Attach
   Rules        Model   Classifier Engine  Profiler    Analyzer
        └──────────┴────────┼────────┴──────────┴──────────┘
                            ▼
                   ┌──────────────────┐
                   │  Fusion Engine    │ → score 0–1, verdict, top reasons
                   └────────┬─────────┘
                            ▼
             FastAPI + WebSocket → Dashboard (live feed, graph view)
                            ▼
              IMAP actions: Quarantine / Flag / Allow
```

---

## 💻 Technology Stack

### Backend
| Technology | Purpose |
|---|---|
| **Python 3.11** | Core backend language |
| **FastAPI** + **Uvicorn** | REST API + WebSocket server |
| **IMAPClient** | IMAP IDLE mailbox monitoring |
| **Pydantic** | Data validation and settings |
| **SQLite** (via `aiosqlite`) | Event store, audit log, feedback |
| **structlog** | Structured logging |

### AI / ML Pipeline
| Technology | Purpose |
|---|---|
| **Transformers** (HuggingFace) | DistilBERT phishing text classifier |
| **ONNX Runtime** | Optimized CPU inference |
| **LightGBM** | URL feature classifier + fusion meta-model |
| **SHAP** | Explainable AI — verdict reason attribution |
| **scikit-learn** | Feature engineering and model utilities |
| **NetworkX** | Heterogeneous threat knowledge graph |
| **python-louvain** | Community/campaign detection |
| **datasketch** (MinHash) | Near-duplicate email clustering |

### Evasion Detection
| Technology | Purpose |
|---|---|
| **RapidOCR** (ONNX) | OCR for image-only phishing emails |
| **pyzbar** | QR code decoding ("quishing" detection) |
| **confusables** | Unicode homoglyph detection |
| **BeautifulSoup4** | HTML parsing and structural analysis |
| **Levenshtein** | Brand/domain lookalike distance |

### Frontend Dashboard
| Technology | Purpose |
|---|---|
| **React 19** | UI framework |
| **Vite 8** | Build tool and dev server |
| **Tailwind CSS 4** | Styling |
| **WebSocket** | Real-time verdict streaming |

### Infrastructure
| Technology | Purpose |
|---|---|
| **Docker** + **Docker Compose** | One-command deployment |
| **Postfix + Dovecot** (`docker-mailserver`) | Full IMAP/SMTP test mail server |
| **Roundcube** | FOSS webmail with PhishGuard banner plugin |
| **MCP (Model Context Protocol)** | Programmatic tool interface |

### Testing
| Technology | Purpose |
|---|---|
| **pytest** + **pytest-asyncio** | Unit and integration tests |
| **Robustness suite** | Evasion + prompt injection test sets |

---

## 🚀 Demo — Quick Start

### Prerequisites
- **Docker** and **Docker Compose** installed
- **Git** installed

### Run the entire system in 4 commands:

```bash
# 1. Clone the repository
git clone https://github.com/Bharaths31/BnB.git
cd BnB/phishguard

# 2. Set up environment
cp .env.example .env          # Windows PowerShell: Copy-Item .env.example .env

# 3. Launch everything
docker compose up -d --build

# 4. (Optional) Send test phishing emails
python scripts/send_demo_mail.py
```

### Access the services:

| Service | URL | Credentials |
|---|---|---|
| 📧 **Roundcube Webmail** | [http://localhost:8080](http://localhost:8080) | `victim@demo.local` / `changeme` |
| 📊 **PhishGuard Dashboard** | [http://localhost:3000](http://localhost:3000) | — |
| 🔌 **API Documentation** | [http://localhost:8000/docs](http://localhost:8000/docs) | — |

### Demo Flow (3–4 minutes):

1. **Log into Roundcube** as `victim@demo.local` — Dashboard shows "protection active"
2. **Send test emails** via the demo script — includes: obvious phish, LLM-crafted CEO fraud, homoglyph domain attack, QR-code-only email, and a legitimate newsletter
3. **Watch verdicts land** in seconds on the dashboard — phishing emails auto-quarantined in Roundcube
4. **Explore explanations** — click any verdict to see top contributing reasons and the threat graph showing shared infrastructure with known phish campaigns
5. **Test evasion resistance** — homoglyph, zero-width character, and redirect chain attacks are all caught

> 📖 **Full setup guide** (including Windows, local dev, and troubleshooting): [`phishguard/README.md`](phishguard/README.md)

---

## 📂 Repository Structure

```
BnB/
├── phishguard/                          # Main application
│   ├── guard/                           # Detection pipeline
│   │   ├── parse/                       # Email parser & feature extraction
│   │   ├── headers/                     # SPF/DKIM/DMARC & header anomaly rules
│   │   ├── nlp/                         # DistilBERT text classifier (ONNX)
│   │   ├── url/                         # URL lexical analysis & lookalike detection
│   │   ├── graph/                       # Knowledge graph & campaign clustering
│   │   ├── behavioral/                  # Sender/relationship behavioral profiling
│   │   ├── html/                        # HTML structural analysis
│   │   ├── attachment/                  # Attachment inspection (Office/PDF/SVG)
│   │   ├── multimodal/                  # Cross-modal consistency checks
│   │   ├── fusion/                      # Meta-model verdict engine (LightGBM)
│   │   ├── explainer/                   # SHAP-based reason attribution
│   │   ├── mcp_server/                  # MCP tool server
│   │   ├── watcher/                     # IMAP IDLE monitor
│   │   ├── api/                         # FastAPI endpoints + WebSocket
│   │   └── store/                       # SQLite persistence layer
│   ├── dashboard/                       # React + Vite live dashboard
│   ├── roundcube_plugin/                # Webmail integration plugin
│   ├── scripts/                         # Dataset download, training, demo tools
│   ├── tests/                           # Unit + integration + robustness tests
│   ├── config/                          # Tunable thresholds & policy
│   ├── docs/                            # Evaluation reports & architecture docs
│   ├── docker-compose.yml               # One-command deployment
│   └── README.md                        # Detailed setup & operations guide
├── technical_reference.md               # Full technical reference document
├── technical_reference.pdf              # PDF version of technical reference
└── README.md                            # ← You are here
```

---

## 📊 Judging Criteria Alignment

### 🎨 Creativity
- **Novel multi-modal approach**: Combines NLP, graph analysis, behavioral profiling, and cross-modal consistency — not just another blacklist checker
- **Real email client integration**: Users interact with a real webmail; protection is invisible and automatic
- **Knowledge graph visualization**: Interactive threat graphs showing attacker infrastructure relationships and campaign clusters
- **Evasion-aware by design**: Built specifically to catch attacks that fool conventional systems (homoglyphs, QR lures, image-only phish, redirect chains)

### ⚙️ Technical Complexity
- **8+ specialized detection modules** running in parallel with a meta-model fusion engine
- **ONNX-optimized neural network** inference on CPU with sub-500ms latency
- **Heterogeneous graph engine** with community detection (Louvain), MinHash-based campaign clustering, and reputation propagation
- **Full MCP server** implementation with 9 tools for programmatic analysis
- **IMAP IDLE** real-time mailbox monitoring with reconnect/backoff logic
- **Deterministic fallbacks** — every component degrades gracefully when optional dependencies are unavailable

### 🔧 Practicality
- **One-command deployment** — `docker compose up -d --build` and it works
- **Privacy-first** — all processing is local; no email content leaves the machine
- **Reversible quarantine** — false positives are restored with one click; nothing is ever deleted
- **Explainable verdicts** — every decision comes with human-readable reasons and structured evidence
- **Works on CPU-only hardware** — no GPU required

### 🎤 Presentation
- **Live demo** with real email delivery and real-time verdicts
- **Interactive dashboard** with live verdict feed and threat graph visualization
- **Clear documentation** with architecture diagrams, setup guides, and evaluation reports

---

## ✅ Hackathon Compliance

| Requirement | Status |
|---|---|
| Original work developed during the hackathon | ✅ All code written from scratch during the 24-hour event |
| Submitted before the deadline | ✅ |
| Clear project description | ✅ This README |
| Demo included | ✅ One-command Docker setup + demo script |
| Documentation provided | ✅ Root README + detailed [`phishguard/README.md`](phishguard/README.md) + [`technical_reference.pdf`](technical_reference.pdf) |
| GitHub updated with regular commits | ✅ Commits pushed throughout development |
| Technology stack disclosed | ✅ Full stack listed above |

---

## 🧪 Running Tests

```bash
cd phishguard
pytest tests/ -v
```

The test suite includes:
- **Unit tests** — parser, normalizer, each detector module
- **Integration tests** — end-to-end: send email → quarantine
- **Robustness tests** — homoglyph, zero-width, QR, redirect, prompt injection

---

## 📄 Documentation

| Document | Description |
|---|---|
| [`phishguard/README.md`](phishguard/README.md) | Complete setup, configuration, operations, and troubleshooting guide |
| [`technical_reference.md`](technical_reference.md) | Full technical reference with architecture deep-dive |
| [`technical_reference.pdf`](technical_reference.pdf) | PDF version of the technical reference |
| [`PSN013_phishing_detection_build_plan.md`](PSN013_phishing_detection_build_plan.md) | Original build specification |

---

## 🔐 Security & Privacy

- **Local-only inference** — no email content is sent to any external service
- **Email content is untrusted data** — never treated as instructions
- **No destructive actions** — quarantine is reversible; there is no "delete" operation
- **Append-only audit log** — every automated action is logged with reasons
- **No secrets in the repository** — credentials managed via `.env` (`.env.example` provided)

---

## 👥 Team

**Team PSN013** — GDG Bit N Build Hackathon 2026

---

## 📜 License

This project was built for the GDG Bit N Build Hackathon 2026. All code is original work developed during the 24-hour event.
