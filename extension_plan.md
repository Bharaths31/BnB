# PhishGuard Extension — Implementation & Improvement Plan

> Derived from the extension prompt (behavioral profiling, cross-modal consistency, HTML
> analysis, temporal graph, attachment analysis, adversarial framework, fusion uncertainty,
> threshold calibration, campaign similarity, intent features, evidence system, ablation
> evaluation, campaign-aware splitting) layered on the existing `phishguard/` codebase and
> [implementation_plan.md](file:///home/ragnarok/Documents/projects/BnB/implementation_plan.md).

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Analysis — Current State](#2-project-analysis--current-state)
3. [Prompt Decomposition — Workstreams](#3-prompt-decomposition--workstreams)
4. [Constraints & Capability Contract](#4-constraints--capability-contract)
5. [Target Architecture](#5-target-architecture)
6. [Phase 0 — Foundations & Contracts](#6-phase-0--foundations--contracts)
7. [Phase 1 — Independent Detector Modules](#7-phase-1--independent-detector-modules)
8. [Phase 2 — Temporal Graph, Campaigns & Intent](#8-phase-2--temporal-graph-campaigns--intent)
9. [Phase 3 — Fusion v2, Uncertainty & ExplainEngine v2](#9-phase-3--fusion-v2-uncertainty--explainengine-v2)
10. [Phase 4 — Data Pipeline, Splitting & Calibration](#10-phase-4--data-pipeline-splitting--calibration)
11. [Phase 5 — Adversarial Framework & Full Evaluation](#11-phase-5--adversarial-framework--full-evaluation)
12. [Phase 6 — Presentation & Polish](#12-phase-6--presentation--polish)
13. [Fusion Integration Matrix](#13-fusion-integration-matrix)
14. [Test Matrix](#14-test-matrix)
15. [Policy, Config & Schema Changes](#15-policy-config--schema-changes)
16. [Compliance Checklist](#16-compliance-checklist)
17. [Sequencing, Effort & Cut-Line](#17-sequencing-effort--cut-line)
18. [Risks](#18-risks)

---

## 1. Executive Summary

This plan extends the existing PhishGuard prototype with **13 workstreams** from the extension
prompt, organized into 7 dependency-ordered phases. It upgrades the existing skeleton — whose
ML components are currently keyword/stub implementations — by adding a **typed component
contract**, a **unified evidence system**, and a **registry-based FusionEngine**, so that every
new detection capability (behavioral, cross-modal, HTML, attachment, graph/campaign, intent)
integrates uniformly, fails safe, records latency, and contributes explainable evidence.

**Hard rules honored throughout:**

- Python-first, CPU-compatible, locally executable, Docker-compatible.
- Deterministic wherever possible; low-latency; explainable; modular; testable.
- **No generative LLM, chatbot, autonomous reasoning agent, prompt-based classifier, or
  generative-AI explanation system.** All similarity/decision logic is statistical
  (MinHash, robust statistics, edit distance, TF-IDF/token overlap) or non-generative
  pretrained encoders.
- Email content is **untrusted data, never instructions**.
- Existing models (text classifier, tactic classifier, fusion heuristic) are **not replaced**;
  their interfaces are preserved and new subsystems are built against typed contracts with
  deterministic fallbacks, so real ONNX/LightGBM artifacts can drop in later without redesign.

---

## 2. Project Analysis — Current State

### 2.1 What exists and works

| Layer | Status | Notes |
|---|---|---|
| Docker stack (mailserver, Roundcube, backend, dashboard) | ✅ Working | `docker-compose.yml`, mailserver config, demo scripts |
| IMAP IDLE watcher | ✅ Working | `guard/watcher/imap_watcher.py` — reconnect w/ backoff, UID tracking, quarantine/flag actions |
| Email parsing | ✅ Basic | `guard/parse/parser.py` (mailparser + BeautifulSoup), `normalizer.py` (NFKC, zero-width, bidi, homoglyph), `html_sanitizer.py`, `ocr.py` |
| Header rules | ✅ Basic | `guard/headers/rules.py` — SPF/DKIM/DMARC substring checks, 3 header anomalies |
| SQLite store | ✅ Basic | `guard/store/database.py` — `emails`, `verdicts`, `audit_log`, `feedback`, `mailbox_state` |
| FastAPI | ✅ Skeleton | `guard/api/` — only `/sessions` + `/events` routes |
| Dashboard | ⚠️ Stub | `dashboard/src/` — only `App.jsx`/`main.jsx`, no components |
| Roundcube plugin | ✅ Basic | login hook + banner |
| MCP server | ❌ Missing | planned in original `implementation_plan.md` Phase 4, not built |
| Tests | ❌ Missing | **no `tests/` directory at all** |
| Data pipeline | ❌ Missing | no `data/`, no dataset scripts, no parquet, no calibration artifacts |

### 2.2 Critical gaps vs. the prompt's assumed baseline

The extension prompt assumes mature components that are actually **stubs**:

| Prompt assumption | Reality in code | Consequence for this plan |
|---|---|---|
| Specialized Transformer text classifier | `guard/nlp/classifier.py` = keyword-matching dummy (0.85/0.90/0.1) | Keep `classify(text) → float` interface; build against typed contracts + deterministic fallback so real ONNX drops in later |
| LightGBM/LR fusion + SHAP | `guard/fusion/fusion_engine.py` = heuristic `text_prob + 0.1·headers` | Additive refactor into component registry; current heuristic stays as the no-model fallback |
| Graph relationships + campaign clustering | `guard/store/graph.py` = in-memory `MultiDiGraph`, **not persisted, not wired into the watcher** | WS4 supersedes with `guard/graph/` (temporal, persisted, integrated) |
| SHAP explanations | `guard/explainer/engine.py` = string template lookup | Extended in place for evidence-driven ranking (WS11) |
| Datasets / evaluation | None | WS13 + dataset bootstrap (§10) builds the whole pipeline |

### 2.3 Integration seams that must change (additive only)

1. **`ParsedEmail` is too thin** — lacks: recipients (`To`/`Cc`), message timestamp, per-URL
   display text (only a boolean today), raw attachment payload bytes (payloads are discarded —
   attachment analysis is impossible without them), sender/reply-to domain helpers.
2. **`Verdict` lacks** calibrated probability, uncertainty, confidence, evidence, `REVIEW` level.
3. **Watcher pipeline** is sequential; no component-error isolation, latency recording, or
   post-verdict profile/graph update hooks.
4. **No component contract** — every module invents its own return shape.

---

## 3. Prompt Decomposition — Workstreams

| # | Workstream | New code | Depends on |
|---|---|---|---|
| WS1 | Behavioral profiling | `guard/behavioral/` (6 files) | Parser recipients/timestamps, SQLite |
| WS2 | Cross-modal consistency | `guard/multimodal/` (4 files) | Parser URLs/OCR/QR, brand dict |
| WS3 | HTML structural analysis | `guard/html/` (5 files) | Parser HTML part |
| WS4 | Temporal relationship graph | `guard/graph/` (5 files; supersedes `store/graph.py`) | Parser; WS9 inputs |
| WS5 | Static attachment analysis | `guard/attachment/` (7 files) | Parser attachment payloads |
| WS6 | Adversarial transformation & evaluation | `guard/adversarial/` (5 files) | All models; WS13 holdout |
| WS7 | Fusion uncertainty + REVIEW | `guard/fusion/uncertainty.py`, `meta_model.py` | All components registered |
| WS8 | Threshold calibration | `scripts/calibrate_thresholds.py` | WS13 validation split, WS7 |
| WS9 | Campaign similarity channels | extends `guard/graph/clustering.py` | WS4; MinHash/embedder |
| WS10 | Structured intent features | `guard/nlp/intent.py` | WS2/WS3/WS5 signals |
| WS11 | Unified evidence representation | `guard/evidence/` (3 files) | None — **do first** |
| WS12 | Ablation evaluation pipeline | `scripts/evaluate.py`, `scripts/ablation.py`, `docs/evaluation.md` | Everything + WS13 |
| WS13 | Campaign-aware dataset splitting | `scripts/split_dataset.py`, parquet outputs, leakage report | None — **do early** |

---

## 4. Constraints & Capability Contract

### 4.1 Capability contract (applies to every new detection capability)

1. Produce structured numerical or categorical features.
2. Expose a typed Python interface.
3. Integrate into the existing FusionEngine.
4. Be independently testable.
5. Have an ablation measurement.
6. Have a deterministic fallback when its dependency fails.
7. Contribute evidence to ExplainEngine.
8. Record its latency.
9. Never prevent the rest of the detection pipeline from operating.

Preferred techniques: classical ML, statistical analysis, deterministic heuristics, feature
engineering, lightweight discriminative models, graph algorithms, pretrained non-generative
encoders.

### 4.2 Untrusted-data handling

- All parsing wrapped in `safe_run()` isolation (rule 9) with size caps on bodies/attachments.
- HTML parsed statically (BeautifulSoup) — **JavaScript never executed**.
- Attachments **never executed**; archives inspected with bomb protection.
- Email text is feature input only; never treated as instructions (architecturally immune to
  prompt injection — no LLM exists in the pipeline).
- All SQL parameterized; PII-redacted logs per existing policy.

---

## 5. Target Architecture

### 5.1 Unifying contracts (Phase 0 — enables everything)

```python
# guard/evidence/models.py
class EvidenceCategory(str, Enum):
    HEADER, AUTHENTICATION, TEXT, TACTIC, URL, HTML, ATTACHMENT, IMAGE,
    QR, BEHAVIOR, GRAPH, CAMPAIGN, CONSISTENCY, THREAT_INTEL

class Evidence(BaseModel):
    evidence_id: str
    category: EvidenceCategory
    feature: str                 # e.g. "domain_age"
    value: str                   # observed value, e.g. "2 days"
    normalized_score: float      # 0..1 risk contribution
    severity: str                # info | low | medium | high | critical
    confidence: str              # low | medium | high
    source_module: str
    timestamp: datetime
    related_entity: str | None
    explanation_key: str          # links to explainer template

# guard/component.py — shared protocol (NEW)
class ComponentResult(BaseModel):
    features: dict[str, float]   # named feature vector for FusionEngine
    evidence: list[Evidence]
    latency_ms: float
    degraded: bool                # True if fallback was used

class AnalysisComponent(Protocol):
    name: str
    def run(self, parsed: ParsedEmail, ctx: AnalysisContext) -> ComponentResult: ...
```

`AnalysisContext` carries cross-component inputs (sender/domain reputation, authentication
results, URL features, intent scores, behavioral profile) so modules like HTML are
**contextualized** rather than treating complexity as malicious. A `safe_run()` wrapper
implements rules 6/8/9: `try/except` → deterministic neutral fallback result + `degraded=True`
+ WARNING log, with `time.perf_counter()` latency measurement.

### 5.2 Final module tree (additions only — nothing existing is deleted)

```
guard/
├── component.py                     # NEW: protocol, safe_run, AnalysisContext
├── evidence/                        # WS11
│   ├── __init__.py
│   ├── models.py                    # Evidence, EvidenceCategory
│   └── collector.py                 # dedup, deterministic ranking, provenance
├── behavioral/                      # WS1
│   ├── __init__.py
│   ├── sender_profile.py
│   ├── recipient_profile.py
│   ├── temporal_features.py
│   ├── anomaly.py
│   └── profile_store.py
├── multimodal/                      # WS2
│   ├── __init__.py
│   ├── consistency.py
│   ├── identity_consistency.py
│   ├── link_consistency.py
│   └── semantic_consistency.py
├── html/                            # WS3
│   ├── __init__.py
│   ├── features.py
│   ├── forms.py
│   ├── javascript.py
│   ├── obfuscation.py
│   └── model.py
├── graph/                           # WS4 + WS9 (supersedes guard/store/graph.py)
│   ├── __init__.py
│   ├── engine.py
│   ├── temporal.py
│   ├── features.py
│   ├── clustering.py
│   └── persistence.py
├── attachment/                      # WS5
│   ├── __init__.py
│   ├── analyzer.py
│   ├── magic.py
│   ├── archive.py
│   ├── office.py
│   ├── pdf.py
│   └── features.py
├── adversarial/                     # WS6
│   ├── __init__.py
│   ├── mutations.py
│   ├── generator.py
│   ├── evaluator.py
│   └── reports.py
├── nlp/
│   └── intent.py                    # WS10 (extends existing tactic classifier)
├── fusion/
│   ├── fusion_engine.py            # WS7 (additive refactor → registry)
│   ├── meta_model.py                # WS7
│   └── uncertainty.py               # WS7 (NEW)
scripts/
├── download_datasets.py             # dataset bootstrap (§10.1)
├── build_features.py                # dataset bootstrap (§10.2)
├── split_dataset.py                 # WS13
├── calibrate_thresholds.py          # WS8
├── evaluate.py                      # WS12
└── ablation.py                      # WS12
tests/                               # NEW directory (see §14)
data/
├── raw/                             # .gitignored corpora + feeds
└── processed/                       # parquet splits, calibrated_policy.json, leakage_report.json
docs/
└── evaluation.md                    # WS12 report
```

### 5.3 Runtime data flow (per email)

```
raw MIME → parser (extended)
  → components in isolation (headers, URL, text, tactics+intent, HTML,
    attachment, multimodal, behavioral, graph/campaign)
      each: ComponentResult(features, evidence, latency_ms, degraded)
  → FusionEngine v2 (registry + meta-model + calibration + uncertainty)
  → Verdict(score, calibrated_probability, uncertainty, confidence,
            level ∈ {ALLOW, FLAG, REVIEW, BLOCK}, reasons, component_scores, evidence)
  → ExplainEngine v2 (deterministic evidence ranking)
  → action → POST-VERDICT hooks: profile update + graph update
             (gated by configurable poisoning-prevention policy)
```

Post-verdict ordering is deliberate: behavioral profiles and graph reputation update **only
after** analysis, gated by policy (never update from BLOCK-level or high-score mail unless
`update_policy: always` is explicitly configured).

---

## 6. Phase 0 — Foundations & Contracts

> Goal: every later workstream can plug in uniformly. ~2–3 dev-days.

| Task | File | Details |
|---|---|---|
| 0.1 | `guard/models.py` | **Additive** `ParsedEmail` fields: `recipients: list[str]`, `cc: list[str]`, `received_at: datetime` (parsed `Date` header), `url_display_texts` (per-URL), `attachment_payloads: list[bytes]` (capped, e.g. 10 MB/attachment), `sender_domain`, `replyto_domain`. **Additive** `AttachmentInfo`: `payload_ref`, `magic_sniffed_type`. New `Verdict` fields (see WS7). Backward compatible — defaults everywhere. |
| 0.2 | `guard/component.py` | `AnalysisComponent` protocol, `AnalysisContext`, `safe_run()` — capability rules 2/6/8/9 as reusable machinery |
| 0.3 | `guard/evidence/` | WS11: `Evidence`, `EvidenceCategory` (13 categories), `EvidenceCollector` (dedup, deterministic ranking by `normalized_score × severity`, provenance). **ExplainEngine may only render what exists in Evidence — enforced by tests.** |
| 0.4 | `tests/scaffolding` | `tests/conftest.py` + `tests/factories.py`: deterministic seeded synthetic MIME email factory producing all archetypes (legit newsletter, credential phish, BEC, QR phish, branded phish, macro doc, mailing list, forwarded). Foundation for all later phases. |
| 0.5 | `guard/parse/parser.py` | Extract To/Cc/Date; retain URL display text and attachment payloads (size-capped). Untrusted-input hardening. |
| 0.6 | `guard/fusion/fusion_engine.py` | Minimal registry hook: merge each registered component's `features` into `component_scores`; keep existing heuristic as pre-registry fallback. |
| 0.7 | `requirements.txt` | Add: `pytest`, `pytest-asyncio`, `pandas`, `pyarrow`, `scikit-learn`, `olefile`, `pypdf`, `idna`, `Levenshtein`, `xxhash` — all classical, CPU, local. |

**Acceptance:** parser regression tests pass on all factory archetypes; `safe_run` proven by
fault-injection unit test (component raising → neutral fallback, pipeline continues, latency
recorded, `degraded=True`).

---

## 7. Phase 1 — Independent Detector Modules

> Four modules, fully parallelizable. Each ships with features + evidence + tests. ~9–11 dev-days.

### 7.1 WS1 — Behavioral profiling · `guard/behavioral/`

**`sender_profile.py`** — `SenderProfile`:
first_seen, last_seen, total_messages, messages_per_day, typical sending hour (**circular
median** via mean vector of hour angles), typical weekday (distribution mode), median message
length, normal URL count, normal attachment frequency, common recipient domains / addresses
(frequency-ranked, top-K capped for privacy), common subject patterns (token frequency),
observed sender domains, observed Reply-To domains, historical authentication outcomes,
historical display-name/domain consistency, historical URL domains, historical attachment MIME
types, historical campaign membership.

**`recipient_profile.py`** — `RelationshipProfile` per (sender, recipient):
first_seen, message_count, average interval, typical message length, typical subject similarity
(token Jaccard vs history), normal attachment behavior, normal URL behavior, `is_new`,
`outside_history`.

**`temporal_features.py`** — circular statistics for hour-of-day/weekday; hour deviation =
angular distance (robust to midnight wraparound).

**`anomaly.py`** — the 13 required deterministic anomaly features:

```
sender_newness_score              sender_frequency_anomaly
sender_time_anomaly               sender_domain_change_score
sender_replyto_anomaly            sender_url_behavior_anomaly
sender_attachment_anomaly         sender_authentication_anomaly
recipient_relationship_newness    recipient_relationship_anomaly
display_name_history_anomaly      communication_pattern_anomaly
```

- Numeric distributions → **median + MAD robust z-score** (`0.6745·(x−median)/MAD`, MAD
  floored to avoid division by zero) and quantile-range deviation.
- Categorical distributions → historical frequency with Laplace-style smoothing.
- Newness explicitly distinguishes: **genuinely unknown** (no history) / **unusual** (history
  exists, robust-z beyond quantile gate) / **strongly anomalous** (multiple independent
  deviations).
- **An unknown sender is never automatically classified as phishing** — newness contributes
  evidence only.

Returns:

```python
BehaviorProfileResult(
    sender_anomaly_score: float,
    relationship_anomaly_score: float,
    sender_newness_score: float,
    temporal_anomaly_score: float,
    communication_anomaly_score: float,
    evidence: list[str],
)
```

**`profile_store.py`** — SQLite tables `sender_profiles`, `relationship_profiles`,
`profile_observations` (raw event log enabling rebuilds). **Profiles survive service restarts.**

**Update policy** (`config/policy.yaml`):
`behavioral.update_policy: only_below_block` (default — skips profile updates for BLOCK-level
or high-score mail → **poisoning prevention**), `min_observations_before_anomaly: 5`.

**Fusion integration:** 13 features as independent inputs, weight-capped so behavioral
features can never dominate the final decision by themselves.

**Tests (10):** normal repeated communication · new sender · new recipient relationship ·
abnormal sending time · abnormal attachment behavior · abnormal URL behavior · sender domain
change · display-name change · profile persistence (store reopen) · profile poisoning
prevention (BLOCK mail does not alter profile).

**Metrics:** whether behavioral features improve precision, recall, F1, false-positive rate,
detection of previously unseen senders, and detection of BEC-style anomalies (via WS12
ablation configuration F).

### 7.2 WS3 — HTML structural analysis · `guard/html/`

**`features.py`** — all structural counts (~28 features): forms, input elements, password
inputs, external form-action domains, iframes, script count, inline/external script counts,
hidden element count, hidden text count, CSS obfuscation indicators, suspicious style
attributes, zero-sized elements, transparent elements, suspicious redirects, data-URI usage,
base64-like content, external resource count, external image domains, external CSS domains,
HTML size, DOM depth, DOM node count, anchor count, mismatched anchor/href count, form
submission domain mismatch. BeautifulSoup static parse — **JavaScript never executed**.

**`forms.py`** — explicit detections: password form + external submission domain; unexpected
form elements; iframe-based credential collection; credential-collection indicators.

**`javascript.py`** — static analysis only: Shannon entropy of script bodies, suspicious JS
tokens (`eval`, `atob`, `unescape`, `String.fromCharCode`, `document.write`,
`XMLHttpRequest`, `location`), encoded-JavaScript indicators (base64/hex/percent density).

**`obfuscation.py`** — CSS hiding (`display:none`, `visibility:hidden`, `opacity:0`,
`font-size:0`, color==background, offscreen absolute positioning), hidden phishing-text
extraction, meta-refresh/redirect indicators.

**`model.py`** — returns:

```python
HTMLRiskResult(
    html_risk_score: float,
    form_risk_score: float,
    obfuscation_score: float,
    external_resource_score: float,
    features: dict[str, float],
    evidence: list[str],
)
```

**Complexity ≠ malicious.** Legitimate marketing email contains complex HTML, tracking URLs,
images, external CSS. Raw structural features flow to FusionEngine where they are
**contextualized** by domain reputation, sender reputation, URL features, authentication,
intent/tactic features, and behavioral profile (via `AnalysisContext`). No standalone
complexity-based decision.

**Tests (9, adversarial):** hidden text · nested HTML · harmless newsletter HTML · HTML
credential form · form action mismatch · encoded scripts · iframe · CSS hiding · benign
tracking links.

### 7.3 WS5 — Safe static attachment analysis · `guard/attachment/`

**`magic.py`** — magic-byte signature table; **never trust MIME headers or file extensions**
→ `extension_mismatch`, `mime_magic_mismatch` features. Supported: PDF, DOC, DOCX, XLS, XLSX,
PPT, PPTX, ZIP, EML, ICS, HTML, SVG, TXT, images.

**`archive.py`** — recursive archive inspection (zipfile/tarfile) to a safe configurable depth;
**decompression-bomb protection** via file-count, size, and nesting limits + compression-ratio
cap (all in `policy.yaml`).

**`office.py`** — OLE macro detection (`vbaProject.bin`), OOXML external relationships
(`*.rels`), embedded URLs in document XML, suspicious external resources.

**`pdf.py`** — static pypdf parse: embedded URLs (`/URI`), forms (`/AcroForm`), JavaScript
indicators (`/JavaScript`, `/AA`), external actions (`/OpenAction`, `/Launch`).

**`features.py`** — the 14 required features:
filename_risk, extension_mismatch, mime_magic_mismatch, file_entropy, archive_depth,
nested_archive_count, embedded_url_count, embedded_domain_count, macro_indicator,
external_relationship_count, script_indicator, suspicious_pdf_action,
suspicious_office_relationship, attachment_size_anomaly, attachment_hash_reputation.

**`analyzer.py`** — orchestrator; returns:

```python
AttachmentAnalysisResult(
    risk_score: float,
    per_attachment: list[AttachmentResult],
    aggregate_features: dict[str, float],
    evidence: list[str],
)
```

**Never automatically block solely because of a generic feature such as "contains a macro"** —
the feature is combined with sender, URL, text, authentication, and behavioral evidence in
fusion. **Attachments are never executed.** SVG handled as text: detect scripts, external
references, suspicious links, event handlers.

**Tests (10):** legitimate PDF · phishing PDF · macro document · ordinary spreadsheet ·
nested ZIP · extension spoofing · SVG with external reference · malformed attachment ·
oversized archive · decompression-bomb protection.

### 7.4 WS2 — Cross-modal consistency · `guard/multimodal/`

Twelve deterministic consistency signals:

1. Displayed URL text vs actual href → `link_consistency.py`
2. Sender display name vs sender domain → `identity_consistency.py`
3. Sender address vs Reply-To → `identity_consistency.py`
4. Sender domain vs claimed organization/brand → `identity_consistency.py`
5. Email text vs URL destination → `semantic_consistency.py`
6. OCR text vs URL destination → `link_consistency.py`
7. QR-decoded URL vs surrounding message text → `link_consistency.py`
8. Subject vs body → `semantic_consistency.py`
9. Attachment filename vs MIME type → `semantic_consistency.py`
10. Attachment content description vs message context → `semantic_consistency.py`
11. Claimed brand vs actual domain → `identity_consistency.py`
12. Claimed organization vs historical sender identity (behavioral profiles) → `identity_consistency.py`

Features:

```
display_href_mismatch          display_domain_mismatch
sender_identity_mismatch        replyto_identity_mismatch
brand_domain_mismatch           text_url_semantic_mismatch
ocr_url_mismatch                qr_context_mismatch
subject_body_mismatch           attachment_context_mismatch
brand_visual_domain_mismatch    identity_history_mismatch
```

**`consistency.py`** orchestrates and returns:

```python
ConsistencyResult(
    overall_consistency_score: float,
    contradiction_score: float,
    features: dict[str, float],
    evidence: list[str],
)
```

`contradiction_score` increases as **independent modalities disagree** — e.g., display text
claims microsoft.com, href points elsewhere, sender claims Microsoft from an unrelated domain,
body requests credentials → several independent features fire, not one hard-coded rule.

**Semantic similarity:** deterministic token-Jaccard / TF-IDF cosine; optionally SecureBERT
embedding cosine (existing non-generative encoder) — locally executable and deterministic.

**Brand engine:** configurable protected-brand dictionary in `policy.yaml` (each brand with
`legitimate_domains`); Unicode canonicalization + punycode decoding (`idna`); edit distance
(Levenshtein); confusable-character distance; domain-token similarity; **exact legitimate
domains distinguished from lookalike domains**.

**Tests (8):** legitimate branded email · display/href mismatch · Reply-To mismatch ·
homoglyph brand · QR URL conflicting with visible text · benign newsletter · legitimate
third-party mailing services (SendGrid/etc. verified allowed) · forwarded messages and
mailing lists.

---

## 8. Phase 2 — Temporal Graph, Campaigns & Intent

> ~7–8 dev-days. Depends on Phase 1 signals for contextualization.

### 8.1 WS4 + WS9 — Temporal relationship graph + campaign similarity · `guard/graph/`

**`engine.py`** — supersedes `guard/store/graph.py` (kept briefly as an adapter, then removed).
Preserves the existing heterogeneous node types — Email, SenderAddress, SenderDomain,
ReplyToDomain, URL, URLDomain, IP, ASN, Brand, AttachmentHash — and **adds**: Recipient,
Campaign, AttachmentType, InfrastructureCluster.

**Every relationship retains timestamps**: `first_seen`, `last_seen`, `observation_count`,
plus derived `time_since_first_seen`, `time_since_last_seen`, `edge_velocity`, `node_velocity`.

**`temporal.py`** — the 16 required temporal features:
domain_age_in_system, sender_age_in_system, url_first_seen, infrastructure_first_seen,
new_edge_rate, new_node_rate, sender_burstiness, campaign_burstiness, domain_burstiness,
infrastructure_churn, campaign_growth_rate, relationship_age, shared_infrastructure_count,
shared_sender_count, shared_url_count, shared_attachment_count.

**`clustering.py`** (WS9) — campaign membership via **7 independent similarity channels**:

1. MinHash similarity on normalized text (fixed seed — deterministic)
2. Character n-gram similarity
3. URL-domain overlap
4. Attachment-hash overlap
5. Sender/infrastructure overlap
6. Subject similarity
7. Security-encoder embedding similarity

→ `text_similarity`, `url_similarity`, `sender_similarity`, `infrastructure_similarity`,
`attachment_similarity`, `subject_similarity`, `embedding_similarity` → combined
`campaign_membership_score` requiring **≥ 2 independent channels above threshold**
(anti-collapse guard: unrelated messages sharing common words like *urgent / account /
verification / payment* never merge on word overlap alone).

```python
Campaign(
    campaign_id, first_seen, last_seen, member_count, confidence,
    dominant_brand, dominant_tactic, shared_domains, shared_ips, shared_attachments,
)
```

**Campaign expansion detection:** several emails within a short period sharing normalized
textual structure / URL domains / redirect destinations / sender infrastructure / attachment
hashes / brand impersonation target → create or update a Campaign node. **No automatic
retro-BLOCK**; instead compute `campaign_risk_score`, `campaign_membership_confidence`,
`confirmed_campaign_member`. Retro-flagging only on confirmed malicious campaign evidence
above configurable promotion thresholds (or human confirmation).

**Graph-poisoning prevention:**
- one low-confidence detection is never ground truth;
- configurable confidence or human confirmation required before promoting a node to malicious;
- evidence provenance stored on every reputation relationship.

**`persistence.py`** — SQLite `graph_nodes` / `graph_edges` tables (timestamps, attributes
JSON); load on startup, periodic snapshots. Graph state survives restarts.

**`features.py`** — assembles:

```python
TemporalGraphResult(
    graph_risk_score: float,
    campaign_id: str | None,
    campaign_membership_score: float,
    temporal_features: dict[str, float],
    related_entities: list[dict],
    evidence: list[str],
)
```

**Tests (7 + 7):** first-time domain · repeated campaign · burst campaign · benign mailing
campaign · shared legitimate infrastructure · malicious infrastructure reuse · graph poisoning
attempt ‖ exact duplicate · lightly modified duplicate · paraphrased same campaign · unrelated
phishing emails · legitimate bulk mailing · two independent campaigns using the same brand.

**Dashboard:** graph output updated to display timestamps and relationship evidence (§12).

### 8.2 WS10 — Structured intent features · `guard/nlp/intent.py`

Keeps the existing tactic labels untouched: urgency, authority_impersonation,
credential_request, payment_gift_card, link_bait, attachment_lure.

Deterministic derived features, computed **only from combinations of classifier outputs and
verified technical signals**:

```
credential_harvesting_score   financial_fraud_score      account_takeover_score
business_email_compromise_score   malicious_attachment_score   social_engineering_score
```

Example rule: `credential_request > threshold AND suspicious URL > threshold AND
brand-domain mismatch ⇒ credential_harvesting_score increases`. **No single language feature
is sufficient for BLOCK** — enforced structurally (intent features are bounded fusion inputs,
never hard rules).

```python
IntentResult(
    tactics, tactic_confidence, derived_intent_scores, evidence,
)
```

The same structured intent data feeds ExplainEngine so explanations describe the detected
attack pattern without free-form reasoning.

**Tests (8):** credential phishing · payment fraud · BEC · benign password-reset
notification · legitimate invoice · ordinary newsletter · attachment lure · QR lure.

---

## 9. Phase 3 — Fusion v2, Uncertainty & ExplainEngine v2 (WS7)

> ~4 dev-days. Registry refactor is additive; current heuristic remains the no-model fallback.

**`guard/fusion/meta_model.py` (refactor)**
- Component registry: every Phase-1/2 module registered via `safe_run`.
- Pluggable scorer: `fusion_model.lgbm` (LightGBM/LogisticRegression + isotonic calibration)
  when the artifact exists; existing heuristic as deterministic fallback otherwise.
- Feature matrix assembled from all `ComponentResult.features` dicts (named features).

**`guard/fusion/uncertainty.py` (new)**
- Component agreement across the 8 required components: text classifier, URL model, header
  rules, HTML model, behavioral model, attachment model, graph model, cross-modal
  consistency — via normalized dispersion (e.g., `1 − MAD/mean` of component scores), handling
  missing components.
- Produces: `uncertainty_score`, `prediction_confidence`, `decision_margin`, `evidence_count`,
  `component_agreement`, `component_disagreement`.
- Disagreement cases are detected: `text=0.95, url=0.08, headers=0.10, behavior=0.12` (high
  disagreement) is **not** treated like `text=0.91, url=0.88, headers=0.92, behavior=0.87`
  (agreement).
- **Calibrated probabilities** used rather than raw model outputs (isotonic/Platt maps loaded
  from calibration artifacts; identity map fallback).

**REVIEW level** added to the existing decision levels:
`ALLOW < flag_threshold ≤ FLAG < review_window ≤ BLOCK` — REVIEW triggers for configurable
high-risk / high-uncertainty cases. **Uncertainty is not a replacement for the risk score.**

**Extended `Verdict`:**

```python
Verdict(
    score, calibrated_probability, uncertainty, confidence,
    level,            # ALLOW | FLAG | REVIEW | BLOCK
    reasons, component_scores,  # + preserved evidence list (WS11)
)
```

**ExplainEngine v2:**
- deterministic evidence ranking (top-N by `normalized_score × severity`);
- states why risk is high, which components agreed, which disagreed, and why the system
  selected FLAG / BLOCK / REVIEW;
- renders only from Evidence — tests assert no invented information.

**Tests (6):** all components agree · one component disagrees · only one component fires ·
missing component · model failure · calibrated edge cases.
**Benchmarks:** false positives measured **separately for BLOCK, FLAG, REVIEW**.

---

## 10. Phase 4 — Data Pipeline, Splitting & Calibration

> ~5–6 dev-days including dataset bootstrap.

### 10.1 Dataset bootstrap (prerequisite for calibration/ablation numbers)

| Task | File | Details |
|---|---|---|
| 10.1.1 | `scripts/download_datasets.py` | Auto-download: HuggingFace `ealvaradob/phishing-dataset`, `zefang-liu/phishing-email-dataset`, SpamAssassin corpus, PhiUSIIL URL dataset; feed snapshots (PhishTank, OpenPhish, URLhaus, Tranco top-1M). Checksum verification; save to `data/raw/`. |
| 10.1.2 | `scripts/build_features.py` | Parse raw emails → extract subject+body → normalize (reuse `guard/parse/normalizer`) → per-URL lexical features → labeled dataframe with `source`, `dataset_name`, `collection_time`, `label` metadata columns. Saves to `data/processed/` for splitting. |

### 10.2 WS13 — Campaign-aware dataset splitting · `scripts/split_dataset.py`

Before train/validation/test splitting:

1. normalize text;
2. canonicalize URLs;
3. canonicalize domains;
4. calculate MinHash signatures (fixed seed);
5. calculate character n-gram fingerprints;
6. calculate attachment hashes;
7. identify duplicate and near-duplicate groups;
8. identify campaign groups where possible.

**`group_id` is the primary split key** — no group may appear simultaneously in train and
test. **No random row-level splitting when a campaign spans multiple rows.** Group-wise split
maintaining class balance. Metadata: `source, dataset_name, campaign_id, group_id,
collection_time, label`.

Outputs:
`data/processed/train.parquet`, `data/processed/validation.parquet`,
`data/processed/test.parquet`, `data/processed/test_adversarial.parquet`.

**Leakage report** (`data/processed/leakage_report.json`): duplicate_count,
near_duplicate_count, cross_split_duplicate_count, cross_split_campaign_count,
source_distribution, class_distribution, time_distribution. **The build explicitly fails if
cross-split duplicates exceed the configured tolerance.**

### 10.3 WS8 — Threshold calibration · `scripts/calibrate_thresholds.py`

- Evaluates candidate thresholds on **validation data only** — the final test set remains
  completely untouched until evaluation.
- Calculates: precision, recall, F1, PR-AUC, false-positive-rate, false-negative-rate,
  precision_at_recall, recall_at_precision, BLOCK_false_positive_rate,
  FLAG_false_positive_rate (and REVIEW FP rate).
- Separate threshold evaluation for attack classes: phishing, BEC, credential phishing,
  QR phishing, attachment phishing, brand impersonation.
- **Cost-sensitive validation** with configurable costs: `false_positive_cost`,
  `false_negative_cost`, `block_cost`, `review_cost` (in `policy.yaml`).
- **Does not optimize only for F1.**

Emits `data/processed/calibrated_policy.json`:

```json
{
  "block_threshold": 0.85,
  "flag_threshold": 0.50,
  "review_threshold": 0.70,
  "calibration_method": "cost_sensitive_validation",
  "validation_samples": 12345,
  "timestamp": "2026-09-28T00:00:00Z"
}
```

**Runtime loads `calibrated_policy.json`** (via `guard/config.py`) rather than hard-coded
values; **safe fallback defaults remain in `policy.yaml`.**

---

## 11. Phase 5 — Adversarial Framework & Full Evaluation

> ~6–7 dev-days.

### 11.1 WS6 — Adversarial transformation & evaluation · `guard/adversarial/`

**`mutations.py`** — the 19 required deterministic transformations (pure functions on raw
MIME; **no generative AI**; malicious semantic intent preserved):

Unicode homoglyph substitution · zero-width insertion · bidirectional control characters ·
whitespace manipulation · HTML hiding · HTML restructuring · URL encoding · hxxp
obfuscation · dot/bracket obfuscation · benign-text padding · subject/body separation ·
URL display-text manipulation · domain token mutation · typo insertion · punctuation
mutation · text truncation · image-only phishing · QR-only phishing · attachment-only
phishing.

**`generator.py`** — every transformed sample retains `original_sample_id`,
`transformation_type`, `transformation_parameters`, `expected_label`. Maintains a **separate
adversarial holdout set** — never trained/tested on identical transformations.

**`evaluator.py`** — evaluates both clean accuracy (clean_precision, clean_recall, clean_f1,
clean_pr_auc) and adversarial robustness (adversarial_precision, adversarial_recall,
adversarial_f1, robustness_drop). Per transformation: detection_rate, false_negative_rate,
score_shift, confidence_shift. **Differential evaluation:** original_email_score,
transformed_email_score, score_delta — a robust detector minimizes score degradation when
harmlessly obfuscating the same phishing content. Runs against **text model, URL model, HTML
model, fusion model**.

**`reports.py`** — machine-readable JSON + human-readable Markdown.

**Tests:** unit tests for **every** transformation (identity of preserved label, determinism
of output).

### 11.2 WS12 — Ablation & evaluation · `scripts/evaluate.py`, `scripts/ablation.py`, `docs/evaluation.md`

Configurations:

| | Configuration |
|---|---|
| A | Header rules only |
| B | Text only |
| C | Text + URL |
| D | Text + URL + headers |
| E | + HTML |
| F | + behavioral profiling |
| G | + cross-modal consistency |
| H | + attachments |
| I | + graph |
| J | + campaign clustering |
| K | Full PhishGuard |

Per configuration: precision, recall, F1, PR-AUC, ROC-AUC, false-positive-rate,
false-negative-rate, **FPR at 95% recall**, median latency, p95 latency.

Attack classes evaluated separately: credential phishing, BEC, QR phishing, attachment
phishing, brand impersonation, URL obfuscation, homoglyph phishing, zero-width phishing,
image-only phishing, campaign variants.

Test settings: (1) random stratified, (2) source-held-out, (3) adversarial, (4) time-based
where data allows. **No optimization on the final test set.** Campaign-aware deduplication
before splitting guarantees no near-duplicate leaks (WS13). Per-source and aggregate
performance reported.

**Deliverable:** a table showing the incremental contribution of every new feature family —
proving each component adds measurable value rather than complexity (this is the ablation
gate referenced by every workstream acceptance).

---

## 12. Phase 6 — Presentation & Polish

> ~3 dev-days.

| Task | File | Details |
|---|---|---|
| 12.1 | `guard/api/routes/graph.py` | `GET /graph/{node_id}?hops=2` (subgraph JSON with **timestamps + relationship evidence**), `GET /campaigns` |
| 12.2 | `guard/api/routes/analysis.py`, `feedback.py` | verdict details incl. component scores, explanation, evidence; feedback recording |
| 12.3 | `dashboard/src/components/` | `EvidenceTable` (category / signal / observed value / risk contribution / confidence / source — fed by WS11), `CampaignList`, temporal `GraphView` (Cytoscape.js, timestamps + evidence), REVIEW-level badge |
| 12.4 | `roundcube_plugin/` | amber "review" banner state alongside existing red/amber |
| 12.5 | `docs/evaluation.md`, `README.md` | evaluation report; updated architecture diagram + setup |
| 12.6 | Compliance pass | run §16 checklist; `graphify update .` after code changes if graphify is in use |

---

## 13. Fusion Integration Matrix

| Component | Feature vector | Evidence category |
|---|---|---|
| Text (existing) | `p_text` | TEXT |
| URL (existing) | `p_url_max` + lexical set | URL |
| Headers (existing) | 6 boolean features | HEADER, AUTHENTICATION |
| Tactics + intent (WS10) | 6 tactic scores + 6 derived intent scores | TACTIC |
| Behavioral (WS1) | 13 anomaly features (weight-capped, never dominant) | BEHAVIOR |
| Multimodal (WS2) | 12 consistency features | CONSISTENCY |
| HTML (WS3) | ~28 structural features + 4 risk scores | HTML |
| Attachment (WS5) | 14 aggregate features | ATTACHMENT |
| Graph/campaign (WS4/9) | 16 temporal + campaign scores | GRAPH, CAMPAIGN |
| Fusion (WS7) | uncertainty, agreement, margin, calibrated probability | — |

---

## 14. Test Matrix

| Test module | Covers |
|---|---|
| `tests/test_contracts.py` | `safe_run` isolation, latency recording, fallback, evidence emission (Phase 0) |
| `tests/test_behavioral.py` | WS1's 10 scenarios |
| `tests/test_html.py` | WS3's 9 adversarial scenarios |
| `tests/test_attachment.py` | WS5's 10 scenarios |
| `tests/test_multimodal.py` | WS2's 8 scenarios |
| `tests/test_graph_temporal.py` | WS4's 7 + WS9's 7 scenarios |
| `tests/test_intent.py` | WS10's 8 scenarios |
| `tests/test_uncertainty.py` | WS7's 6 scenarios + per-level FP benchmarks |
| `tests/test_evidence.py` | evidence ranking, no invented explanation facts |
| `tests/test_mutations.py` | one test per transformation (19) |
| `tests/test_split_dataset.py` | leakage report, group isolation, build-failure tolerance |
| `tests/test_calibration.py` | threshold sweep, cost objective, artifact loading + fallback |
| `tests/test_e2e_pipeline.py` | factory email → full pipeline → verdict with evidence + latency, component fault injection never blocks pipeline |

---

## 15. Policy, Config & Schema Changes

### 15.1 `config/policy.yaml` additions

```yaml
behavioral:
  update_policy: only_below_block   # always | only_below_block | confirmed_only
  min_observations_before_anomaly: 5
  profile_db_path: /data/profiles.db

brands:                             # extends protected_brands
  microsoft: { legitimate_domains: [microsoft.com, live.com, office.com] }
  google:   { legitimate_domains: [google.com, gmail.com] }
  # ...

html:
  max_dom_nodes: 20000
  max_html_bytes: 2097152

attachment:
  max_depth: 3
  max_files_per_archive: 500
  max_total_uncompressed_bytes: 104857600
  max_compression_ratio: 100
  max_attachment_bytes: 10485760

graph:
  campaign_promotion_threshold: 0.75
  campaign_membership_min_channels: 2
  similarity_weights: { text: 0.3, url: 0.2, sender: 0.15, attachment: 0.1, subject: 0.1, embedding: 0.15 }

fusion:
  review_threshold: 0.70            # fallback; overridden by calibrated_policy.json
  uncertainty_review_gate: 0.6

calibration:
  false_positive_cost: 1.0
  false_negative_cost: 10.0
  block_cost: 2.0
  review_cost: 0.5
  leakage_tolerance: 0
```

### 15.2 SQLite schema additions (additive migrations in `guard/store/database.py`)

- `sender_profiles`, `relationship_profiles`, `profile_observations` (WS1)
- `graph_nodes`, `graph_edges`, `campaigns` (WS4/9)
- `evidence` (optional persistence of evidence per verdict for audit)
- `emails` gains `recipients_json`, `received_at`; `verdicts` gains `calibrated_probability`,
  `uncertainty`, `confidence`, `evidence_json`

---

## 16. Compliance Checklist

| Constraint | How satisfied |
|---|---|
| No generative AI / LLM / prompt-based classifier | All logic statistical (MinHash, TF-IDF, robust stats, edit distance) or non-generative encoders; ExplainEngine is template + evidence only |
| Deterministic | Fixed MinHash seeds, no runtime randomness, static calibration maps, stable evidence ranking |
| CPU / local / Docker | No heavy deps; pure-Python CPU modules; existing ONNX/LightGBM class unchanged |
| Email = untrusted data | `safe_run` isolation, size caps, no JS execution, no attachment execution, bomb protection, parameterized SQL |
| Don't replace existing models | Existing classifier interfaces untouched; FusionEngine refactored additively (registry + fallback keeps current behavior) |
| Fallback / never blocks pipeline | `safe_run` returns degraded neutral result on any component failure |
| Profile poisoning prevention | Post-verdict update gating (`only_below_block` default), graph promotion thresholds + provenance |
| Runtime loads calibrated thresholds | `calibrated_policy.json` loader with `policy.yaml` fallback defaults |
| No training on final test set | Calibration uses validation split only; adversarial holdout separate; leakage report fails build |

---

## 17. Sequencing, Effort & Cut-Line

Total ≈ **35–40 dev-days** (single developer):

| Phase | Duration | Parallelizable |
|---|---|---|
| 0 Foundations & contracts | 2–3 d | — |
| 1 Behavioral / HTML / Attachment / Multimodal | 9–11 d | 4 independent tracks |
| 2 Graph + campaigns + intent | 7–8 d | 2 tracks after 1 |
| 3 Fusion v2 + uncertainty + explainer v2 | 4 d | — |
| 4 Dataset bootstrap + splitting + calibration | 5–6 d | 2 tracks |
| 5 Adversarial + ablation | 6–7 d | 2 tracks |
| 6 Presentation & polish | 3 d | — |

**Cut-line (time-constrained):** Phase 0 → WS1 → WS3 → WS4/9 → WS7 → WS13/WS8 → WS5 → WS2 →
WS6 → WS12. Ablation may run reduced configurations, but **A / B / F / K minimum must be
reported**.

---

## 18. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| `ParsedEmail` payload retention raises memory use | Medium | hard caps (10 MB/attachment, 2 MB HTML), payload released after analysis |
| Parser extension touches live watcher path | High | factory-based regression tests land **before** parser changes (Phase 0.4) |
| No real labeled data yet — ablation/calibration numbers impossible | High | dataset bootstrap (§10.1) precedes Phase 4/5; synthetic factory covers unit level meanwhile |
| Behavioral features dominate decisions → FP surge | Medium | weight-capped fusion features; ablation configuration F gates acceptance; FP benchmark per level |
| Campaign over-merging (legit bulk mail) | Medium | ≥2 independent similarity channels + benign-bulk test case + promotion thresholds |
| Stub models make calibrated probabilities degenerate | Low | identity calibration fallback; calibration artifacts regenerated when real models land |
| Graph/profile DB contention with watcher loop | Low | SQLite WAL mode, async store access, post-verdict updates off the hot path |
