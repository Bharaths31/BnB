# PhishGuard

PhishGuard is a real-time, fully local, deterministic AI phishing detection system. It connects directly to an IMAP mailbox, actively monitors for new incoming emails, and evaluates them using a specialized ONNX-based multi-model detection pipeline. 

All reasoning is deterministic, fast (sub-500ms), and runs entirely locally on CPU, ensuring zero external data leakage and zero prompt-injection risk from Generative LLMs.

## Architecture

PhishGuard combines several modular components:
1. **Mailserver Infrastructure:** `docker-mailserver` (Postfix + Dovecot) serving as the test bed.
2. **Dashboard & Webmail:** `roundcube` webmail for interacting with the mailbox, and a React `dashboard` to monitor events in real-time.
3. **Backend Service:** A FastAPI server containing the `MailboxWatcher` and the ML detection engine.
4. **Detection Pipeline:** 
   - **Text Classifier:** A fine-tuned DistilBERT model (`cybersectony/phishing-email-detection-distilbert_v2.1`) running via `onnxruntime`.
   - **Tactic Classifier (Future):** A multi-label DistilBERT identifying specific tactics (Urgency, Authority, etc).
   - **Graph Engine (Future):** Relationship maps tracking shared infrastructure, domains, and sender histories.
   - **Header Rules:** Hardcoded heuristics validating SPF/DKIM/DMARC and domain alignment.
5. **Fusion Meta-Model:** Aggregates signals into a final verdict (ALLOW, FLAG, BLOCK).

## Requirements
- Docker and Docker Compose
- Python 3.11 (if running backend outside Docker)
- *Optional:* A Windows laptop with a dedicated GPU connected via Github for re-training or fine-tuning models. The models run efficiently on CPU via ONNX, but fine-tuning `DistilBERT` or `SecureBERT` on custom phishing datasets will significantly benefit from GPU acceleration.

## Setup & Execution

We have provided a unified `manage.py` script that handles the entire setup process.

### 1. Initialize and Start Services
```bash
# Set execution permissions
chmod +x manage.py

# This command will:
# 1. Start all Docker containers (Mailserver, Backend, Dashboard, Roundcube)
# 2. Automatically download and export the ONNX models into the backend container
# 3. Send a suite of demo phishing and legitimate emails to populate the system
./manage.py setup_all
```

### 2. Manual Commands
If you prefer running individual steps, you can use the script actions:
- Start containers: `./manage.py start`
- Stop containers: `./manage.py stop`
- Download ONNX models: `./manage.py setup_models`
- Send Demo Emails: `./manage.py demo`

### 3. Verification

Once `setup_all` finishes:
- **Dashboard:** Open `http://localhost:3000` to see the live verdict stream.
- **Webmail:** Open `http://localhost:8080`, log in as `victim@demo.local` (Password: `changeme`), and verify that phishing emails are moved to the `Quarantine` folder and flagged emails show a warning banner.
- **API:** Check the events at `http://localhost:8000/api/events`.

## Model Pipeline and Training

PhishGuard currently downloads the `cybersectony/phishing-email-detection-distilbert_v2.1` model directly from HuggingFace and exports it to ONNX for fast, lightweight inference.

If you wish to train or fine-tune models locally:
1. Connect to your Windows laptop with the GPU via Github (e.g. using Codespaces or SSH).
2. Set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Use the notebooks in `notebooks/` (e.g., `train_text_model.ipynb`) to perform further domain adaptation using datasets like `ealvaradob/phishing-dataset` or `SpamAssassin`.
4. Export the resulting PyTorch model using Optimum:
   ```bash
   optimum-cli export onnx --model path/to/your/fine-tuned-model --task text-classification data/processed/text_classifier_onnx
   ```
5. Place the exported ONNX model in `data/processed/text_classifier_onnx` and PhishGuard will automatically load it.
