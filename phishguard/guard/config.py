from pydantic_settings import BaseSettings
from typing import Optional
import yaml
import os

class Settings(BaseSettings):
    mail_domain: str = "demo.local"
    mail_admin_user: str = "admin@demo.local"
    mail_admin_pass: str = "changeme"
    dovecot_master_user: str = "backend"
    dovecot_master_pass: str = "changeme"
    sqlite_path: str = "/data/phishguard.db"
    log_level: str = "INFO"
    
    text_model: str = "cybersectony/phishing-email-detection-distilbert_v2.1"
    security_encoder: str = "ehsanaghaei/SecureBERT"
    url_phish_model: str = "ealvaradob/bert-finetuned-phishing"

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()

# Load policy.yaml if needed
POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "policy.yaml")
policy = {}
if os.path.exists(POLICY_PATH):
    with open(POLICY_PATH, 'r') as f:
        policy = yaml.safe_load(f)
