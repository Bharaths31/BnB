import asyncio
from imapclient import IMAPClient
from guard.config import settings
from guard.store.events import save_email, save_verdict, get_last_uid, update_last_uid
from guard.store.audit import log_action
from guard.parse.parser import parse_email
from guard.models import Verdict
from guard.fusion.fusion_engine import fusion_engine
from guard.explainer.engine import explainer_engine
import structlog
import traceback

logger = structlog.get_logger()

class MailboxWatcher:
    def __init__(self, user: str, host: str):
        self.user = user
        self.host = host
        self.client = None
        self.running = False

    async def run(self):
        self.running = True
        backoff = 1
        while self.running:
            try:
                self.client = IMAPClient(self.host, ssl=False) # For demo, ssl=False
                self.client.login(f"{self.user}*{settings.dovecot_master_user}", settings.dovecot_master_pass)
                self.client.select_folder('INBOX')
                
                # Check for quarantine folder
                folders = [f[2] for f in self.client.list_folders()]
                if 'Quarantine' not in folders:
                    self.client.create_folder('Quarantine')
                
                logger.info("Connected to IMAP", user=self.user)
                backoff = 1
                
                while self.running:
                    # Sync initial state
                    last_uid = await get_last_uid(self.user)
                    messages = self.client.search(['UID', f'{last_uid + 1}:*'])
                    for uid in messages:
                        await self.process_message(uid)
                        
                    # IDLE
                    self.client.idle()
                    logger.info("IDLEing...", user=self.user)
                    responses = await asyncio.to_thread(self.client.idle_check, timeout=1740)
                    self.client.idle_done()
                    
                    if responses:
                        logger.info("IDLE responses", responses=responses)
                        
            except Exception as e:
                logger.error("IMAP connection error", error=str(e), traceback=traceback.format_exc())
                if self.client:
                    try:
                        self.client.logout()
                    except:
                        pass
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def process_message(self, uid: int):
        logger.info("Processing message", uid=uid)
        msg_data = self.client.fetch(uid, ['RFC822'])
        raw_email = msg_data[uid][b'RFC822']
        
        parsed = parse_email(raw_email)
        await save_email(uid, self.user, parsed.subject, parsed.from_addr, parsed.raw_headers)
        
        verdict = fusion_engine.evaluate(uid, parsed)
        
        # Add explanation using ExplainerEngine
        verdict.explanation = explainer_engine.explain(verdict)
            
        await save_verdict(verdict)
        
        if verdict.level == "BLOCK":
            self.client.copy(uid, 'Quarantine')
            self.client.delete_messages(uid)
            self.client.expunge()
            await log_action(uid, "QUARANTINE", "Blocked by rules")
            logger.info("Quarantined message", uid=uid)
        elif verdict.level == "FLAG":
            self.client.set_flags(uid, [b'$Phishing'])
            await log_action(uid, "FLAG", "Flagged by rules")
            logger.info("Flagged message", uid=uid)
            
        await update_last_uid(self.user, uid)

    def stop(self):
        self.running = False
        if self.client:
            self.client.idle_done()
            self.client.logout()
