#!/bin/bash
set -e

echo "Populating mailboxes with demo emails..."
python3 scripts/send_demo_mail.py --type all

echo "Done! The backend IMAP watcher should now process these."
echo "Check the dashboard at http://localhost:3000 to see the verdicts."
