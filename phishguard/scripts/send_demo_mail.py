import argparse
import smtplib
from email.message import EmailMessage

EMAILS = {
    "phish": {
        "subject": "Action Required: Update your account details",
        "body_plain": "Please click the link below to update your account details.\nhttp://account-update-secvices.com/login",
        "body_html": "<p>Please click the link below to update your account details.</p><p><a href='http://account-update-secvices.com/login'>Update Account</a></p>",
        "from": "attacker@demo.local",
    },
    "ceo_fraud": {
        "subject": "Urgent wire transfer",
        "body_plain": "I need you to process an urgent wire transfer to our new vendor. Please do this immediately.",
        "body_html": "<p>I need you to process an urgent wire transfer to our new vendor. Please do this immediately.</p>",
        "from": "boss@demo.local",
    },
    "homoglyph": {
        "subject": "Security Alert: Google Account",
        "body_plain": "We detected suspicious activity. Please verify your identity at http://gọogle.com/verify",
        "body_html": "<p>We detected suspicious activity. Please verify your identity at <a href='http://gọogle.com/verify'>Google Verification</a></p>",
        "from": "attacker@demo.local",
    },
    "qr": {
        "subject": "Scan to view your invoice",
        "body_plain": "Please scan the attached QR code to view your invoice.",
        "body_html": "<p>Please scan the attached QR code to view your invoice.</p>",
        "from": "attacker@demo.local",
    },
    "legit": {
        "subject": "Weekly Team Update",
        "body_plain": "Hi team, here is the weekly update. Everything is on track.",
        "body_html": "<p>Hi team, here is the weekly update. Everything is on track.</p>",
        "from": "boss@demo.local",
    }
}

def send_mail(args, mail_type):
    data = EMAILS[mail_type]
    msg = EmailMessage()
    msg['Subject'] = data['subject']
    msg['From'] = args.sender or data['from']
    msg['To'] = args.to

    msg.set_content(data['body_plain'])
    msg.add_alternative(data['body_html'], subtype='html')

    try:
        with smtplib.SMTP(args.smtp_host, args.smtp_port) as server:
            server.send_message(msg)
        print(f"Sent {mail_type} email to {args.to}")
    except Exception as e:
        print(f"Failed to send {mail_type} email: {e}")

def main():
    parser = argparse.ArgumentParser(description="Send demo emails for PhishGuard testing")
    parser.add_argument('--type', choices=['phish', 'ceo_fraud', 'homoglyph', 'qr', 'legit', 'all'], required=True)
    parser.add_argument('--from', dest='sender', help="Override sender address")
    parser.add_argument('--to', default='victim@demo.local', help="Recipient address")
    parser.add_argument('--smtp-host', default='localhost', help="SMTP host")
    parser.add_argument('--smtp-port', type=int, default=25, help="SMTP port")
    
    args = parser.parse_args()

    if args.type == 'all':
        for t in EMAILS.keys():
            send_mail(args, t)
    else:
        send_mail(args, args.type)

if __name__ == "__main__":
    main()
