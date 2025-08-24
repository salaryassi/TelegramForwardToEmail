#!/usr/bin/env python3
"""
Telegram → Gmail Forwarder (Full Rewrite)

Goals (from user requirements):
 - Always start with a friendly **Setup Wizard** if anything is missing/broken, or when user chooses Reset.
 - Ask for, validate, and persist everything: Telegram API ID/HASH, Gmail sender/receiver, and the single listener
   (either bot username **or** numeric user id). Never run for more than one user.
 - Detect and explain common problems (missing credentials.json, missing/invalid token.json, Telethon lock issues, etc.).
 - Provide a simple **Main Menu** to: start the forwarder, change listener, authorize Gmail, resend outbox, or reset.
 - Forward only messages matching the listener and (by default) **edit** Google verification messages starting with
   patterns like `G-123456` into the compact format:
      Phone number : <Destination/Phone>
      Google verification codes: <Code>
   Add a runtime toggle: `--no-edit` to bypass editing for testing.
 - If email sending fails, store messages (including media) in `./outbox` and provide a resend action.
 - Logging toggle `--log` to also write logs to `tgfwd.log`.

Files used:
 - config.json                 → user configuration (safe to edit by hand)
 - credentials.json / token.json (Gmail OAuth) – see menu help for how to create these
 - .active_listener.json       → enforces single listener; menu can view/clear or replace
 - outbox/                     → queued messages if sending fails

Run examples:
  python telegram_gmail_forwarder.py                # guided menu
  python telegram_gmail_forwarder.py --log          # menu + file logging
  python telegram_gmail_forwarder.py --no-edit      # menu with editing disabled (raw forward)
"""

from __future__ import annotations
import os
import sys
import json
import asyncio
import tempfile
import shutil
import time
import argparse
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import re

from telethon import TelegramClient, events

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# ---------------- Constants & Paths ----------------
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_FILE = Path('credentials.json')
TOKEN_FILE = Path('token.json')
CONFIG_FILE = Path('config.json')
ACTIVE_LOCK = Path('.active_listener.json')
OUTBOX_DIR = Path('outbox')
LOG_FILE = 'tgfwd.log'

OUTBOX_DIR.mkdir(exist_ok=True)

# ---------------- Logging ----------------
logger = logging.getLogger('tgfwd')
logger.setLevel(logging.INFO)
_handler_stdout = logging.StreamHandler(sys.stdout)
_handler_stdout.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(_handler_stdout)

# ---------------- Small helpers ----------------

def chmod_600(p: Path):
    try:
        p.chmod(0o600)
    except Exception:
        pass


def mask(s: Optional[str]) -> str:
    if not s:
        return '(not set)'
    s = str(s)
    if len(s) <= 6:
        return '*' * len(s)
    return s[:3] + '...' + s[-3:]

# ---------------- Config I/O ----------------

def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        logger.exception('Could not read config.json; starting fresh')
        return {}


def save_config(cfg: Dict[str, Any]):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    chmod_600(CONFIG_FILE)

# ---------------- Gmail ----------------

def explain_credentials():
    print("""
[ACTION REQUIRED] credentials.json missing.
Steps:
 1) Open Google Cloud Console and create/select a project.
 2) Enable the Gmail API.
 3) Create OAuth Client ID → Desktop app.
 4) Download the JSON and save it next to this script as 'credentials.json'.
 5) In the menu, choose: Gmail → Authorize (to create token.json).
""")


def explain_token():
    print("""
[token.json missing/invalid]
Options:
  A) Choose Gmail → Authorize to run the browser OAuth flow and create token.json.
  B) Or create token.json on another machine (run the same authorize flow there) and copy it here.
""")


def get_gmail_service(allow_authorize: bool = False):
    if not CREDENTIALS_FILE.exists():
        explain_credentials()
        return None

    creds = None
    if TOKEN_FILE.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
        except Exception:
            logger.exception('Invalid token.json')
            creds = None

    if not creds and allow_authorize:
        try:
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
            creds = flow.run_local_server(port=0)
            TOKEN_FILE.write_text(creds.to_json())
            chmod_600(TOKEN_FILE)
            logger.info('Saved token.json')
        except Exception:
            logger.exception('OAuth flow failed')
            print('[ERROR] OAuth flow failed on this machine. Try on a machine with a browser and copy token.json back here.')
            return None

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            TOKEN_FILE.write_text(creds.to_json())
            chmod_600(TOKEN_FILE)
            logger.info('Refreshed token.json')
        except Exception:
            logger.exception('Token refresh failed')

    if not creds:
        explain_token()
        return None

    try:
        return build('gmail', 'v1', credentials=creds)
    except Exception:
        logger.exception('Failed to init Gmail API client')
        return None


def create_mime(sender: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> str:
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    for p in attachments or []:
        try:
            part = MIMEBase('application', 'octet-stream')
            with open(p, 'rb') as f:
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{Path(p).name}"')
            msg.attach(part)
        except Exception:
            logger.exception('Attach failed for %s', p)

    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


def send_email(service, sender: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> bool:
    try:
        raw = create_mime(sender, to, subject, body, attachments)
        service.users().messages().send(userId='me', body={'raw': raw}).execute()
        return True
    except HttpError as e:
        logger.exception('Gmail API error: %s', e)
        return False
    except Exception:
        logger.exception('Sending failed')
        return False


async def send_email_async(service, sender: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> bool:
    return await asyncio.to_thread(send_email, service, sender, to, subject, body, attachments)

# ---------------- Outbox ----------------

def save_outbox(email_obj: dict, media_paths: List[str]):
    ts = int(time.time() * 1000)
    folder = OUTBOX_DIR / f'out_{ts}'
    folder.mkdir(parents=True, exist_ok=True)
    saved_media = []
    for p in media_paths:
        try:
            dest = folder / Path(p).name
            shutil.copy2(p, dest)
            saved_media.append(str(dest))
        except Exception:
            logger.exception('Copy media failed: %s', p)
    email_obj['media'] = saved_media
    (folder / 'meta.json').write_text(json.dumps(email_obj, indent=2, ensure_ascii=False))
    logger.info('Saved to outbox %s', folder)


async def resend_outbox(service):
    for child in sorted(OUTBOX_DIR.iterdir()):
        if not child.is_dir():
            continue
        meta = child / 'meta.json'
        if not meta.exists():
            continue
        try:
            obj = json.loads(meta.read_text())
            ok = await send_email_async(service, obj['sender'], obj['to'], obj['subject'], obj['body'], obj.get('media', []))
            if ok:
                shutil.rmtree(child)
                logger.info('Resent & removed %s', child)
            else:
                logger.warning('Failed to resend %s', child)
        except Exception:
            logger.exception('Resend failed for %s', child)

# ---------------- Parsing / Formatting ----------------
GOOGLE_CODE_RE = re.compile(r'G-(\d{4,})')
DEST_ADDR_RE = re.compile(r'Destination Address:\s*(\+?\d+)', re.IGNORECASE)
PHONE_RE = re.compile(r'\+?\d{5,}')


def extract_google(text: str) -> Tuple[Optional[str], Optional[str]]:
    code_m = GOOGLE_CODE_RE.search(text or '')
    code = code_m.group(1) if code_m else None

    dest = None
    d = DEST_ADDR_RE.search(text or '')
    if d:
        dest = d.group(1)
    else:
        p = PHONE_RE.search(text or '')
        if p:
            dest = p.group(0)
    return dest, code


def format_compact(dest: Optional[str], code: Optional[str]) -> str:
    return (f"Phone number : {dest or '(not found)'}\n"
            f"Google verification codes: {code or '(not found)'}")

# ---------------- Setup Wizard ----------------

def wizard_setup(cfg: Dict[str, Any]) -> Dict[str, Any]:
    print('\n=== Setup Wizard ===')
    # Telegram
    api_id = input(f'Telegram API ID [{cfg.get("telegram", {}).get("api_id", "")}]: ').strip() or cfg.get('telegram', {}).get('api_id')
    api_hash = input(f'Telegram API Hash [{mask(cfg.get("telegram", {}).get("api_hash"))}]: ').strip() or cfg.get('telegram', {}).get('api_hash')
    session = input(f'Telegram session name [{cfg.get("telegram", {}).get("session", "forwarder_session")}]: ').strip() or cfg.get('telegram', {}).get('session', 'forwarder_session')

    # Email
    sender = input(f'Email sender (Gmail) [{cfg.get("email", {}).get("sender", "")}]: ').strip() or cfg.get('email', {}).get('sender')
    receiver = input(f'Email receiver [{cfg.get("email", {}).get("receiver", "")}]: ').strip() or cfg.get('email', {}).get('receiver')

    # Listener (single)
    print('Choose a single listener (bot username without @ OR numeric user id). Leave the other blank.')
    bot_name = input(f'Bot/User name [{cfg.get("listener", {}).get("bot_name", "")}]: ').strip().lower()
    bot_id_raw = input(f'User ID [{cfg.get("listener", {}).get("bot_id", "")}]: ').strip()
    bot_id = int(bot_id_raw) if bot_id_raw else None

    if (not bot_name and not bot_id) or (bot_name and bot_id):
        print('[ERROR] You must specify exactly one: bot name OR user id.')
        return cfg

    cfg_new = {
        'telegram': {'api_id': api_id, 'api_hash': api_hash, 'session': session},
        'email': {'sender': sender, 'receiver': receiver},
        'listener': {'bot_name': bot_name or None, 'bot_id': bot_id or None},
        'options': cfg.get('options', {'edit': True})
    }
    save_config(cfg_new)

    # Update/validate active lock
    desired = {'bot_name': cfg_new['listener']['bot_name'], 'bot_id': cfg_new['listener']['bot_id']}
    if ACTIVE_LOCK.exists():
        try:
            current = json.loads(ACTIVE_LOCK.read_text())
        except Exception:
            current = None
        if current and current != desired:
            print('[INFO] Existing .active_listener.json differs from your selection.')
            ans = input('Replace it now? (y/N): ').strip().lower()
            if ans == 'y':
                ACTIVE_LOCK.write_text(json.dumps(desired))
                chmod_600(ACTIVE_LOCK)
                print('Lock replaced.')
            else:
                print('Keeping existing lock. Forwarder will not start if they differ.')
        else:
            print('Lock matches or is unreadable; updating.')
            ACTIVE_LOCK.write_text(json.dumps(desired))
            chmod_600(ACTIVE_LOCK)
    else:
        ACTIVE_LOCK.write_text(json.dumps(desired))
        chmod_600(ACTIVE_LOCK)

    print('✓ Setup saved to config.json.')
    return cfg_new

# ---------------- Menu ----------------

def show_menu():
    print('\n=== Telegram → Gmail Forwarder ===')
    print('1) Start forwarder')
    print('2) Change listener (bot name / user id)')
    print('3) Gmail → Authorize / Refresh token.json')
    print('4) Outbox → Resend queued emails')
    print('5) View/clear .active_listener.json')
    print('6) Reset / Run Setup Wizard again')
    print('0) Exit')


def menu_loop(no_edit_flag: bool):
    cfg = load_config()
    if not cfg or not cfg.get('telegram') or not cfg.get('email') or not cfg.get('listener'):
        cfg = wizard_setup(cfg)

    while True:
        show_menu()
        choice = input('Select: ').strip()
        if choice == '1':
            asyncio.run(start_forwarder(cfg, no_edit_flag))
            cfg = load_config()  # reload after return (e.g., after Ctrl+C)
        elif choice == '2':
            cfg = load_config()
            cfg = wizard_setup(cfg)
        elif choice == '3':
            svc = get_gmail_service(allow_authorize=True)
            if svc:
                print('✓ Gmail ready. You can now start the forwarder.')
        elif choice == '4':
            svc = get_gmail_service(allow_authorize=False)
            if not svc:
                print('Gmail is not authorized. Use menu option 3 first.')
            else:
                asyncio.run(resend_outbox(svc))
        elif choice == '5':
            if ACTIVE_LOCK.exists():
                print('Current lock contents:')
                try:
                    print(ACTIVE_LOCK.read_text())
                except Exception:
                    print('(unreadable)')
                ans = input('Remove lock? (y/N): ').strip().lower()
                if ans == 'y':
                    try:
                        ACTIVE_LOCK.unlink()
                        print('Lock removed.')
                    except Exception:
                        print('Could not remove lock file.')
            else:
                print('No lock present.')
        elif choice == '6':
            ans = input('This will re-run Setup and overwrite config.json listener fields. Continue? (y/N): ').strip().lower()
            if ans == 'y':
                cfg = wizard_setup(load_config())
        elif choice == '0':
            print('Bye!')
            return
        else:
            print('Unknown choice.')

# ---------------- Forwarder ----------------

async def start_forwarder(cfg: Dict[str, Any], no_edit_flag: bool):
    # Validate lock matches configured listener
    desired = {'bot_name': cfg.get('listener', {}).get('bot_name'), 'bot_id': cfg.get('listener', {}).get('bot_id')}
    if ACTIVE_LOCK.exists():
        try:
            current = json.loads(ACTIVE_LOCK.read_text())
        except Exception:
            current = None
        if current and current != desired:
            print('[ERROR] Another listener configuration already exists in .active_listener.json.')
            print('To change it, use menu → View/clear .active_listener.json, or rerun Setup to replace it.')
            return
    else:
        ACTIVE_LOCK.write_text(json.dumps(desired))
        chmod_600(ACTIVE_LOCK)

    tg = cfg.get('telegram', {})
    em = cfg.get('email', {})

    # Telethon client
    try:
        api_id = int(tg.get('api_id'))
    except Exception:
        print('[ERROR] Telegram API ID is missing/invalid. Run Setup again.')
        return
    api_hash = tg.get('api_hash')
    session = tg.get('session', 'forwarder_session')

    if not api_hash:
        print('[ERROR] Telegram API Hash is missing. Run Setup again.')
        return

    email_sender = em.get('sender')
    email_receiver = em.get('receiver')
    if not email_sender or not email_receiver:
        print('[ERROR] Email sender/receiver missing. Run Setup again.')
        return

    service = get_gmail_service(allow_authorize=False)
    if not service:
        print('[INFO] Gmail not available — emails will be saved to outbox and can be resent later.')

    bot_name = (cfg.get('listener', {}).get('bot_name') or '').lower()
    bot_id = cfg.get('listener', {}).get('bot_id') or 0

    client = TelegramClient(session, api_id, api_hash)
    logger.info('Telegram client created with session: %s', session)

    @client.on(events.NewMessage(incoming=True))
    async def on_new_message(event):
        logger.info('New message event triggered')
        tmpdir = None
        try:
            sender = await event.get_sender()
            username = (getattr(sender, 'username', '') or '').lower()
            user_id = getattr(sender, 'id', None)
            logger.debug('Sender details: username=%s, id=%s', username, user_id)

            if bot_name and username != bot_name:
                logger.debug('Sender username does not match listener bot_name=%s', bot_name)
                return
            if bot_id and user_id != bot_id:
                logger.debug('Sender id does not match listener bot_id=%s', bot_id)
                return

            name = ((sender.first_name or '') + (' ' + sender.last_name if getattr(sender, 'last_name', None) else '')).strip() or (sender.username or f'id:{user_id}')
            logger.info('Processing message from: %s (username=%s, id=%s)', name, username, user_id)
            subject = f'Telegram message from {name}'
            raw_text = event.raw_text or ''
            logger.debug('Raw message text: %s', raw_text[:200])

            attachments: List[str] = []
            if event.media:
                logger.info('Message has media; downloading...')
                tmpdir = tempfile.mkdtemp(prefix='tgfwd_')
                path = await event.download_media(file=tmpdir)
                if path:
                    if os.path.isdir(path):
                        for fn in sorted(os.listdir(path)):
                            attachments.append(os.path.join(path, fn))
                    else:
                        attachments.append(path)
                logger.info('Downloaded attachments: %s', attachments)

            body: str
            if no_edit_flag or not cfg.get('options', {}).get('edit', True):
                # Raw forward (minimal header + body)
                body = f"From: {name}\n" \
                       f"Username: @{sender.username if getattr(sender, 'username', None) else ''}\n" \
                       f"Date: {event.message.date.isoformat()}\n\n" \
                       f"{raw_text}"
                logger.debug('Using raw forward mode')
            else:
                dest, code = extract_google(raw_text)
                if dest or code:
                    body = format_compact(dest, code)
                    logger.debug('Extracted Google code: dest=%s, code=%s', dest, code)
                else:
                    body = format_compact(None, None) + "\n---- Original message below ----\n" + raw_text
                    logger.debug('No Google code found; using fallback format')

            logger.debug('Formatted email body: %s', body[:200])

            sent = False
            if service:
                logger.info('Attempting to send email...')
                try:
                    sent = await send_email_async(service, email_sender, email_receiver, subject, body, attachments)
                except Exception:
                    logger.exception('Email send failed')

            if sent:
                logger.info('Email sent successfully')
            else:
                logger.warning('Email send failed or no service; saving to outbox')
                save_outbox({'sender': email_sender, 'to': email_receiver, 'subject': subject, 'body': body, 'timestamp': time.time()}, attachments)
        except Exception:
            logger.exception('Handler error')
        finally:
            try:
                if tmpdir and os.path.isdir(tmpdir):
                    shutil.rmtree(tmpdir)
                    logger.debug('Cleaned up temp dir: %s', tmpdir)
            except Exception:
                logger.exception('Temp dir cleanup failed')

    async def run_client():
        logger.info('Starting Telegram client...')
        await client.start()
        logger.info('Telegram client started successfully')
        logger.info('Forwarder started. Listening for messages from listener (bot_name=%s or bot_id=%s)... (Ctrl+C to stop)', bot_name, bot_id)
        if service:
            logger.info('Resending any pending outbox items...')
            await resend_outbox(service)
            logger.info('Outbox resend complete')
        await client.run_until_disconnected()
        logger.info('Telegram client disconnected')

    try:
        await run_client()
    except KeyboardInterrupt:
        logger.info('Keyboard interrupt received; shutting down')
    except Exception:
        logger.exception('Unexpected error in forwarder')
    finally:
        try:
            if ACTIVE_LOCK.exists():
                ACTIVE_LOCK.unlink()
                logger.info('Removed active listener lock')
        except Exception:
            logger.exception('Failed to remove active listener lock')

# ---------------- Entrypoint ----------------

def main():
    parser = argparse.ArgumentParser(description='Telegram → Gmail Forwarder (guided)')
    parser.add_argument('--no-edit', action='store_true', help='Disable Google-code editing for testing')
    parser.add_argument('--log', action='store_true', help='Also write logs to tgfwd.log')
    args = parser.parse_args()

    if args.log:
        fh = logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)
        logger.info('File logging enabled to %s', LOG_FILE)

    menu_loop(no_edit_flag=args.no_edit)


if __name__ == '__main__':
    main()