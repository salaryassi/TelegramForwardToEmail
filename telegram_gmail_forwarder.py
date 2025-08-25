#!/usr/bin/env python3
"""
Telegram → Gmail Forwarder (Full Rewrite)

(added: Device Authorization Flow for headless server authorization)

See menu option 3 (Gmail -> Authorize) — it will now attempt a headless Device Flow first
and save token.json automatically. If device flow isn't supported for the configured
client/scope, it falls back to the existing manual flow (where you paste the code).

The device code & verification URL are written to `device_auth.txt` in the working dir
and printed to stdout. If your Telegram session (configured in config.json) is valid,
we also *attempt* to send the verification info to your Saved Messages (`me`).

This file is the same script you provided with the device-flow additions.
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

import requests

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
DEVICE_AUTH_FILE = Path('device_auth.txt')
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

# ---------------- Device Flow Utilities ----------------

DEVICE_ENDPOINT = 'https://oauth2.googleapis.com/device/code'
TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'


def _read_client_from_credentials() -> Tuple[Optional[str], Optional[str]]:
    """Read client_id and client_secret from credentials.json (installed/web)."""
    if not CREDENTIALS_FILE.exists():
        return None, None
    try:
        j = json.loads(CREDENTIALS_FILE.read_text())
        # credentials.json usually contains either 'installed' or 'web'
        info = j.get('installed') or j.get('web') or {}
        return info.get('client_id'), info.get('client_secret')
    except Exception:
        logger.exception('Reading credentials.json failed')
        return None, None


def start_device_flow(client_id: str, scope_list: List[str]) -> dict:
    data = {'client_id': client_id, 'scope': ' '.join(scope_list)}
    r = requests.post(DEVICE_ENDPOINT, data=data, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f'Device endpoint responded: {r.status_code} {r.text}')
    return r.json()


def poll_device_token(client_id: str, client_secret: Optional[str], device_code: str, interval: int) -> dict:
    payload = {
        'client_id': client_id,
        'device_code': device_code,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
    }
    if client_secret:
        payload['client_secret'] = client_secret

    while True:
        time.sleep(interval)
        r = requests.post(TOKEN_ENDPOINT, data=payload, timeout=15)
        try:
            j = r.json()
        except Exception:
            raise RuntimeError('Invalid JSON from token endpoint')

        if r.status_code == 200 and 'access_token' in j:
            return j
        err = j.get('error')
        if err == 'authorization_pending':
            continue
        if err == 'slow_down':
            interval += 5
            continue
        # other errors (expired_token, access_denied, invalid_scope, etc.)
        raise RuntimeError(f'Device token error: {err} - {j.get("error_description")}')


def save_credentials_from_token_resp(token_resp: dict):
    creds = Credentials(
        token=token_resp.get('access_token'),
        refresh_token=token_resp.get('refresh_token'),
        token_uri=TOKEN_ENDPOINT,
        client_id=token_resp.get('client_id') or _read_client_from_credentials()[0],
        client_secret=token_resp.get('client_secret') or _read_client_from_credentials()[1],
        scopes=SCOPES,
    )
    TOKEN_FILE.write_text(creds.to_json())
    chmod_600(TOKEN_FILE)


def device_authorize_headless(notify_fn=None) -> bool:
    """Run the Device Authorization flow and save token.json.

    notify_fn: optional callable that will be called with a text message to notify the user
               (for example: send via Telegram). If notify_fn isn't provided, we write device_auth.txt
               and print to stdout.
    Returns True on success.
    """
    client_id, client_secret = _read_client_from_credentials()
    if not client_id:
        print('[ERROR] credentials.json missing or invalid. See instructions in the menu.')
        return False

    try:
        info = start_device_flow(client_id, SCOPES)
    except Exception as e:
        logger.exception('Device flow start failed')
        print('[INFO] Device flow failed to start:', e)
        return False

    verification_url = info.get('verification_url') or info.get('verification_uri')
    user_code = info.get('user_code')
    device_code = info.get('device_code')
    interval = info.get('interval', 5)

    message = f'Google device authorization:\nURL: {verification_url}\nCode: {user_code}\n'
    # save to file so admin can copy it remotely
    try:
        DEVICE_AUTH_FILE.write_text(message)
        chmod_600(DEVICE_AUTH_FILE)
    except Exception:
        logger.exception('Writing device_auth.txt failed')

    # notify (if callback provided)
    if notify_fn:
        try:
            notify_fn(message)
        except Exception:
            logger.exception('notify_fn failed')

    # Always print to stdout as well (visible in logs)
    print('\n=== Device Authorization ===')
    print(message)
    print('Waiting for user to complete authorization...')

    try:
        token_resp = poll_device_token(client_id, client_secret, device_code, interval)
    except Exception as e:
        logger.exception('Polling token failed')
        print('[ERROR] Device authorization failed:', e)
        return False

    # Save tokens
    try:
        # attach client info if missing so saved creds work
        if 'client_id' not in token_resp:
            token_resp['client_id'] = client_id
        if client_secret and 'client_secret' not in token_resp:
            token_resp['client_secret'] = client_secret
        save_credentials_from_token_resp(token_resp)
        print('Device authorization complete — token.json saved.')
        return True
    except Exception:
        logger.exception('Saving token.json failed')
        return False

# ---------------- Gmail ----------------

def explain_credentials():
    print("""
[ACTION REQUIRED] credentials.json missing.
Steps:
 1) Open Google Cloud Console and create/select a project.
 2) Enable the Gmail API.
 3) Create OAuth Client ID -> Desktop app (or Web app if using redirect).
 4) Download the JSON and save it next to this script as 'credentials.json'.
 5) In the menu, choose: Gmail -> Authorize (to create token.json).
""")


def explain_token():
    print("""
[token.json missing/invalid]
Options:
  A) Choose Gmail -> Authorize to run the OAuth flow and create token.json.
  B) Or create token.json on another machine (run the same authorize flow there) and copy it here.
""")


def try_send_saved_message_via_telegram(cfg: Dict[str, Any], text: str) -> bool:
    """Attempt to send `text` to the running account's Saved Messages ('me') using Telethon.
    This is best-effort: if Telethon can't start (no session, bad api keys), it fails silently.
    Returns True if message was sent.
    """
    try:
        tg = cfg.get('telegram', {})
        api_id = int(tg.get('api_id'))
        api_hash = tg.get('api_hash')
        session = tg.get('session', 'forwarder_session') + '_auth'
    except Exception:
        logger.debug('Telegram config missing or invalid; cannot send device message via Telegram')
        return False

    try:
        client = TelegramClient(session, api_id, api_hash)
        client.start()  # will use existing session or require login if missing
        client.send_message('me', text)
        client.disconnect()
        logger.info('Sent device authorization message to Saved Messages (me)')
        return True
    except Exception:
        logger.exception('Failed to send device authorization message via Telegram')
        return False


def get_gmail_service(allow_authorize: bool = False, cfg: Optional[Dict[str, Any]] = None):
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
        # Try headless device flow first; if it succeeds we'll have token.json
        notified = False
        try:
            # attempt to notify via Telegram if cfg provided
            notify_fn = None
            if cfg:
                notify_fn = lambda text: try_send_saved_message_via_telegram(cfg, text)
            ok = device_authorize_headless(notify_fn=notify_fn)
            if ok:
                try:
                    creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
                except Exception:
                    logger.exception('token.json created but could not be read')
                    creds = None
                    print('[ERROR] token.json could not be read after device flow')
        except Exception:
            logger.exception('Device flow attempt failed')

        # If device flow failed or not available, fall back to manual flow (paste code)
        if not creds:
            try:
                flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
                auth_url, _ = flow.authorization_url(prompt='consent')
                print(f"Please visit this URL to authorize this application: {auth_url}")
                code = input("Enter the authorization code: ")
                flow.fetch_token(code=code)
                creds = flow.credentials
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
        service = build('gmail', 'v1', credentials=creds)
        return service
    except Exception:
        logger.exception('Failed to build Gmail service')
        return None

# ---------------- rest of script ----------------
# The remainder of the script is unchanged except that menu option 3 now passes cfg
# to get_gmail_service so device flow can attempt Telegram notification.

# ---------------- Gmail helper functions and forwarding code ----------------

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
    print('\n=== Telegram \u2192 Gmail Forwarder ===')
    print('1) Start forwarder')
    print('2) Change listener (bot name / user id)')
    print('3) Gmail \u2192 Authorize / Refresh token.json (headless-aware)')
    print('4) Outbox \u2192 Resend queued emails')
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
            # Pass cfg so get_gmail_service can attempt Telegram notify during device flow
            svc = get_gmail_service(allow_authorize=True, cfg=cfg)
            if svc:
                print('\u2713 Gmail ready. You can now start the forwarder.')
        elif choice == '4':
            svc = get_gmail_service(allow_authorize=False, cfg=cfg)
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
            print('To change it, use menu \u2192 View/clear .active_listener.json, or rerun Setup to replace it.')
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

    service = get_gmail_service(allow_authorize=False, cfg=cfg)
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
    parser = argparse.ArgumentParser(description='Telegram \u2192 Gmail Forwarder (guided)')
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
