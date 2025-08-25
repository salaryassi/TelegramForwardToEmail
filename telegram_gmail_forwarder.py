#!/usr/bin/env python3
"""
Telegram → Gmail Forwarder (SMTP Edition)

- Uses Gmail SMTP with an App Password.
- Fully interactive Setup Wizard creates .env automatically.
- Supports attachments, outbox, resend, test email, and listener management.
"""

from __future__ import annotations
import os, sys, json, asyncio, tempfile, shutil, time, argparse, logging, getpass
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import re
import smtplib

from telethon import TelegramClient, events
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv

# ---------------- Paths & Constants ----------------
CONFIG_FILE = Path('config.json')
ACTIVE_LOCK = Path('.active_listener.json')
OUTBOX_DIR = Path('outbox')
ENV_FILE = Path('.env')
LOG_FILE = 'tgfwd.log'
OUTBOX_DIR.mkdir(exist_ok=True)

# ---------------- Logging ----------------
logger = logging.getLogger('tgfwd')
logger.setLevel(logging.INFO)
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(stdout_handler)

# ---------------- Helpers ----------------
def chmod_600(p: Path):
    try: p.chmod(0o600)
    except Exception: pass

def mask(s: Optional[str]) -> str:
    if not s: return '(not set)'
    s = str(s)
    if len(s) <= 6: return '*' * len(s)
    return s[:3] + '...' + s[-3:]

def load_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists(): return {}
    try: return json.loads(CONFIG_FILE.read_text())
    except Exception: logger.exception('Could not read config.json'); return {}

def save_config(cfg: Dict[str, Any]):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    chmod_600(CONFIG_FILE)

def load_env():
    if ENV_FILE.exists(): load_dotenv(ENV_FILE)

def get_env_email() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    load_env()
    return os.getenv('EMAIL_SENDER'), os.getenv('EMAIL_PASSWORD'), os.getenv('EMAIL_RECEIVER')

# ---------------- Setup Wizard ----------------
def wizard_setup(cfg: Dict[str, Any]) -> Dict[str, Any]:
    print('\n=== Setup Wizard ===')
    # Telegram
    api_id = input(f'Telegram API ID [{cfg.get("telegram", {}).get("api_id", "")}]: ').strip() or cfg.get('telegram', {}).get('api_id')
    api_hash = input(f'Telegram API Hash [{mask(cfg.get("telegram", {}).get("api_hash"))}]: ').strip() or cfg.get('telegram', {}).get('api_hash')
    session = input(f'Telegram session name [{cfg.get("telegram", {}).get("session","forwarder_session")}]: ').strip() or cfg.get('telegram', {}).get('session', 'forwarder_session')

    # Email
    sender = input(f'Email sender (Gmail) [{cfg.get("email", {}).get("sender", "")}]: ').strip() or cfg.get('email', {}).get('sender', '')
    receiver = input(f'Email receiver [{cfg.get("email", {}).get("receiver", "")}]: ').strip() or cfg.get('email', {}).get('receiver', '')
    print('Enter your Gmail App Password (will be saved to .env, input hidden):')
    password = getpass.getpass('EMAIL_PASSWORD: ').strip()

    # Save to .env
    lines = []
    if ENV_FILE.exists():
        existing = [ln for ln in ENV_FILE.read_text().splitlines() if not ln.startswith('EMAIL_')]
        lines.extend(existing)
    lines += [
        f'EMAIL_SENDER={sender}',
        f'EMAIL_PASSWORD={password}',
        f'EMAIL_RECEIVER={receiver}'
    ]
    ENV_FILE.write_text('\n'.join(lines)+'\n')
    chmod_600(ENV_FILE)
    print('✓ .env created/updated with email credentials (chmod 600).')

    # Save config.json
    cfg_new = {
        'telegram': {'api_id': api_id, 'api_hash': api_hash, 'session': session},
        'email': {'sender': sender, 'receiver': receiver},
        'listener': cfg.get('listener', {}),
        'options': cfg.get('options', {'edit': True})
    }
    save_config(cfg_new)
    print('✓ Setup saved.')
    return cfg_new

# ---------------- SMTP ----------------
def create_mime(sender: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None):
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    for p in attachments or []:
        try:
            part = MIMEBase('application', 'octet-stream')
            with open(p, 'rb') as f: part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{Path(p).name}"')
            msg.attach(part)
        except Exception: logger.exception('Attach failed: %s', p)
    return msg

def send_email_smtp(sender: str, password: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> bool:
    try:
        msg = create_mime(sender, to, subject, body, attachments)
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=60) as smtp:
            smtp.starttls()
            smtp.login(sender, password)
            smtp.send_message(msg)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error('Gmail authentication failed. Use an App Password.')
        return False
    except Exception:
        logger.exception('SMTP send failed')
        return False

async def send_email_smtp_async(sender: str, password: str, to: str, subject: str, body: str, attachments: Optional[List[str]] = None) -> bool:
    return await asyncio.to_thread(send_email_smtp, sender, password, to, subject, body, attachments)

# ---------------- Outbox ----------------
def save_outbox(email_obj: dict, media_paths: List[str]):
    ts = int(time.time()*1000)
    folder = OUTBOX_DIR / f'out_{ts}'
    folder.mkdir(parents=True, exist_ok=True)
    saved_media = []
    for p in media_paths:
        try: 
            dest = folder / Path(p).name
            shutil.copy2(p, dest)
            saved_media.append(str(dest))
        except Exception: logger.exception('Copy media failed: %s', p)
    email_obj['media'] = saved_media
    (folder/'meta.json').write_text(json.dumps(email_obj, indent=2, ensure_ascii=False))
    logger.info('Saved to outbox %s', folder)

async def resend_outbox(sender: str, password: str, to: str):
    for child in sorted(OUTBOX_DIR.iterdir()):
        if not child.is_dir(): continue
        meta = child/'meta.json'
        if not meta.exists(): continue
        try:
            obj = json.loads(meta.read_text())
            ok = await send_email_smtp_async(sender, password, to, obj['subject'], obj['body'], obj.get('media', []))
            if ok:
                shutil.rmtree(child)
                logger.info('Resent & removed %s', child)
            else:
                logger.warning('Failed to resend %s', child)
        except Exception:
            logger.exception('Resend failed for %s', child)

# ---------------- Parsing ----------------
GOOGLE_CODE_RE = re.compile(r'G-(\d{4,})')
DEST_ADDR_RE = re.compile(r'Destination Address:\s*(\+?\d+)', re.IGNORECASE)
PHONE_RE = re.compile(r'\+?\d{5,}')

def extract_google(text: str) -> Tuple[Optional[str], Optional[str]]:
    code_m = GOOGLE_CODE_RE.search(text or '')
    code = code_m.group(1) if code_m else None
    dest = None
    d = DEST_ADDR_RE.search(text or '')
    if d: dest = d.group(1)
    else:
        p = PHONE_RE.search(text or '')
        if p: dest = p.group(0)
    return dest, code

def format_compact(dest: Optional[str], code: Optional[str]) -> str:
    return (f"Phone number : {dest or '(not found)'}\nGoogle verification codes: {code or '(not found)'}")

# ---------------- Menu ----------------
def show_menu():
    print('\n=== Telegram → Gmail Forwarder (SMTP) ===')
    print('1) Start forwarder')
    print('2) Change listener')
    print('3) SMTP → Send test email')
    print('4) Outbox → Resend queued emails')
    print('5) View/clear .active_listener.json')
    print('6) Reset / Run Setup Wizard again')
    print('0) Exit')

def menu_loop(no_edit_flag: bool):
    cfg = load_config()
    if not cfg or not cfg.get('telegram') or not cfg.get('email'):
        cfg = wizard_setup(cfg)
    while True:
        show_menu()
        choice = input('Select: ').strip()
        if choice == '1':
            asyncio.run(start_forwarder(cfg, no_edit_flag))
            cfg = load_config()
        elif choice == '2':
            print('Listener config:')
            bot_name = input(f'Bot/User name [{cfg.get("listener", {}).get("bot_name","")}]: ').strip().lower()
            bot_id_raw = input(f'User ID [{cfg.get("listener", {}).get("bot_id","")}]: ').strip()
            bot_id = int(bot_id_raw) if bot_id_raw else None
            if (not bot_name and not bot_id) or (bot_name and bot_id):
                print('[ERROR] Must specify exactly one: bot name OR user id.')
            else:
                cfg.setdefault('listener', {})
                cfg['listener']['bot_name'] = bot_name or None
                cfg['listener']['bot_id'] = bot_id or None
                save_config(cfg)
                print('✓ Listener updated.')
        elif choice == '3':
            sender, password, receiver = get_env_email()
            ok = send_email_smtp(sender, password, receiver, 'SMTP test', 'SMTP connection test successful!')
            print('✓ Test email sent.' if ok else '✗ Test email failed.')
        elif choice == '4':
            sender, password, receiver = get_env_email()
            asyncio.run(resend_outbox(sender, password, receiver))
        elif choice == '5':
            if ACTIVE_LOCK.exists():
                print('Lock contents:')
                print(ACTIVE_LOCK.read_text() or '(unreadable)')
                ans = input('Remove lock? (y/N): ').strip().lower()
                if ans=='y':
                    try: ACTIVE_LOCK.unlink(); print('Lock removed.')
                    except: print('Could not remove lock file.')
            else: print('No lock present.')
        elif choice == '6':
            ans = input('Run Setup Wizard again? (y/N): ').strip().lower()
            if ans=='y': cfg = wizard_setup(load_config())
        elif choice == '0':
            print('Bye!'); return
        else: print('Unknown choice.')

# ---------------- Forwarder ----------------
async def start_forwarder(cfg: Dict[str, Any], no_edit_flag: bool):
    desired = {'bot_name': cfg.get('listener', {}).get('bot_name'), 'bot_id': cfg.get('listener', {}).get('bot_id')}
    if ACTIVE_LOCK.exists():
        try: current = json.loads(ACTIVE_LOCK.read_text())
        except: current=None
        if current and current!=desired:
            print('[ERROR] Another listener config exists.')
            return
    else:
        ACTIVE_LOCK.write_text(json.dumps(desired))
        chmod_600(ACTIVE_LOCK)

    tg = cfg.get('telegram', {})
    try: api_id=int(tg.get('api_id'))
    except: print('[ERROR] Telegram API ID missing/invalid.'); return
    api_hash = tg.get('api_hash')
    session = tg.get('session','forwarder_session')
    if not api_hash: print('[ERROR] Telegram API Hash missing.'); return

    sender, pwd, receiver = get_env_email()
    if not sender or not receiver or not pwd:
        print('[ERROR] Missing EMAIL_* values in .env.'); return

    bot_name = (cfg.get('listener', {}).get('bot_name') or '').lower()
    bot_id = cfg.get('listener', {}).get('bot_id') or 0

    client = TelegramClient(session, api_id, api_hash)
    logger.info('Telegram client created with session: %s', session)

    @client.on(events.NewMessage(incoming=True))
    async def on_new_message(event):
        tmpdir=None
        try:
            sender_obj = await event.get_sender()
            username = (getattr(sender_obj,'username','') or '').lower()
            user_id = getattr(sender_obj,'id',None)
            if bot_name and username!=bot_name: return
            if bot_id and user_id!=bot_id: return

            name = ((sender_obj.first_name or '') + (' ' + getattr(sender_obj,'last_name','') if getattr(sender_obj,'last_name',None) else '')).strip() or (sender_obj.username or f'id:{user_id}')
            subject = f'Telegram message from {name}'
            raw_text = event.raw_text or ''
            attachments: List[str]=[]
            if event.media:
                tmpdir=tempfile.mkdtemp(prefix='tgfwd_')
                path = await event.download_media(file=tmpdir)
                if path:
                    if os.path.isdir(path):
                        for fn in sorted(os.listdir(path)): attachments.append(os.path.join(path,fn))
                    else: attachments.append(path)

            if no_edit_flag or not cfg.get('options', {}).get('edit', True):
                body = f"From: {name}\nUsername: @{getattr(sender_obj,'username','')}\nDate: {event.message.date.isoformat()}\n\n{raw_text}"
            else:
                dest, code = extract_google(raw_text)
                if dest or code: body=format_compact(dest, code)
                else: body=format_compact(None,None)+"\n---- Original message ----\n"+raw_text

            sent = await send_email_smtp_async(sender, pwd, receiver, subject, body, attachments)
            if sent: logger.info('Email sent successfully')
            else: 
                logger.warning('Send failed; saving to outbox')
                save_outbox({'sender':sender,'to':receiver,'subject':subject,'body':body,'timestamp':time.time()}, attachments)
        except Exception: logger.exception('Handler error')
        finally:
            try: 
                if tmpdir and os.path.isdir(tmpdir): shutil.rmtree(tmpdir)
            except: logger.exception('Temp dir cleanup failed')

    async def run_client():
        logger.info('Starting Telegram client...')
        await client.start()
        logger.info('Forwarder started. Listening for messages from listener...')
        await resend_outbox(sender, pwd, receiver)
        await client.run_until_disconnected()
        logger.info('Client disconnected')

    try:
        await run_client()
    except KeyboardInterrupt: logger.info('Keyboard interrupt; shutting down')
    except Exception: logger.exception('Unexpected error')
    finally:
        if ACTIVE_LOCK.exists():
            try: ACTIVE_LOCK.unlink(); logger.info('Removed listener lock')
            except: logger.exception('Failed to remove listener lock')

# ---------------- Entrypoint ----------------
def main():
    parser = argparse.ArgumentParser(description='Telegram → Gmail Forwarder (SMTP)')
    parser.add_argument('--no-edit', action='store_true', help='Disable Google-code editing')
    parser.add_argument('--log', action='store_true', help='Write logs to tgfwd.log')
    args = parser.parse_args()

    if args.log:
        fh=logging.FileHandler(LOG_FILE)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)
        logger.setLevel(logging.DEBUG)

    menu_loop(no_edit_flag=args.no_edit)

if __name__=='__main__':
    main()
