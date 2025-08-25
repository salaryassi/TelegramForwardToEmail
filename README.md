
# Telegram → Gmail Forwarder

Forward Telegram messages containing Google verification codes to Gmail automatically.

---

## Requirements

* Python 3.10+
* Linux (tested on Ubuntu)
* Python packages:

  ```bash
  pip install telethon python-dotenv
  ```
* **Telegram API ID and Hash**
* **Gmail sender email and App Password**

---

## What They Are

### Telegram API ID & Hash

To use the script, you need a **Telegram API ID and Hash**:

1. Go to [https://my.telegram.org](https://my.telegram.org)
2. Log in with your Telegram account
3. Click **API development tools**
4. Create a new application
5. Copy your **API ID** and **API Hash** — you will use them in the script

These credentials allow the script to log in and read your Telegram messages.

---

### Google App Password

To send emails via Gmail without using your main password:

1. Enable **2-Step Verification** on your Gmail account
2. Go to [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Generate a new **App Password** for “Mail”
4. Use this password as the sender password in the script

This ensures secure access to Gmail without exposing your main password.

---

## Installation

1. Place the script in a folder, e.g.:

   ```bash
   /opt/TelegramForwardToEmail
   ```

2. Install dependencies:

   ```bash
   pip install telethon python-dotenv
   ```

3. Run the script to configure:

   ```bash
   python3 telegraph_forwarder.py
   ```

   * Enter Telegram API ID, API Hash
   * Enter Gmail sender, receiver, and App Password
   * Enter Telegram listener (bot or user)

---

## Running

* **Interactive mode**:

  ```bash
  python3 telegraph_forwarder.py
  ```
* **Systemd service mode** (background):

  ```bash
  sudo systemctl start tgfwd
  sudo systemctl enable tgfwd
  ```

---

## Options

* `--auto` → Run without interactive menu
* `--log` → Save logs to `tgfwd.log`
* `--no-edit` → Forward raw messages without extracting Google codes

---

## Checking Service Status

```bash
sudo systemctl status tgfwd
sudo journalctl -u tgfwd -f
```

This lets you see if the bot is running and logs any forwarded messages in real-time.

