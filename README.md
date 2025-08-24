# Telegram → Gmail Forwarder

This is a Python script that forwards messages from a specific Telegram bot or user to a Gmail address. It includes a user-friendly setup wizard, main menu for management, and handles common issues like failed email sends by queuing them in an outbox. It can also edit Google verification code messages into a compact format for easier reading.

## Features
- **Setup Wizard**: Guides you through configuration if anything is missing or broken. Runs automatically on first use or when resetting.
- **Validation and Persistence**: Asks for and validates Telegram API credentials, Gmail sender/receiver emails, and a single listener (either a bot username or numeric user ID). Supports only one listener at a time.
- **Error Detection**: Explains common problems, such as missing `credentials.json`, invalid `token.json`, or Telethon session locks.
- **Main Menu**: Options to start the forwarder, change the listener, authorize Gmail, resend outbox items, view/clear the active listener lock, or reset configuration.
- **Message Forwarding**: Forwards only messages from the specified listener. By default, edits Google verification messages (e.g., starting with `G-123456`) into a compact format:
  ```
  Phone number : <Destination/Phone>
  Google verification codes: <Code>
  ```
  - Use the `--no-edit` flag to disable editing and forward raw messages (for testing).
- **Outbox for Failed Sends**: If email sending fails (e.g., due to network issues), stores messages (including media attachments) in the `./outbox` directory. Provides a menu option to resend them later.
- **Logging**: Optional `--log` flag to write detailed logs to `tgfwd.log`.
- **Single Listener Enforcement**: Uses `.active_listener.json` to prevent running for multiple listeners accidentally.

## Requirements
- Python 3.6+ (tested with Python 3.x)
- Install dependencies via pip:
  ```
  pip install telethon google-auth-oauthlib google-api-python-client
  ```
- Telegram API credentials (API ID and Hash) from [my.telegram.org](https://my.telegram.org).
- Google Cloud credentials for Gmail API (see Setup section below).

## Setup
1. **Telegram API Credentials**:
   - Go to [my.telegram.org](https://my.telegram.org), log in, and create an app to get your API ID and Hash.
   - These will be prompted during the Setup Wizard.

2. **Gmail API Credentials**:
   - Create a Google Cloud project at [console.cloud.google.com](https://console.cloud.google.com).
   - Enable the Gmail API in the project.
   - Create OAuth 2.0 Client IDs (select "Desktop app" type).
   - Download the JSON file and save it as `credentials.json` in the same directory as the script.
   - In the menu, select "Gmail → Authorize" to run the OAuth flow and generate `token.json` (this requires a browser; if running on a headless server, generate `token.json` elsewhere and copy it over).

3. **Run the Script**:
   - The Setup Wizard will guide you through entering Telegram details, Gmail emails, and the listener (bot username or user ID).
   - Configuration is saved to `config.json` (you can edit it manually if needed, but use the wizard for safety).

If you encounter issues:
- Missing `credentials.json`: Follow the on-screen instructions to create it.
- Invalid/missing `token.json`: Use the menu to authorize or copy a valid one.
- Telethon session issues: The script detects and explains locks; you may need to delete old session files if prompted.

## Usage
Run the script with Python:
```
python telegram_gmail_forwarder.py
```
- This launches the guided main menu.
- Select "Start forwarder" to begin listening for Telegram messages.

Optional flags:
```
python telegram_gmail_forwarder.py --log          # Enable file logging to tgfwd.log
python telegram_gmail_forwarder.py --no-edit      # Disable editing of Google verification messages (forward raw content)
python telegram_gmail_forwarder.py --log --no-edit  # Combine flags
```

The forwarder runs indefinitely until stopped (Ctrl+C). It automatically resends any pending outbox items when starting if Gmail is authorized.

## Files Used
- `config.json`: User configuration (Telegram creds, emails, listener). Safe to edit manually.
- `credentials.json`: Google OAuth client secrets (download from Google Cloud Console).
- `token.json`: Gmail API access token (generated via authorization menu).
- `.active_listener.json`: Lock file to enforce a single listener (view/clear via menu).
- `outbox/`: Directory for queued failed messages (each in a subfolder with `meta.json` and attachments).
- `tgfwd.log`: Optional log file (enabled with `--log`).
- `forwarder_session.session`: Telethon session file (auto-generated; do not edit).

## Troubleshooting
- **Telegram Connection Issues**: Ensure API ID/Hash are correct. If locked out, wait or delete the `.session` file and re-run setup.
- **Gmail Send Failures**: Check internet, authorize via menu, or inspect `token.json`. Failed messages go to outbox for later resend.
- **No Messages Forwarded**: Verify the listener (bot/username or ID) matches the sender. Use menu to change or view the active lock.
- **Media Attachments**: Supported; downloaded temporarily and attached to emails (or saved to outbox if send fails).
- **Headless/Server Use**: For authorization without a browser, generate `token.json` on a machine with a browser and copy it over.

## Security Notes
- All credential files (`credentials.json`, `token.json`, `config.json`, `.active_listener.json`) are set to 0600 permissions for security.
- The script masks sensitive info (e.g., API Hash) in prompts.
- Only forwards from one specified listener to avoid unintended data exposure.
- Uses Gmail's `send` scope only—no reading of emails.

## License
This script is provided as-is under the MIT License. Feel free to modify and use it for personal purposes.

If you have issues or suggestions, check the script's logs or open an issue (if this is in a repo).