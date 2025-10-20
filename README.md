# Mattermost Personal Backup

Tools for exporting all content accessible to a Mattermost user (teams, channels, direct messages, attachments) and browsing the backup locally.

## Features
- Authenticates with either a personal access token or an existing browser session cookie.
- Exports messages and attachments for every visible channel, preserving thread metadata.
- Generates JSON archives plus readable HTML snapshots for each channel.
- Supports resume and verification modes for large exports.
- Optional Flask viewer for navigating the backup by team/channel.

## Project Layout
```
.
├── README.md
├── environment.yml          # Conda environment definition
├── mattermost_backup.py     # Backup/export CLI
├── viewer.py                # Optional Flask viewer
└── backup_output/           # Default export destination (created after first run)
    ├── json/<team>/<channel>.json
    ├── html/<team>/<channel>.html
    └── attachments/<team>/<channel>/
```

## Getting Started

### 1. Create and activate the environment
```bash
conda env create -f environment.yml
conda activate mattermost-backup
```

### 2. Collect authentication credentials

You can authenticate in one of two ways:

1. **Personal Access Token (PAT)**  
   - In Mattermost, open your profile menu → *Security* → *Personal Access Tokens*.  
   - Create a token, copy its value, and keep it secret (Mattermost shows it only once).  
   - Pass it with `--token YOUR_TOKEN`.

2. **Session cookie (works with SSO/GitLab logins)**  
   - Log into Mattermost via the browser you normally use.  
   - Open developer tools → Storage/Application tab → Cookies for your Mattermost domain.  
   - Copy the value of the `MMAUTHTOKEN` cookie (or the cookie name used by your instance).  
   - Save it to a file, e.g.:
     ```bash
     printf 'MMAUTHTOKEN=%s\n' 'PASTE_COOKIE_VALUE' > mm_cookie.txt
     ```
   - Provide that file with `--session-cookie mm_cookie.txt`.

### 3. Run a backup
```bash
python mattermost_backup.py \
  --server https://mattermost.inria.fr \
  --user strivaud \
  --output backup_output \
  --resume \
  --session-cookie mm_cookie.txt
```

Flags of interest:
- `--resume` skips channels that already have JSON+HTML exports.
- `--verify` checks an existing backup for missing files or corrupt JSON.
- `--insecure` disables TLS verification (only if necessary, e.g. for self-signed certs).

### 4. Browse the export (optional)
```bash
python viewer.py --backup-dir backup_output --host 127.0.0.1 --port 5000
```
Open `http://127.0.0.1:5000` to browse messages and download attachments locally.

## Tips
- Re-run the backup periodically; `--resume` keeps it incremental.
- Rotate session cookies when your Mattermost login expires.
- Store exports securely—JSON files include message contents and attachment paths.

## Sharing
To publish this project for colleagues:
1. Create a new GitHub repository under your account.
2. Push this directory (including `backup_output/.gitkeep` if you add one) to the new repo.
3. Share the repository URL along with instructions from this README.

## License
Add your preferred license here before sharing publicly.
