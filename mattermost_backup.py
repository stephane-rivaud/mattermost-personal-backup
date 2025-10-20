#!/usr/bin/env python3
"""
Mattermost Backup Tool
======================

Usage:
    python mattermost_backup.py --server https://mattermost.inria.fr --user strivaud --output ~/mattermost_backup

This script exports all Mattermost data that is accessible to the authenticated user, including
teams, channels (public, private, direct, and group), posts, and attachments. JSON and HTML
representations are generated for each channel, and attachments are stored locally so that
conversations remain browsable offline. The tool supports resuming interrupted exports, verifying
existing backups, and includes clear logging for transparency during long-running operations.

Dependencies:
    - Python 3.10+
    - requests
    - tqdm
    - jinja2

Ensure these packages are installed in your environment prior to running the script.
"""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from jinja2 import Environment, select_autoescape
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError, RequestException
from tqdm import tqdm
from urllib3.util.retry import Retry


DEFAULT_PER_PAGE = 200
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "backup_output"
CHANNEL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{{ channel.display_name }} — Mattermost Backup</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f6f7f8; margin: 0; padding: 0; }
        header { background: #166de0; color: white; padding: 1.5rem; }
        main { padding: 1.5rem; }
        article { background: white; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        .meta { color: #57616c; font-size: 0.9rem; margin-bottom: 0.5rem; }
        pre { background: #f0f3f7; padding: 0.75rem; border-radius: 6px; overflow-x: auto; }
        .attachment { margin-top: 0.5rem; font-size: 0.9rem; }
        .thread { border-left: 3px solid #d1d7de; margin-left: 1.5rem; padding-left: 1rem; margin-top: 0.75rem; }
        a { color: #166de0; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <header>
        <h1>{{ channel.display_name }}</h1>
        <p>{{ channel.header or "Mattermost channel backup" }}</p>
    </header>
    <main>
        {% for post in posts %}
        <article id="{{ post.id }}">
            <div class="meta">
                <strong>{{ post.username or post.user_id or "Unknown User" }}</strong>
                — {{ post.create_at_human }}
                {% if post.is_thread_root %}(thread root){% endif %}
            </div>
            {% if post.message %}
            <div class="message">
                {{ post.message | e | replace("\\n", "<br>") | safe }}
            </div>
            {% endif %}
            {% if post.attachments %}
            <div class="attachment">
                Attachments:
                <ul>
                {% for attachment in post.attachments %}
                    <li><a href="{{ attachment.local_path }}">{{ attachment.name }}</a>
                        ({{ attachment.size | filesizeformat }})</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            {% if post.reply_count %}
            <div class="thread">
                Replies: {{ post.reply_count }} (see thread in JSON export)
            </div>
            {% endif %}
        </article>
        {% endfor %}
    </main>
</body>
</html>
"""


def configure_logging(level: str) -> None:
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def sanitize_filename(name: str) -> str:
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "-" for c in name.strip())
    safe = "-".join(filter(None, safe.split("-")))
    return safe or "untitled"


def humanize_timestamp(timestamp_ms: int) -> str:
    from datetime import datetime

    if not timestamp_ms:
        return "Unknown time"
    dt = datetime.utcfromtimestamp(timestamp_ms / 1000.0)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


@dataclass
class ChannelInfo:
    id: str
    name: str
    display_name: str
    type: str
    team_id: Optional[str]
    header: Optional[str] = None


class MattermostBackupError(Exception):
    """Raised when the backup process encounters a fatal error."""


class MattermostBackup:
    def __init__(
        self,
        server: str,
        username: Optional[str],
        output: Path,
        token: Optional[str],
        cookie_path: Optional[Path],
        cookie_name: str,
        resume: bool,
        verify_only: bool,
        timeout: int,
        verify_tls: bool,
    ) -> None:
        self.server = server.rstrip("/")
        self.api_base = urljoin(self.server + "/", "api/v4/")
        self.username = username
        self.output = output.expanduser().resolve()
        self.token = token
        self.cookie_path = cookie_path
        self.cookie_name = cookie_name
        self.resume = resume
        self.verify_only = verify_only
        self.timeout = timeout
        self.verify_tls = verify_tls

        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.user: Optional[Dict[str, Any]] = None
        self.team_map: Dict[str, Dict[str, Any]] = {}
        self.channel_map: Dict[str, ChannelInfo] = {}
        self.user_cache: Dict[str, Dict[str, Any]] = {}

        self.state_path = self.output / "state.json"
        self.state: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    def authenticate(self) -> None:
        if self.cookie_path and self.cookie_path.exists():
            raw_cookie = self.cookie_path.read_text(encoding="utf-8").strip()
            cookie_value = raw_cookie.split("=", 1)[-1].strip()
            domain = urlparse(self.server).hostname or ""
            logging.info("Using session cookie from %s", self.cookie_path)
            self.session.cookies.set(self.cookie_name, cookie_value, domain=domain)
        elif self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"
            logging.info("Using personal access token for authentication")
        else:
            self.session.headers["Authorization"] = f"Bearer {self._prompt_token()}"
            logging.info("Using personal access token obtained via prompt")

        self.user = self._get("/users/me")
        logging.info("Authenticated as %s (%s)", self.user.get("username"), self.user.get("email", "no-email"))

    def _prompt_token(self) -> str:
        token = getpass.getpass("Enter Mattermost personal access token: ").strip()
        if not token:
            raise MattermostBackupError("No token provided; cannot authenticate.")
        return token

    # ------------------------------------------------------------------ #
    # HTTP helpers
    # ------------------------------------------------------------------ #
    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        url = urljoin(self.api_base, path.lstrip("/"))
        try:
            response = self.session.get(url, params=params, timeout=self.timeout, verify=self.verify_tls)
            response.raise_for_status()
        except HTTPError as exc:
            if exc.response.status_code == 401:
                raise MattermostBackupError("Unauthorized: check token or session cookie.") from exc
            if exc.response.status_code == 403:
                raise MattermostBackupError("Forbidden: account lacks required permissions.") from exc
            raise MattermostBackupError(f"HTTP error {exc.response.status_code} for {url}") from exc
        except RequestException as exc:
            raise MattermostBackupError(f"Request to {url} failed: {exc}") from exc
        if response.headers.get("Content-Type", "").startswith("application/json"):
            return response.json()
        return response.content

    def _get_stream(self, path: str) -> requests.Response:
        url = urljoin(self.api_base, path.lstrip("/"))
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_tls, stream=True)
            response.raise_for_status()
        except HTTPError as exc:
            raise MattermostBackupError(f"HTTP error {exc.response.status_code} during download: {url}") from exc
        except RequestException as exc:
            raise MattermostBackupError(f"Download request failed for {url}: {exc}") from exc
        return response

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def discover(self) -> None:
        teams = self._get("/users/me/teams")
        self.team_map = {team["id"]: team for team in teams}
        logging.info("Discovered %d teams", len(self.team_map))

        channels = self._collect_channels(teams)
        self.channel_map = {channel.id: channel for channel in channels}
        logging.info("Discovered %d channels (public/private/direct/group)", len(self.channel_map))

    def _collect_channels(self, teams: Iterable[Dict[str, Any]]) -> List[ChannelInfo]:
        channels: Dict[str, ChannelInfo] = {}

        # Attempt to use unified endpoint first
        try:
            raw_channels = self._get("/users/me/channels")
            logging.debug("Fetched %d channels via /users/me/channels", len(raw_channels))
            for channel in raw_channels:
                channels[channel["id"]] = self._channel_from_payload(channel)
        except MattermostBackupError as exc:
            logging.debug("Unified channel listing unavailable (%s); falling back to per-team listing", exc)

        # Fallback per team
        for team in teams:
            team_id = team["id"]
            try:
                team_channels = self._get(f"/users/me/channels/{team_id}")
            except MattermostBackupError as exc:
                logging.warning("Failed to fetch channels for team %s (%s): %s", team.get("display_name"), team_id, exc)
                continue
            for channel in team_channels:
                channels[channel["id"]] = self._channel_from_payload(channel)

        # Ensure DM / GM display names are populated
        for channel_id, info in list(channels.items()):
            if info.display_name:
                continue
            try:
                data = self._get(f"/channels/{channel_id}")
                channels[channel_id] = ChannelInfo(
                    id=data["id"],
                    name=data.get("name", info.name),
                    display_name=data.get("display_name") or info.display_name or data.get("name") or data["id"],
                    type=data.get("type", info.type),
                    team_id=data.get("team_id") or info.team_id,
                    header=data.get("header") or info.header,
                )
            except MattermostBackupError:
                # Best effort; keep existing info
                continue

        return list(channels.values())

    @staticmethod
    def _channel_from_payload(payload: Dict[str, Any]) -> ChannelInfo:
        return ChannelInfo(
            id=payload["id"],
            name=payload.get("name") or payload["id"],
            display_name=payload.get("display_name") or payload.get("name") or payload["id"],
            type=payload.get("type", "O"),
            team_id=payload.get("team_id"),
            header=payload.get("header"),
        )

    # ------------------------------------------------------------------ #
    # State management
    # ------------------------------------------------------------------ #
    def load_state(self) -> None:
        if self.state_path.exists():
            try:
                self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
                logging.info("Loaded existing state from %s", self.state_path)
            except json.JSONDecodeError:
                logging.warning("State file at %s is corrupt; starting fresh", self.state_path)
                self.state = {}
        else:
            self.state = {}

    def save_state(self) -> None:
        temp_path = self.state_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")
        temp_path.replace(self.state_path)

    # ------------------------------------------------------------------ #
    # Export operations
    # ------------------------------------------------------------------ #
    def export(self) -> None:
        ensure_directory(self.output)
        ensure_directory(self.output / "json")
        ensure_directory(self.output / "html")
        ensure_directory(self.output / "attachments")

        self.load_state()

        if self.user:
            self.state.setdefault("server", self.server)
            self.state.setdefault("user_id", self.user.get("id"))
            self.state.setdefault("username", self.user.get("username"))
            self.state.setdefault("channels", {})
            self.save_state()

        total_channels = len(self.channel_map)
        exported_channels = 0
        total_messages = 0
        total_attachments = 0

        channel_iter = tqdm(
            self.channel_map.values(),
            desc="Exporting channels",
            unit="channel",
        )

        for channel in channel_iter:
            team_dir, channel_dir = self._resolve_paths(channel)
            json_path = self.output / "json" / team_dir / f"{channel_dir}.json"
            html_path = self.output / "html" / team_dir / f"{channel_dir}.html"
            attachments_dir = self.output / "attachments" / team_dir / channel_dir
            ensure_directory(json_path.parent)
            ensure_directory(html_path.parent)
            ensure_directory(attachments_dir)

            if self.resume and json_path.exists() and html_path.exists():
                logging.info("Skipping %s (resume mode, files already exist)", channel.display_name)
                exported_channels += 1
                continue

            logging.info("Exporting channel %s (%s)", channel.display_name, channel.id)
            posts, attachments = self._export_channel_posts(channel, attachments_dir)
            total_messages += len(posts)
            total_attachments += len(attachments)

            self._write_json(json_path, channel, posts, attachments)
            self._write_html(html_path, channel, posts)

            state_entry = self.state.setdefault("channels", {})
            state_entry[channel.id] = {
                "last_export_ts": max((post.get("update_at", 0) for post in posts), default=0),
                "json": str(json_path.relative_to(self.output)),
                "html": str(html_path.relative_to(self.output)),
            }
            self.save_state()
            exported_channels += 1

        logging.info(
            "Export complete: %d/%d channels, %d messages, %d attachments",
            exported_channels,
            total_channels,
            total_messages,
            total_attachments,
        )

    def _export_channel_posts(
        self,
        channel: ChannelInfo,
        attachments_dir: Path,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        posts: List[Dict[str, Any]] = []
        all_attachments: List[Dict[str, Any]] = []
        page = 0
        seen_ids = set()

        while True:
            payload = self._get(
                f"/channels/{channel.id}/posts",
                params={"page": page, "per_page": DEFAULT_PER_PAGE},
            )
            order = payload.get("order", [])
            post_map = payload.get("posts", {})

            if not order:
                break

            for post_id in reversed(order):
                if post_id in seen_ids:
                    continue
                post = post_map.get(post_id)
                if not post:
                    continue
                processed_post, attachments = self._process_post(post, attachments_dir)
                posts.append(processed_post)
                all_attachments.extend(attachments)
                seen_ids.add(post_id)

            if len(order) < DEFAULT_PER_PAGE:
                break
            page += 1

        posts.sort(key=lambda p: p.get("create_at", 0))
        return posts, all_attachments

    def _process_post(
        self,
        post: Dict[str, Any],
        attachments_dir: Path,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        user_id = post.get("user_id")
        user = self._get_user(user_id) if user_id else None
        username = user.get("username") if user else None

        processed = {
            "id": post.get("id"),
            "create_at": post.get("create_at"),
            "update_at": post.get("update_at"),
            "create_at_human": humanize_timestamp(post.get("create_at", 0)),
            "user_id": user_id,
            "username": username,
            "root_id": post.get("root_id"),
            "parent_id": post.get("parent_id"),
            "reply_count": post.get("reply_count"),
            "message": post.get("message"),
            "props": post.get("props", {}),
            "metadata": {
                "priority": post.get("metadata", {}).get("priority"),
                "embeds": post.get("metadata", {}).get("embeds", []),
                "mentions": post.get("metadata", {}).get("mentions", []),
            },
            "is_thread_root": post.get("id") == post.get("thread_id") or not post.get("parent_id"),
            "attachments": [],
        }

        attachments: List[Dict[str, Any]] = []
        file_infos = post.get("metadata", {}).get("files", []) or []
        for file_info in file_infos:
            attachment = self._handle_attachment(file_info, attachments_dir)
            processed["attachments"].append(attachment)
            attachments.append(attachment)

        return processed, attachments

    def _handle_attachment(self, file_info: Dict[str, Any], attachments_dir: Path) -> Dict[str, Any]:
        file_id = file_info.get("id")
        original_name = file_info.get("name") or f"{file_id}.bin"
        safe_name = sanitize_filename(original_name)
        filename = f"{file_id}_{safe_name}"
        local_path = attachments_dir / filename

        if not local_path.exists():
            response = self._get_stream(f"/files/{file_id}")
            with local_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)

        relative_path = local_path.relative_to(self.output)
        return {
            "id": file_id,
            "name": original_name,
            "mime_type": file_info.get("mime_type"),
            "size": file_info.get("size"),
            "has_preview_image": file_info.get("has_preview_image"),
            "width": file_info.get("width"),
            "height": file_info.get("height"),
            "local_path": str(relative_path),
        }

    def _get_user(self, user_id: str) -> Dict[str, Any]:
        if user_id in self.user_cache:
            return self.user_cache[user_id]
        data = self._get(f"/users/{user_id}")
        self.user_cache[user_id] = data
        return data

    def _write_json(
        self,
        path: Path,
        channel: ChannelInfo,
        posts: List[Dict[str, Any]],
        attachments: List[Dict[str, Any]],
    ) -> None:
        from datetime import datetime

        payload = {
            "server": self.server,
            "user": self.user,
            "channel": {
                "id": channel.id,
                "name": channel.name,
                "display_name": channel.display_name,
                "team_id": channel.team_id,
                "type": channel.type,
                "header": channel.header,
            },
            "exported_at_iso": datetime.utcnow().isoformat() + "Z",
            "posts": posts,
            "attachments": attachments,
        }

        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(path)

    def _write_html(self, path: Path, channel: ChannelInfo, posts: List[Dict[str, Any]]) -> None:
        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        env.filters["filesizeformat"] = self._filesizeformat
        template = env.from_string(CHANNEL_TEMPLATE)
        html_posts: List[Dict[str, Any]] = []
        for post in posts:
            post_copy = dict(post)
            attachments_copy = []
            for attachment in post.get("attachments", []):
                attachment_copy = dict(attachment)
                local_path = attachment_copy.get("local_path")
                if local_path:
                    absolute = (self.output / local_path).resolve()
                    rel_path = os.path.relpath(absolute, path.parent)
                    attachment_copy["local_path"] = rel_path
                attachments_copy.append(attachment_copy)
            post_copy["attachments"] = attachments_copy
            html_posts.append(post_copy)

        html = template.render(channel=channel, posts=html_posts)

        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(html, encoding="utf-8")
        tmp_path.replace(path)

    @staticmethod
    def _filesizeformat(value: Optional[int]) -> str:
        if value is None:
            return "unknown"
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(value)
        for unit in units:
            if size < 1024.0 or unit == units[-1]:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def _resolve_paths(self, channel: ChannelInfo) -> Tuple[str, str]:
        team_name = "no-team"
        if channel.team_id and channel.team_id in self.team_map:
            team = self.team_map[channel.team_id]
            team_name = sanitize_filename(team.get("name") or team.get("display_name") or channel.team_id)
        elif channel.type == "D":
            team_name = "direct-messages"
        elif channel.type == "G":
            team_name = "group-messages"
        else:
            team_name = "misc"

        channel_token = sanitize_filename(channel.display_name or channel.name or channel.id)
        return team_name, f"{channel_token}-{channel.id[:8]}"

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #
    def verify(self) -> bool:
        logging.info("Verifying backup integrity in %s", self.output)
        json_root = self.output / "json"
        html_root = self.output / "html"
        attachments_root = self.output / "attachments"

        if not json_root.exists():
            logging.error("JSON directory %s does not exist", json_root)
            return False

        issues: List[str] = []
        for json_file in json_root.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                issues.append(f"{json_file}: invalid JSON ({exc})")
                continue

            channel_info = data.get("channel", {})

            # Attempt to infer corresponding HTML path from state if available
            state_ch = self.state.get("channels", {}).get(channel_info.get("id"))
            if state_ch:
                html_rel = state_ch.get("html")
                if html_rel:
                    html_candidate = self.output / html_rel
                    if not html_candidate.exists():
                        issues.append(f"Missing HTML for {json_file}: expected {html_candidate}")
            else:
                html_guess = html_root / json_file.relative_to(json_root)
                html_guess = html_guess.with_suffix(".html")
                if not html_guess.exists():
                    issues.append(f"Missing HTML companion for {json_file}")

            for post in data.get("posts", []):
                for attachment in post.get("attachments", []):
                    local_path = attachment.get("local_path")
                    if not local_path:
                        issues.append(f"{json_file}: attachment without local_path")
                        continue
                    target = self.output / local_path
                    if not target.exists():
                        issues.append(f"Missing attachment {target} referenced in {json_file}")
                        continue
                    expected_size = attachment.get("size")
                    if expected_size is not None and target.stat().st_size != expected_size:
                        issues.append(
                            f"Size mismatch for attachment {target} (expected {expected_size}, "
                            f"found {target.stat().st_size})"
                        )

        if issues:
            logging.error("Verification failed with %d issues:", len(issues))
            for issue in issues:
                logging.error(" - %s", issue)
            return False

        if attachments_root.exists():
            total_files = sum(1 for _ in attachments_root.rglob("*") if _.is_file())
            logging.info("Verification succeeded. %d attachment files accounted for.", total_files)
        else:
            logging.info("Verification succeeded. No attachments directory found.")
        return True


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backup accessible Mattermost data to a local archive.")
    parser.add_argument("--server", required=True, help="Mattermost server base URL (e.g. https://mattermost.example.com)")
    parser.add_argument("--user", dest="username", help="Username (display purposes only)")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Destination directory for the backup (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument("--token", help="Personal access token for authentication")
    parser.add_argument(
        "--session-cookie",
        type=Path,
        help="Path to a file containing a valid Mattermost session cookie value",
    )
    parser.add_argument(
        "--cookie-name",
        default="MMAUTHTOKEN",
        help="Cookie name to use when authenticating with --session-cookie (default: MMAUTHTOKEN)",
    )
    parser.add_argument("--resume", action="store_true", help="Resume an interrupted export, skipping completed channels")
    parser.add_argument("--verify", action="store_true", help="Verify an existing backup and exit")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP request timeout in seconds (default: 30)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (use with caution)")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.log_level)

    backup = MattermostBackup(
        server=args.server,
        username=args.username,
        output=args.output,
        token=args.token,
        cookie_path=args.session_cookie,
        cookie_name=args.cookie_name,
        resume=args.resume,
        verify_only=args.verify,
        timeout=args.timeout,
        verify_tls=not args.insecure,
    )

    try:
        if args.verify:
            backup.load_state()
            ok = backup.verify()
            return 0 if ok else 1

        backup.authenticate()
        backup.discover()
        backup.export()
        logging.info("Backup finished successfully.")
        return 0
    except MattermostBackupError as exc:
        logging.error("Backup failed: %s", exc)
        return 2
    except KeyboardInterrupt:
        logging.error("Backup interrupted by user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
