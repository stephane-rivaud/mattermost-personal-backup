#!/usr/bin/env python3
"""
Simple Flask viewer for Mattermost backups produced by mattermost_backup.py.

Usage:
    python viewer.py --backup-dir ~/mattermost_backup --host 127.0.0.1 --port 5000
"""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, abort, render_template_string, send_from_directory, url_for


INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mattermost Backup Viewer</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 2rem; background: #f6f7f8; }
    h1 { color: #166de0; }
    section { background: white; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    ul { list-style: none; padding-left: 0; }
    li { margin-bottom: 0.5rem; }
    a { color: #166de0; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>Mattermost Backup Viewer</h1>
  {% for team_name, channels in grouped.items() %}
  <section>
    <h2>{{ team_name }}</h2>
    <ul>
      {% for channel in channels %}
      <li><a href="{{ url_for('channel_view', channel_id=channel.id) }}">{{ channel.display_name }}</a></li>
      {% endfor %}
    </ul>
  </section>
  {% endfor %}
</body>
</html>
"""


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
    .attachments { margin-top: 0.75rem; font-size: 0.9rem; }
    .attachments ul { list-style: none; padding-left: 0; }
    .attachments li { margin-bottom: 0.35rem; }
    a { color: #166de0; text-decoration: none; }
    a:hover { text-decoration: underline; }
    nav { padding: 1rem 1.5rem; background: #e6ebf2; }
  </style>
</head>
<body>
  <header>
    <h1>{{ channel.display_name }}</h1>
    <p>{{ channel.header or "Mattermost channel backup" }}</p>
  </header>
  <nav>
    <a href="{{ url_for('index') }}">← Back to channels</a>
  </nav>
  <main>
    {% for post in posts %}
    <article>
      <div class="meta">
        <strong>{{ post.username or post.user_id or "Unknown User" }}</strong>
        — {{ post.create_at_human or post.create_at }}
      </div>
      {% if post.message %}
      <div class="message">
        {{ post.message | e | replace("\\n", "<br>") | safe }}
      </div>
      {% endif %}
      {% if post.attachments %}
      <div class="attachments">
        Attachments:
        <ul>
        {% for attachment in post.attachments %}
          <li><a href="{{ attachment.viewer_url }}">{{ attachment.name }}</a> ({{ attachment.size | filesizeformat }})</li>
        {% endfor %}
        </ul>
      </div>
      {% endif %}
    </article>
    {% endfor %}
  </main>
</body>
</html>
"""


@dataclass
class ChannelRecord:
    id: str
    display_name: str
    team_name: str
    json_path: Path
    header: Optional[str] = None


class BackupViewer:
    def __init__(self, backup_dir: Path) -> None:
        self.backup_dir = backup_dir.expanduser().resolve()
        self.json_dir = self.backup_dir / "json"
        self.attachments_dir = self.backup_dir / "attachments"
        self.state_path = self.backup_dir / "state.json"
        self.state: Dict[str, Dict[str, str]] = {}
        self.channels: Dict[str, ChannelRecord] = {}

    def load(self) -> None:
        if not self.json_dir.exists():
            raise FileNotFoundError(f"JSON export directory not found at {self.json_dir}")

        if self.state_path.exists():
            with self.state_path.open(encoding="utf-8") as handle:
                data = json.load(handle)
                self.state = data.get("channels", {})
        else:
            logging.warning("State file not found at %s; indexing JSON files directly", self.state_path)

        if self.state:
            for channel_id, info in self.state.items():
                json_rel = info.get("json")
                if not json_rel:
                    continue
                json_path = (self.backup_dir / json_rel).resolve()
                if json_path.exists():
                    record = self._record_from_json(json_path)
                    self.channels[channel_id] = record
        else:
            for json_file in self.json_dir.rglob("*.json"):
                record = self._record_from_json(json_file)
                self.channels[record.id] = record

        if not self.channels:
            raise RuntimeError("No channels found in backup directory.")

    def _record_from_json(self, json_path: Path) -> ChannelRecord:
        with json_path.open(encoding="utf-8") as handle:
            data = json.load(handle)

        channel = data.get("channel", {})
        display_name = channel.get("display_name") or channel.get("name") or channel.get("id") or json_path.stem
        team_id = channel.get("team_id")
        try:
            relative_parts = json_path.relative_to(self.json_dir).parts
            team_name = relative_parts[0] if relative_parts else (team_id or "unknown-team")
        except ValueError:
            team_name = team_id or "unknown-team"

        return ChannelRecord(
            id=channel.get("id") or json_path.stem,
            display_name=display_name,
            team_name=team_name,
            header=channel.get("header"),
            json_path=json_path,
        )

    def get_posts(self, channel_id: str) -> Dict[str, Any]:
        record = self.channels.get(channel_id)
        if not record:
            raise KeyError(channel_id)
        with record.json_path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return data


def create_app(viewer: BackupViewer) -> Flask:
    app = Flask(__name__)

    def filesizeformat(value: Optional[int]) -> str:
        if value is None:
            return "unknown"
        units = ["B", "KB", "MB", "GB", "TB"]
        size = float(value)
        for unit in units:
            if size < 1024.0 or unit == units[-1]:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    app.jinja_env.filters["filesizeformat"] = filesizeformat

    @app.route("/")
    def index():
        grouped: Dict[str, List[ChannelRecord]] = defaultdict(list)
        for channel in sorted(viewer.channels.values(), key=lambda c: (c.team_name, c.display_name.lower())):
            grouped[channel.team_name].append(channel)
        return render_template_string(INDEX_TEMPLATE, grouped=grouped)

    @app.route("/channel/<channel_id>")
    def channel_view(channel_id: str):
        try:
            payload = viewer.get_posts(channel_id)
        except KeyError:
            abort(404)

        posts = payload.get("posts", [])
        for post in posts:
            attachments = post.get("attachments", [])
            for attachment in attachments:
                local_path = attachment.get("local_path")
                if local_path:
                    attachment["viewer_url"] = url_for("attachment", path=local_path)
        return render_template_string(
            CHANNEL_TEMPLATE,
            channel=payload.get("channel", {}),
            posts=posts,
        )

    @app.route("/attachments/<path:path>")
    def attachment(path: str):
        target = (viewer.backup_dir / path).resolve()
        try:
            target.relative_to(viewer.backup_dir)
        except ValueError:
            abort(404)
        if not target.exists():
            abort(404)
        return send_from_directory(target.parent, target.name)

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Serve a local viewer for Mattermost backups.")
    parser.add_argument("--backup-dir", type=Path, required=True, help="Path to the backup directory.")
    parser.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s: %(message)s")

    viewer = BackupViewer(args.backup_dir)
    viewer.load()

    app = create_app(viewer)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
