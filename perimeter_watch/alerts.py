"""Alert channels: CLI, webhook, email.

Dispatchers are injectable — tests pass callables; production uses
urllib (webhook) and smtplib (email). Secrets never logged.
"""
import json
import smtplib
import urllib.request
from email.message import EmailMessage


def build_alert(watchlist_name, findings, risks, changes, buckets=None):
    """One alert payload describing this run's notable events."""
    body = {
        "watch": watchlist_name,
        "newly_dangling": changes.get("newly_dangling", []),
        "added": changes.get("added", []),
        "removed": changes.get("removed", []),
        "takeover_risks": risks,
        "secret_exposures": findings,
        "bucket_exposures": buckets or [],
    }
    return body


def should_alert(alert):
    return bool(alert["takeover_risks"] or alert["secret_exposures"]
                or alert["newly_dangling"] or alert["added"] or alert["removed"])


def send_webhook(url, alert, timeout=10, post=None):
    """POST the alert JSON to a webhook URL."""
    post = post or _default_post
    return post(url, json.dumps(alert), timeout)


def send_email(config, alert, smtp=None):
    """Send the alert via SMTP. config: host, port, user, password, to, from."""
    smtp = smtp or _default_smtp
    msg = EmailMessage()
    msg["Subject"] = f"[perimeter-watch] {alert['watch']}: exposure detected"
    msg["From"] = config.get("from", config["user"])
    msg["To"] = config["to"]
    msg.set_content(json.dumps(alert, indent=2))
    smtp(config, msg)


def _default_post(url, payload, timeout):
    req = urllib.request.Request(url, data=payload.encode("utf-8"),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status


def _default_smtp(config, msg):
    with smtplib.SMTP(config["host"], config["port"], timeout=15) as server:
        server.starttls()
        server.login(config["user"], config["password"])
        server.send_message(msg)


def dispatch(alert, channels, senders=None):
    """Dispatch through every configured channel. Returns per-channel results."""
    senders = senders or {"webhook": send_webhook, "email": send_email}
    results = {}
    for name, conf in (channels or {}).items():
        if name == "webhook":
            results["webhook"] = senders["webhook"](conf["url"], alert)
        elif name == "email":
            results["email"] = senders["email"](conf, alert)
    return results
