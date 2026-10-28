"""Alert channels: CLI, webhook, email, and delta alert digests.

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


def build_digest_alert(alert_payloads, watchlist_name="perimeter-watch"):
    """Batch multiple domain alert payloads into a single digest message (markdown)."""
    md_lines = [
        f"# Perimeter Alert Digest — {watchlist_name}",
        f"Total alerting domains: {len(alert_payloads)}",
        "",
    ]
    for domain in sorted(alert_payloads.keys()):
        alert = alert_payloads[domain]
        md_lines.append(f"## Domain: {domain}")
        if alert.get("takeover_risks"):
            md_lines.append("### Takeover Risks:")
            for name in sorted(alert["takeover_risks"].keys()):
                r = alert["takeover_risks"][name]
                md_lines.append(f"- **{name}**: {r.get('evidence')}")
        if alert.get("secret_exposures"):
            md_lines.append("### Secret Exposures:")
            for base in sorted(alert["secret_exposures"].keys()):
                findings = alert["secret_exposures"][base]
                for f in findings:
                    md_lines.append(f"- **{f.get('url')}**: {f.get('evidence')}")
        if alert.get("bucket_exposures"):
            md_lines.append("### Bucket Exposures:")
            for b in alert["bucket_exposures"]:
                md_lines.append(f"- **{b.get('name')}** ({b.get('provider')}): {b.get('evidence')}")
        if alert.get("newly_dangling"):
            md_lines.append(f"### Newly Dangling Subdomains: {', '.join(alert['newly_dangling'])}")
        if alert.get("added"):
            md_lines.append(f"### Added Subdomains: {', '.join(alert['added'])}")
        if alert.get("removed"):
            md_lines.append(f"### Removed Subdomains: {', '.join(alert['removed'])}")
        md_lines.append("")

    summary_md = "\n".join(md_lines).strip()

    digest_body = {
        "digest": True,
        "watch": watchlist_name,
        "domain_alerts_count": len(alert_payloads),
        "alerts": alert_payloads,
        "summary_markdown": summary_md,
        "body": summary_md,
    }
    return digest_body


def get_digest_config(watchlist, cli_digest=False, cli_threshold=None):
    """Determine (digest_enabled, threshold) from watchlist config and CLI options."""
    wl_digest = watchlist.get("digest")
    wl_thresh = watchlist.get("digest_threshold")

    enabled = False
    threshold = 1

    if isinstance(wl_digest, bool):
        enabled = wl_digest
    elif isinstance(wl_digest, int):
        enabled = True
        threshold = wl_digest
    elif isinstance(wl_digest, dict):
        enabled = wl_digest.get("enabled", True)
        threshold = wl_digest.get("threshold", 1)

    if wl_thresh is not None and isinstance(wl_thresh, int):
        threshold = wl_thresh

    if cli_digest:
        enabled = True
    if cli_threshold is not None:
        threshold = cli_threshold
        enabled = True

    return enabled, max(1, threshold)


def should_alert(alert):
    return bool(alert.get("takeover_risks") or alert.get("secret_exposures")
                or alert.get("newly_dangling") or alert.get("added") or alert.get("removed")
                or alert.get("bucket_exposures"))


def send_webhook(url, alert, timeout=10, post=None):
    """POST the alert JSON to a webhook URL."""
    post = post or _default_post
    return post(url, json.dumps(alert), timeout)


def send_email(config, alert, smtp=None):
    """Send the alert via SMTP. config: host, port, user, password, to, from."""
    smtp = smtp or _default_smtp
    msg = EmailMessage()
    if alert.get("digest"):
        msg["Subject"] = f"[perimeter-watch] {alert.get('watch', 'perimeter')}: Alert Digest ({alert.get('domain_alerts_count', 0)} domains)"
        msg.set_content(alert.get("summary_markdown", json.dumps(alert, indent=2)))
    else:
        msg["Subject"] = f"[perimeter-watch] {alert['watch']}: exposure detected"
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
