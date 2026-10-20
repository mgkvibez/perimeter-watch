"""Dangling CNAME / takeover signature detection.

A name is a takeover risk when it resolves an alias (CNAME chain) to a
service whose underlying resource is gone — the alias target itself no
longer resolves, and the target matches a known takeover-prone service.
"""
SIGNATURES = [
    ("herokuapp.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudfront.net", "CloudFront"),
    ("fastly.net", "Fastly"),
    ("pantheon.io", "Pantheon"),
    ("squarespace.com", "Squarespace"),
    ("wordpress.com", "WordPress.com"),
    ("tumblr.com", "Tumblr"),
    ("shopify.com", "Shopify"),
    ("zendesk.com", "Zendesk"),
    ("readme.io", "ReadMe"),
]


def classify(record, resolve_fn=None):
    """Classify one resolution record for takeover risk.

    Returns None (no risk) or a dict with the risk and evidence.
    `resolve_fn` lets tests inject resolution of the alias target.
    """
    if record is None or not record["aliases"]:
        return None

    resolve_fn = resolve_fn or __import__("perimeter_watch.resolver",
                                          fromlist=["resolve"]).resolve

    for alias in record["aliases"]:
        service = next((s for suffix, s in SIGNATURES if alias.endswith(suffix)), None)
        target = resolve_fn(alias)
        dangling = target is None
        if service and dangling:
            return {
                "risk": "takeover",
                "service": service,
                "alias": alias,
                "evidence": f"CNAME to {alias} ({service}) no longer resolves",
            }
    return None


def classify_all(resolved, resolve_fn=None):
    """Return {name: risk-dict} for every risky record."""
    risks = {}
    for name, record in resolved.items():
        risk = classify(record, resolve_fn=resolve_fn)
        if risk:
            risks[name] = risk
    return risks
