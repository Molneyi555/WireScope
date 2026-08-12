"""Small, reviewable tracker signature dataset bundled with WireScope.

This is deliberately not a universal blocklist.  Rules identify a compact set
of widely used analytics, advertising and session-replay endpoints for local
explanation.  A match is evidence of an endpoint signature, not proof of user
tracking or a privacy violation.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple


TRACKER_DATASET: Dict[str, Any] = {
    "name": "wirescope-curated-trackers",
    "version": "2026.08.11.1",
    "scope": "small-curated-signature-set",
    "provenance": "Manually reviewed WireScope signatures; no remote blocklist is fetched at runtime.",
    "limitations": [
        "The dataset is intentionally small and cannot establish that unmatched traffic is tracker-free.",
        "A signature match identifies an endpoint; it does not prove consent status, purpose, or legal compliance.",
        "First-party and proxied analytics may not be identifiable from hostname and path metadata alone.",
    ],
}


TRACKER_RULES: Tuple[Dict[str, Any], ...] = (
    {"id": "google-analytics", "owner": "Google", "category": "analytics", "domains": ("google-analytics.com",), "confidence": "high", "description": "Google Analytics collection endpoint."},
    {"id": "google-tag-manager", "owner": "Google", "category": "tag-manager", "domains": ("googletagmanager.com",), "confidence": "high", "description": "Google Tag Manager script or collection endpoint."},
    {"id": "google-doubleclick", "owner": "Google", "category": "advertising", "domains": ("doubleclick.net", "googlesyndication.com"), "confidence": "high", "description": "Google advertising delivery or measurement endpoint."},
    {"id": "meta-connect", "owner": "Meta", "category": "social-pixel", "domains": ("connect.facebook.net",), "confidence": "high", "description": "Meta social SDK or Pixel script endpoint."},
    {"id": "meta-pixel", "owner": "Meta", "category": "social-pixel", "domains": ("facebook.com",), "path_prefixes": ("/tr",), "confidence": "high", "description": "Meta Pixel event collection path."},
    {"id": "x-analytics", "owner": "X Corp.", "category": "analytics", "domains": ("analytics.twitter.com",), "confidence": "high", "description": "X/Twitter analytics endpoint."},
    {"id": "hotjar", "owner": "Hotjar", "category": "session-replay", "domains": ("static.hotjar.com", "script.hotjar.com", "vars.hotjar.com", "ws.hotjar.com", "in.hotjar.com"), "confidence": "high", "description": "Hotjar analytics or session-replay endpoint."},
    {"id": "microsoft-clarity", "owner": "Microsoft", "category": "session-replay", "domains": ("c.clarity.ms", "d.clarity.ms"), "confidence": "high", "description": "Microsoft Clarity collection endpoint."},
    {"id": "microsoft-clarity-tag", "owner": "Microsoft", "category": "session-replay", "domains": ("www.clarity.ms",), "path_prefixes": ("/tag",), "confidence": "high", "description": "Microsoft Clarity tag script."},
    {"id": "segment", "owner": "Twilio", "category": "analytics", "domains": ("api.segment.io", "cdn.segment.com"), "confidence": "high", "description": "Segment event ingestion or SDK endpoint."},
    {"id": "mixpanel", "owner": "Mixpanel", "category": "analytics", "domains": ("api.mixpanel.com", "api-js.mixpanel.com", "cdn.mxpnl.com"), "confidence": "high", "description": "Mixpanel event ingestion or SDK endpoint."},
    {"id": "amplitude", "owner": "Amplitude", "category": "analytics", "domains": ("api.amplitude.com", "api2.amplitude.com", "cdn.amplitude.com"), "confidence": "high", "description": "Amplitude event ingestion or SDK endpoint."},
    {"id": "yandex-metrica", "owner": "Yandex", "category": "analytics", "domains": ("metrika.yandex.ru", "mc.yandex.ru"), "confidence": "high", "description": "Yandex Metrica script or collection endpoint."},
    {"id": "tiktok-pixel", "owner": "ByteDance", "category": "social-pixel", "domains": ("tiktok.com",), "path_prefixes": ("/i18n/pixel",), "confidence": "high", "description": "TikTok Pixel event collection path."},
    {"id": "matomo-endpoint", "owner": "self-hosted/unknown", "category": "analytics", "path_suffixes": ("/matomo.php", "/piwik.php"), "confidence": "medium", "description": "Conventional self-hosted Matomo/Piwik collection path."},
)
