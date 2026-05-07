"""
LogScrub — Interactive Scrubber controller
Served at: /custom/TA-logscrub/logscrub_scrubber
"""
from __future__ import annotations

import json
import os
import sys

import cherrypy

_HERE     = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT = os.path.dirname(os.path.dirname(_HERE))
_LIB      = os.path.join(_APP_ROOT, "lib")
_REPO_ROOT = os.path.dirname(os.path.dirname(_APP_ROOT))

for _p in (_LIB, _REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from logscrub.engine import scrub      # noqa: E402
from logscrub.patterns import get_patterns  # noqa: E402

import splunk.appserver.mrsparkle.controllers as controllers  # noqa: E402
from splunk.appserver.mrsparkle.lib.decorators import expose_page  # noqa: E402

_STANDARDS: dict[str, set[str] | None] = {
    "gdpr":  {"email", "phone", "ssn", "us_passport", "ipv4", "mac_address",
              "credit_card", "iban", "url_credentials", "generic_credential"},
    "hipaa": {"email", "phone", "ssn", "us_passport", "credit_card", "ipv4",
              "url_credentials", "generic_credential"},
    "pci":   {"credit_card", "iban", "url_credentials", "generic_credential"},
    "soc2":  {"jwt", "bearer_token", "openai_key", "github_token",
              "aws_access_key", "slack_token", "stripe_key", "google_api_key",
              "anthropic_key", "sendgrid_key", "url_credentials",
              "generic_credential"},
    "all":   None,
    "none":  set(),
}


class LogScrubScrubber(controllers.BaseController):

    @expose_page(must_login=True, methods=["GET"])
    def index(self, **kwargs):
        return self.render_template("TA-logscrub:logscrub/scrubber.html", {})

    @expose_page(must_login=True, methods=["POST"])
    def scrub_text(self, **kwargs):
        cherrypy.response.headers["Content-Type"] = "application/json; charset=utf-8"
        try:
            text       = kwargs.get("text", "")
            standard   = kwargs.get("standard", "gdpr").lower()
            mask_style = kwargs.get("mask_style", "partial")

            all_names = {p.name for p in get_patterns()}
            allowed   = _STANDARDS.get(standard, _STANDARDS["gdpr"])
            disabled  = frozenset() if allowed is None else frozenset(all_names - allowed)

            result = scrub(text, mask_style=mask_style, disabled_patterns=disabled)

            findings = [
                {
                    "pattern": f.pattern_name,
                    "category": f.category,
                    "original": f.original,
                    "masked": f.masked,
                }
                for f in result.findings
            ]

            payload = {
                "scrubbed": result.text,
                "findings": findings,
                "finding_count": len(findings),
            }
        except Exception as exc:
            cherrypy.response.status = 500
            payload = {"error": str(exc)}

        return json.dumps(payload).encode("utf-8")
