"""
LogScrub — Interactive Scrubber controller
Served at: /custom/TA-logscrub/logscrub_scrubber/index  (GET)
           /custom/TA-logscrub/logscrub_scrubber/scrub_text  (POST)

All non-Splunk imports are lazy (inside methods) so that an import error in
the logscrub library does not silently 404 the entire controller.
"""
from __future__ import annotations

import json
import os
import sys

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page

_HERE      = os.path.dirname(os.path.abspath(__file__))
_APP_ROOT  = os.path.dirname(os.path.dirname(_HERE))   # …/TA-logscrub/
_LIB       = os.path.join(_APP_ROOT, "lib")
_TEMPLATE  = os.path.join(_APP_ROOT, "appserver", "templates",
                           "logscrub", "scrubber.html")

_STANDARDS = {
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
        """Serve the scrubber HTML page directly (no Mako templating needed)."""
        cherrypy.response.headers["Content-Type"] = "text/html; charset=utf-8"
        try:
            with open(_TEMPLATE, encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            return f"<pre>LogScrub template not found: {exc}</pre>"

    @expose_page(must_login=True, methods=["POST"])
    def scrub_text(self, **kwargs):
        """Run scrub() on POSTed text; returns JSON."""
        cherrypy.response.headers["Content-Type"] = "application/json; charset=utf-8"
        try:
            # Lazy imports — keeps module-load clean even if lib path is wrong
            if _LIB not in sys.path:
                sys.path.insert(0, _LIB)
            from logscrub.engine import scrub          # noqa: PLC0415
            from logscrub.patterns import get_patterns  # noqa: PLC0415

            text       = kwargs.get("text", "")
            standard   = kwargs.get("standard", "gdpr").lower()
            mask_style = kwargs.get("mask_style", "partial")

            all_names = {p.name for p in get_patterns()}
            allowed   = _STANDARDS.get(standard, _STANDARDS["gdpr"])
            disabled  = (frozenset() if allowed is None
                         else frozenset(all_names - allowed))

            result = scrub(text, mask_style=mask_style,
                           disabled_patterns=disabled)

            payload = {
                "scrubbed": result.text,
                "findings": [
                    {"pattern": f.pattern_name, "category": f.category,
                     "original": f.original, "masked": f.masked}
                    for f in result.findings
                ],
                "finding_count": len(result.findings),
            }
        except Exception as exc:
            cherrypy.response.status = 500
            payload = {"error": str(exc)}

        return json.dumps(payload).encode("utf-8")
