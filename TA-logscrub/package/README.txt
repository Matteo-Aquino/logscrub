LogScrub — PII & Secret Sanitizer
===================================
Version: 1.0.0
Author:  Matteo Aquino

OVERVIEW
--------
LogScrub provides the | sanitize streaming search command that masks PII and
secrets from Splunk event fields in-pipeline. No data leaves Splunk — all
scrubbing runs locally on the search head.

REQUIREMENTS
------------
- Splunk Enterprise or Splunk Cloud >= 8.2
- Python 3 (included in Splunk >= 8.x)

INSTALLATION
------------
1. Install via Splunkbase, or drop TA-logscrub/ into $SPLUNK_HOME/etc/apps/
2. Restart Splunk (or use the Apps > Manage Apps > Reload page)
3. Navigate to Apps > LogScrub > Configuration to set global defaults

USAGE
-----
Basic (GDPR defaults):
    index=app_logs | sanitize

Choose a compliance standard:
    index=app_logs | sanitize standard=hipaa fields=_raw,message
    index=app_logs | sanitize standard=pci  mask_style=full
    index=app_logs | sanitize standard=soc2 mask_style=label

Use a custom YAML configuration (stored in TA-logscrub/lookups/):
    index=app_logs | sanitize standard=none configuration=custom.yaml

COMMAND PARAMETERS
------------------
standard        gdpr | hipaa | pci | soc2 | all | none   (default: gdpr or admin setting)
configuration   <filename.yaml> | none                   (default: none)
fields          comma-separated field names               (default: _raw)
mask_style      partial | full | label | redacted | token (default: partial or admin setting)
min_confidence  0-100                                     (default: 0 or admin setting)
report_findings true | false                              (default: true or admin setting)

COMPLIANCE STANDARDS
--------------------
gdpr   : email, phone, SSN, passport, IP, MAC, credit card, IBAN, credentials
hipaa  : email, phone, SSN, passport, credit card, IP, credentials
pci    : credit card, IBAN, URL credentials, generic credentials
soc2   : JWT, bearer tokens, API keys (OpenAI, GitHub, AWS, Slack, Stripe, etc.)
all    : every available pattern
none   : no built-in patterns (use with configuration= for fully custom sets)

CONFIGURATION PAGE
------------------
Admins can set global defaults in Splunk Web:
    Apps > LogScrub > Configuration > Settings

Settings available:
- Default Compliance Standard
- Default Mask Style
- Minimum Confidence (%)
- Report Findings toggle
- Global Allowlist (comma-separated values that are never masked)

YAML CONFIGURATION FILES
------------------------
Place YAML files in TA-logscrub/lookups/ and reference by filename.
See lookups/sample_config.yaml for a documented example.

Supported keys: allowlist, disabled_patterns, min_confidence, mask_style,
                custom_patterns (name, category, regex, confidence)

SUPPORT
-------
GitHub: https://github.com/Matteo-Aquino/logscrub
Issues: https://github.com/Matteo-Aquino/logscrub/issues

LICENSE
-------
MIT License — see LICENSE
