# logscrub.conf.spec — Spec file for logscrub.conf
#
# This file documents the structure of logscrub.conf.
# Place logscrub.conf in default/ or local/ within the TA-logscrub app directory.

[<compliance_standard>]

description = <string>
    * Human-readable description of this compliance standard.
    * Default: empty

patterns = <comma-separated pattern names | *>
    * Pattern names to enable when this standard is selected.
    * Use * to enable all available patterns.
    * Leave empty to enable no patterns.
    * Available names: email, phone, ssn, us_passport, jwt, bearer_token,
      openai_key, github_token, aws_access_key, generic_credential,
      slack_token, stripe_key, google_api_key, anthropic_key, sendgrid_key,
      credit_card, iban, url_credentials, ipv4, mac_address
    * Default: * (all patterns)

[default]

standard = <string>
    * Default compliance standard applied when standard= is not specified.
    * Default: gdpr

mask_style = <partial | full | label | redacted | token>
    * Default masking style when mask_style= is not specified in the command.
    * Default: partial
