# Candidate for verifier-v07
Fingerprint: c6-website-slack-webhook-committed
Proposed verdict by hunter: needs_validation

Claim: client/website/package.json line ~13 script 'slack' contains a hardcoded full Slack incoming-webhook URL (hooks.slack.com/services/T.../B.../<secret>) executed as Firebase postdeploy hook (client/website/firebase.json:3); anyone with repo read access can post arbitrary messages as the webhook's bot into an internal Slack channel (spoofed deploy notices/phishing); webhooks cannot read channel data. Verify the occurrence and line numbers (never print the webhook URL or its path token; refer to it as the committed webhook), confirm it is a real-format webhook (not a placeholder/env reference), whether other client files reference it, and the exact script behaviour. Liveness and channel are deployment facts: needs_validation. Calibrate impact honestly (low-moderate: message spoofing only).

Use this exact fingerprint in your record.
