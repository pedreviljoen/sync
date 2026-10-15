# Candidate for verifier-v08
Fingerprint: nilocloud/shared-robot-token-webhook-unblock
Proposed verdict by hunter: needs_validation

One NILO_ROBOT_TOKEN env guards /v1/webhooks/{sentry,grafana} (query-string ?robotToken=, middleware.go ~:40-52) and /v1/events/unblock (Authorization Bearer robotToken=..., ~:55-66), which publishes consumer-unblock jobs (permanently skip events) and is called from a browser (CORS obs.nile.ag). Claim: no per-purpose credential separation; token in URL. Verify code; decide whether this is a real boundary violation (who holds the webhook URL vs who should unblock) or intended/hardening. Be critical: same-principal authority is not a finding.

Use this exact fingerprint in your record.
