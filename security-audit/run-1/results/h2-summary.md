# hunter-h2 result (parent's condensed record)
Unit nilocloud routes: candidate (4 candidates)
1. nilocloud/subscriptions-auth-noop (proposed confirmed, high, source-level): handlers.go:18-19 -> middleware.go:69-71 r.WithContext result discarded (no auth) -> pubsub.go:20,27,35 / cloudbuild.go:24 -> cloud.go:63 handlePubSubMessage: nexport-start (64-75), consumer-unblock (125-156), mache-restore (157-173); nilocloud/cloudbuild.yaml:45 --allow-unauthenticated. Fix: verify Pub/Sub OIDC push token or require IAM invoker for push SA; remove no-op line.
2. nilocloud/gerrit-checks-unauthenticated (needs_validation) - duplicate root cause with h3 nilocloud-gerrit-checks-run-unauthenticated-enqueue -> CONSOLIDATE (use one fingerprint).
3. nilocloud/shared-robot-token-webhook-unblock (needs_validation): one NILO_ROBOT_TOKEN guards ?robotToken= webhooks (middleware.go:40-52) and /v1/events/unblock (middleware.go:55-66); no per-purpose separation; token in URL.
4. nilocloud/horus-no-operator-allowlist (needs_validation): slack.go:65 verifySlack ok (5-min window), horus.go:48-92 no user/channel allowlist; production deploy/migrate down; unblock action slack.go:112-127. Blocker: Slack app config.
Verified controls: Slack signature verification correct (slack-go v0.17.0, 5-min window, constant-time); /v1/mache empty-token fail-open not reachable over HTTP/1.1 (hardening).
Hardening: != compare; unbounded ReadAll; full body logging on parse errors (pubsub.go:28-30, cloudbuild.go:34, handlesentry.go:24-26); unblock service/consumer strings not validated (grafana/handlers.go:154-166, cloud.go:136-148); cloud.go:283 Sprintf table from static map (safe).
Uncovered: downstream gRPC Jobs handlers in administrator/ledger/trader/postman/harvester/librarian; gerrit verify-task execution.
