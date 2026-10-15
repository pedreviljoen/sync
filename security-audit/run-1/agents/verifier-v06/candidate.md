# Candidate for verifier-v06
Fingerprint: nilocloud/subscriptions-auth-noop
Proposed verdict by hunter: confirmed (source-level)

backend/go/nilocloud/internal/middleware.go ~:69-71: for /v1/subscriptions/* branch calls r.WithContext(...) and discards result; handlers pubSubHandler (pubsub.go ~:16-43) and cloudBuildHandler (cloudbuild.go ~:21-44) verify no OIDC/secret; handlePubSubMessage (cloud.go ~:63) dispatches nexport-start, consumer-unblock, mache-restore from attacker-controlled message data; nilocloud/cloudbuild.yaml ~:45 deploys --allow-unauthenticated. Verify every claim: is the discarded result truly the only auth on that prefix (check ServeHTTP wrappers, handlers.go registration, cmd/server/main.go middleware, any Pub/Sub JWT check elsewhere), whether job types do what's claimed and what downstream gRPC Jobs services require (see thoth auth), and whether Cloud Run IAM could still gate it (deployment). Hunter severity high, confidence medium.

Use this exact fingerprint in your record.
