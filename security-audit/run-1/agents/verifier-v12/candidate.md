# Candidate for verifier-v12
Fingerprint: api-graphql-introspection-cycle-amplification-unauth
Proposed verdict by hunter: needs_validation

backend/go/api/cmd/server/main.go: newServer (~:75-125) has no complexity/depth limit, always extension.Introspection (~:123); ListenAndServe (~:303) no timeouts/body limits. auth.go ~:404,422: unauthenticated user passes if client-chosen operation name is Signup/ValidateCurrentToken. Claim: anonymous caller can nest introspection (__schema{types{interfaces{possibleTypes...}}}) to amplify CPU/memory on the shared api. Verify gqlgen version behaviour (introspection of cyclic types is bounded by schema size? any default validation limits, query size limits, APQ), whether this is cheap-for-attacker/costly-for-service enough to be a finding, or just hardening. Reject if source/framework refutes meaningful amplification.

Use this exact fingerprint in your record.
