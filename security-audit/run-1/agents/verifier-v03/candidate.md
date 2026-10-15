# Candidate for verifier-v03
Fingerprint: thoth/grpc-identity-from-plaintext-metadata
Proposed verdict by hunter: needs_validation

backend/go/thoth/handlers.go: ServerGRPC (~:59) has no transport creds; serverUnaryInterceptor (~:181-217) takes user identity from plaintext metadata user-firebase-id: Robot*/Unauthed IDs yield robot users with no credential; other IDs verified by optional user-auth-token else falls back to Firebase UserByID with full claims (~:202-216). Cloud Run services deployed --allow-unauthenticated (backend/go/*/cloudbuild.yaml ~:45); clients dial :443 TLS. Verify the exact interceptor logic (is the fallback really reachable when the token fails? is there any other auth layer on the gRPC server, e.g. interceptors in each service main.go), and what deployment facts decide reachability. Decide confirmed/needs_validation/rejected.

Use this exact fingerprint in your record.
