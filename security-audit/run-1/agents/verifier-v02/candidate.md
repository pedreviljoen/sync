# Candidate for verifier-v02
Fingerprint: auth/potatoessa-scope-first-field-only
Proposed verdict by hunter: confirmed (source-level)

PotatoesSA token user (backend/go/auth/auth.go ~:198-206 UsrPotatoesSA, Admin party type, Nile admin id, no roles) is meant to be limited to exportData. Gate: auth.go ~:407 !isExportDataQuery(op.Operation); isExportDataQuery (~:323-332) returns at first top-level field with an argument and never checks other selections/fragments. Claim: a document with exportData(type: PotatoesSA) first plus other top-level fields passes and all execute as PotatoesSA user; resolvers gated only by PartyTypes(Admin) (e.g. api/internal/graph/auth_checks.go:28) admit it. Verify exactly how the loop behaves (does it return true only when field name == exportData? what about fields without args?), what gqlgen executes, and which resolvers actually admit this user (concrete reach). Token itself is hardcoded (auth.go:31).

Use this exact fingerprint in your record.
