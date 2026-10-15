# Candidate for verifier-v21
Fingerprint: H5-admin-not-platform-scoped
Proposed verdict by hunter: needs_validation

api/internal/graph/schema.resolvers.go resolvers (Profile ~:2461, ProfileNew, Cart, Seller, Buyer, Sales, Operations, TableGroup, AccountingDoc ~:2728, BuyersProfile, Pricing) let any Admin party-type caller supply any profileID, with no comparison of target profile's AdminProfileID to caller's (auth_checks.go ~:78 AccountingDocAuthorized). Claim: an admin of one platform (Nile, Freshmark, NileInputs, Villa) can read other platforms' profiles/accounting. Verify: do the downstream services/queries scope by caller AdminProfileID (claims), is the X-Platform/checkPlatform check (auth.go ~:494-508) binding admin to one platform in a way that limits data, and are the four platforms separate orgs (docs/README) or all Nile staff (then design, not a boundary). Decide verdict.

Use this exact fingerprint in your record.
