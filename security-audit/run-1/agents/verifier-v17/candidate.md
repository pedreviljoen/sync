# Candidate for verifier-v17
Fingerprint: H5-packhouse-any-seller
Proposed verdict by hunter: confirmed (source-level, medium)

api/internal/graph/schema.resolvers.go ~:1015, 1028, 1041, 1061 (PackhouseSetAllocation/ItemAllocations/ItemMixed/ClearInventories): auth.Checks(PartyTypes(Admin,Seller), PartyTypeForID(sellerID)) with ANY semantics; claim: first check admits every seller so binding to sellerID is dead; PartyTypeForID with no party types is always false (auth/checks.go ~:82). Verify exact semantics of auth.Checks, PartyTypes, PartyTypeForID (maybe Checks is ALL semantics or PartyTypeForID(sellerID) without types means something else), role permission checks (access.Has PackhouseAllocations) and downstream trader/ledger scoping.

Use this exact fingerprint in your record.
