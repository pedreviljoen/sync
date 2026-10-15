# Candidate for verifier-v18
Fingerprint: H5-resolvers-no-authz-read
Proposed verdict by hunter: confirmed (source-level, medium)

Claim: read resolvers in api/internal/graph/schema.resolvers.go with no authorization/ownership: LogisticsDoc (~:2786 takes client profileID/date, builds packing list via shipments.go fetchShipmentsAndProfiles ~:2597, logisticsdocs.go ~:32), ShipmentTransactions, TableDialog (~:2922 settlement dialogs), ShipmentDispatchDialog (~:2994 destination address), QualityReport (~:4245 party type only), DocumentNumber. Verify each resolver individually for any check (party type, ownership, ledger scoping), and which return genuinely sensitive cross-profile data to an authenticated Buyer/Seller; report confirmed only for the ones directly established, listing exactly which. Anonymous reach is covered by a separate candidate (opname bypass); assess authenticated-user impact only.

Use this exact fingerprint in your record.
