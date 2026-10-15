# Candidate for verifier-v19
Fingerprint: H5-resolvers-no-authz-write
Proposed verdict by hunter: confirmed (source-level, high)

Claim: mutations in api/internal/graph/schema.resolvers.go with no caller binding or role check: VolumePriceAdjustment (~:1518, trader.VolumeAdjustmentInput; trader/internal/ops/inputs.go ~:88), UpdateSellerCutoff (graph/seller.go ~:46), UploadPop (~:1130), SetShipmentItemStatus (~:1941), SetInventoryStatus, ReleaseQualityFlag, ChatNotify, EnqueueShipmentLabels, UpdateClaims (~:1932). Verify each individually: any auth.Checks, access.Has, ownership check in resolver helpers or downstream services; concrete effect when called by an authenticated Buyer on another seller's/profile's data. Report confirmed only for those directly established (list exactly which and demote/split the rest in the description). Note anonymous reach is a separate candidate.

Use this exact fingerprint in your record.
