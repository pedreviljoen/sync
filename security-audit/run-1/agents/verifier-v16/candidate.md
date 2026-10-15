# Candidate for verifier-v16
Fingerprint: H5-editshipment-no-ownership
Proposed verdict by hunter: confirmed (source-level, high)

api/internal/graph/schema.resolvers.go EditShipment (~:1595) and EditShipmentItem (~:1746) authorize via EditShipmentAuthorised (auth_checks.go ~:127-169) which checks party type only; the sibling EditShipmentAuthorized (~:182, with ShipmentAuthorized/IsParty) is used only in a read query (~:3670). editShipment (shipment_edits.go ~:87) applies edits via Ledger.Set. Claim: any Seller/Buyer can edit another profile's shipment by ID. Verify: read the mutation resolvers fully, fetchLedgerShipment (shipments.go ~:59), any ownership check inside editShipment/intent handlers or the ledger service (ops checking user vs party), and how an attacker obtains a shipment ID. Decide verdict/severity strictly from evidence.

Use this exact fingerprint in your record.
