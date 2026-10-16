# Nile security audit run-1
Repo nile-core @ 7ca31c0ddf (clean). Scope: backend (Go, Firebase fn, gerrit, nilocloud, relay) + client. Source-only. 4 hunters + 1 verifier. Secret values never reproduced.

## Confirmed
| # | Sev | Finding | Where | Fix |
|---|-----|---------|-------|-----|
| 1 | Critical | generatePdf: unauthenticated, open CORS, `?url=` unvalidated, robot token appended to URL then browsed (token exfil + SSRF, --no-sandbox) | backend/functions/firebase/functions/src/pdf.ts:10-85 | Require auth, allowlist host, short-lived token, escape `name` |
| 2 | Critical | Hardcoded static robot + PotatoesSA tokens = admin on any platform via X-Platform; committed in many files | backend/go/auth/auth.go:30-31,463-476; client/market/graphql.config.ts:13; client/ios/README.md:10; client/ios-native/Farmer App/Nile Farmer/apollo-ios-gen-schema.sh:12; backend/loadtests/locust_testing.py:10 | Rotate now; Secret Manager; OIDC (robot_oidc.go) only |
| 3 | Critical | SetUser form: customer sets own profileID/roles/password, resets any Firebase UID | api/internal/graph/schema.resolvers.go:1146; customers/user.go:166; administrator/internal/ops/users/update.go:66-85 | Non-admin: bind id to caller, ignore profileID/roles |
| 4 | High | "unauthenticated" token passes when client-chosen operation NAME is public; resolvers with no authz run (VolumePriceAdjustment, UpdateSellerCutoff, UploadPop, SetShipmentItemStatus, SetInventoryStatus, EmailPriceList, ChatNotify, LogisticsDoc...) | auth/auth.go:404-422,466; schema.resolvers.go:1130,1518,1563,1803,1871,1941,1955,2786 | Gate on root fields, default-deny, per-resolver checks |
| 5 | High | SwitchUserProfile/relinkProfile links caller to any profile id | schema.resolvers.go:1768; api/internal/graph/customers.go:303 | Require pid == LinkedProfileID |
| 6 | High | Shipment mutations role-only, no IsParty check (cross-customer write by KSUID) | auth_checks.go:127-168; schema.resolvers.go:1595,1733 | Call ShipmentAuthorized first |
| 7 | High | Packhouse mutations: PartyTypeForID(SellerID) has no party types, never passes; any seller acts on any seller | schema.resolvers.go:1015-1061 | PartyTypeForID(id, Seller) |
| 8 | High | Read IDORs: Dashboards (raw profileID), QualityReport, ShipmentTransactions | schema.resolvers.go:4359,4245,2880; quality.go:508 | ShipmentAuthorized / profile check |
| 9 | High | Stored XSS sink: form.description rendered raw; descriptions embed customer-set company names; no CSP | client/market/src/components/Form.tsx:122; api/internal/shipments/inbound_add_product.go:56 | Render as text/DOMPurify; escape server-side; add CSP |
| 10 | High | PotatoesSA restriction checks only first root field; others run as Nile admin; fragment panic | auth/auth.go:323-331,407 | Require exactly one root field |
| 11 | High | nilocloud /v1/subscriptions/* auth is a no-op (WithContext result discarded) on --allow-unauthenticated service: forged Pub/Sub jobs (nexport export/import, consumer-unblock, mache-restore); /v1/gerrit/checks* open (logs, CI trigger) | nilocloud/internal/middleware.go:77; handlers.go:19-32; cloudbuild.yaml:45 | Verify Pub/Sub OIDC; drop allow-unauthenticated |
| 12 | Medium | gerrit-webhook public, no HMAC despite comment; forged change-merged deploys chosen SHA to staging; unvalidated ref to git fetch | gerrit/terraform/functions.tf:63-70; functions/webhook/webhook.go:62-340; agent/actions/git/checkout.go:54-60 | HMAC/secret, validate SHA/ref |
| 13 | Medium | Remove/Set mutations: role-only gates, client-supplied owner ids (partly verified) | api/internal/graph/remove.go:562; set.go:266 | Owner == caller in handlers |
| 14 | Low-Med | Robot token in URLs, logged/in error metadata; in SPA query string; Sentry sends location.href unscrubbed | harvester/internal/ops/download_actions.go:40,51,71; client/market/src/utils/hasRobotToken.ts:2; sentry.ts:138; useLogSentryWithContext.tsx:11 | Header-only, scrub |
| 15 | Low-Med | iOS: no nav host allowlist; startDownload bridge no origin check, filename traversal | client/ios/Nile/Nile/NileWebView.swift:428,596-704 | Allowlist, lastPathComponent |
| 16 | Low | No CSP in market hosting | client/market/firebase.json | Add CSP |
| 17 | Low | Hygiene: Chromium NoSandbox + root containers (harvester/browser.go:56); relay printJobs readable by any signed-in user (backend/relay/terraform/firestore.tf:35); introspection on (api/cmd/server/main.go:122); iOS-native keychain/allowBackup items unverified | | |

## needs_validation
- N1 (critical if true): internal gRPC services (ledger, trader, administrator, postman, harvester, librarian) deployed `--allow-unauthenticated`, no `--ingress` in repo; thoth/handlers.go:170-196 trusts `user-fid` metadata (Robot). Check live Cloud Run ingress/IAM.
- Is the committed robot token the live prod value / rotated? Does downstream gRPC reject FIDUnauthed (affects #4 writes)?
- Who holds the PotatoesSA token (#10); who can set form.description / company name unescaped (#9).
- Gerrit remote transport and whether agent can fetch unmerged SHAs (#12); `/v1/mache` ROBOT_TOKEN env set?
- Prod Firestore/Storage rules (not in repo); firebase.json `!/.well-known/**` header rule.

## Rejected / not exploitable
Host-pin SSRF in harvester (URLs server-built); robot_oidc email_verified; mache empty-token bypass (impractical).

## Not covered
Prod Storage/Firestore rules, GraphQL depth/complexity limits, websocket auth path, profile-0 "match all" semantics, Android TWA assetlinks. No SQL injection found.

## Deliverable gaps
findings.json not produced (schema validator not run); REPORT.md only.
