# Combined security audit — nile/core (backend/ + client/)

Two quick-profile runs, merged. Detail lives in the per-run directories: `../run-1` (backend/) and `../run-2` (client/). Each has `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `findings.json` and `coverage-ledger.json`. `findings.json` in this directory is the validated union of both (28 records, no duplicate fingerprints).

## 1. Scope and limits (read first)
- **Both runs are partial passes** (quick profile, source-only). Between them 24 coverage units were deferred (14 backend, 10 client). Neither run executed any code, contacted any deployed service, or could see Firestore/Storage rules, Cloud Run ingress/IAM, Slack/Gerrit/Xcode Cloud configuration or git history (`core` is a Sapling checkout with no commit ref).
- **"Confirmed" means a source-level observation** (a check absent on every traced path) that an independent verifier agent re-read; it is not a runtime reproduction. "Needs validation" means a specific, source-grounded hypothesis blocked on a named deployment fact; it has no severity and is not a confirmed vulnerability.
- Agents: backend 33 + client 19 = 52. No budget was set.

## 2. Totals
| | confirmed | needs validation | rejected |
|---|---|---|---|
| backend (run-1) | 9 (3 high, 6 medium) | 11 | 1 |
| client (run-2) | 1 (1 high) | 5 | 1 |
| **combined** | **10 (4 high, 6 medium)** | **16** | **2** |

## 3. Confirmed findings (10), by priority
| Severity | Run | Finding | Entry (file:line) |
|---|---|---|---|
| **high** | backend | Any authenticated user can set roles and password on a user account via the SetUser form (self-service role escalat (`H5-setuser-self-role-escalation`) | `backend/go/api/internal/graph/schema.resolvers.go:1146` |
| **high** | backend | Unauthenticated GraphQL access to any operation by naming it Signup/SignUp/ValidateCurrentToken (`H5-unauth-opname-bypass`) | `backend/go/api/cmd/server/main.go:120` |
| **high** | client | Stored XSS: buyer/seller profile name rendered unescaped via dangerouslySetInnerHTML in server-driven form descript (`-market-form-description-stored-xss-profile-name`) | `backend/go/api/internal/graph/schema.resolvers.go:1146` |
| **high** | backend | nilocloud /v1/subscriptions/* routes have no effective authentication (discarded r.WithContext result); unauthentic (`nilocloud/subscriptions-auth-noop`) | `backend/go/nilocloud/internal/handlers.go:18` |
| **medium** | backend | editShipment/editShipmentItem authorize by party type only, with no check that the caller's profile is a party to t (`H5-editshipment-no-ownership`) | `backend/go/api/internal/graph/schema.resolvers.go:1595` |
| **medium** | backend | Packhouse allocation mutations accept any seller's sellerID from any Seller/Admin user (ID binding is dead code) (`H5-packhouse-any-seller`) | `backend/go/api/internal/graph/schema.resolvers.go:1015` |
| **medium** | backend | Read resolvers LogisticsDoc, TableDialog, ShipmentDispatchDialog (and seller-side QualityReport) lack any ownership (`H5-resolvers-no-authz-read`) | `backend/go/api/internal/graph/schema.resolvers.go:2786` |
| **medium** | backend | Multiple GraphQL mutations perform cross-tenant writes with no caller role or ownership check (`H5-resolvers-no-authz-write`) | `backend/go/api/internal/graph/schema.resolvers.go:1518` |
| **medium** | backend | PotatoesSA export-only token user can run any Admin-party-type query because the scope gate only inspects the first (`auth/potatoessa-scope-first-field-only`) | `backend/go/auth/auth.go:373` |
| **medium** | backend | Gerrit webhook Cloud Function is public and accepts forged events without any authentication, enabling attacker-cho (`gerrit-webhook-unauthenticated-event-forgery`) | `backend/go/gerrit/functions/webhook/webhook.go:62` |

## 4. Themes across both runs (the merged feedback)

### A. The backend does not enforce authorization or input hygiene that the clients silently rely on
- **Anonymous reach:** the API admits unauthenticated callers by *operation name* (`auth.go:404`, finding `H5-unauth-opname-bypass`), and many resolvers have no checks of their own (`H5-resolvers-no-authz-read/write`, `H5-editshipment-no-ownership`, `H5-packhouse-any-seller`). The client's role-gating and "robot mode" (`?robotToken=`) are UI-only and cannot compensate; run-2 confirmed the market app and both iOS apps simply send whatever the user's token and `X-Platform` say and let the server decide.
- **Self-service escalation:** `H5-setuser-self-role-escalation` lets any logged-in user grant themselves roles. Together with the above, an attacker's ceiling on the API is decided entirely by resolver-level checks.
- **Unvalidated user strings are stored and later trusted by another tier.** This is the root of both client-tier issues: the server builds form descriptions from user-editable profile names with no escaping while the market app renders them with `dangerouslySetInnerHTML` (**`c1-market-form-description-stored-xss-profile-name`, high, confirmed**: buyer/seller → admin session); and `field.ParseValidURLs` accepts any string that `url.Parse` accepts (including `javascript:`) which the market `FileViewer` later renders as an unsandboxed iframe `src` (`c3-fileviewer-iframe-unvalidated-src`, needs validation). **Fix both at the backend input/output boundary** (escape on output; allow-list URL schemes/hosts on input) and harden the client sinks as defence in depth. Neither client nor server fix alone closes the chain, and no CSP is configured on market hosting.

### B. One shared credential, many copies
The robot token accepted by the public GraphQL path is committed in: `backend/go/auth/auth.go:30`, `backend/functions/.../pdf.ts`, `backend/loadtests/locust_testing.py`, and (client run) `client/market/graphql.config.ts`, `client/ios/README.md`, `client/ios-native/.../apollo-ios-gen-schema.sh` (all byte-identical; none are in a shipped bundle). The `generatePdf` function additionally appends it to a caller-chosen URL, and the market app forwards `window.location.href` (which may carry `?robotToken=`) to the PDF service and to Sentry. This is **one root cause** (`auth/hardcoded-shared-robot-token`, plus `c7-robot-token-client-copies` as extra locations): rotate once, remove every copy, move callers to the existing Google OIDC robot path. Whether the literal is live is a deployment fact (needs validation), but the acceptance path in source is unconditional.

### C. Unauthenticated operations and CI/secret hygiene
- Unauthenticated ops/CI entry points: nilocloud `/v1/subscriptions/*` (confirmed, high — middleware result discarded), the public Gerrit webhook (confirmed, medium), nilocloud `/v1/gerrit/checks*`, Horus without an operator allowlist, internal gRPC identity from plaintext metadata (needs validation; all Cloud Run services are deployed `--allow-unauthenticated`).
- Secrets leaking through tooling: Xcode Cloud script echoes the Sentry auth token into the build log (`c4-ios-ci-sentry-token-echoed-to-build-log`, shell semantics verified; platform masking unknown), a Slack incoming-webhook URL is committed in the website `package.json`, committed Firebase functions env files.

### D. Client-only items (all hinge on deployment facts)
iOS wrapper WebView has no navigation allowlist and attaches the `startDownload` bridge and push-token injection to any loaded page (`c4-ios-webview-thirdparty-page-reaches-bridge-and-token`; practical risk depends on who can author in-app links such as Explore posts — verify). Android TWA trust (assetlinks, keystore) lives outside the repo. Several recon leads were refuted after tracing (listed in `../run-2/REPORT.md` §5), notably universal-link host handling, download filename traversal, `appToken` planting, and ios-native Keychain/X-Platform concerns.

## 5. Needs validation (16) — one owner checklist
These cannot be settled from source. Each has a safe, non-live check in `../run-1/NEEDS-VALIDATION.md` or `../run-2/NEEDS-VALIDATION.md`. Grouped by who can answer:

**GCP / Cloud Run owner**
- Internal gRPC services trust caller identity from unauthenticated metadata; reachability depends on Cloud Run exposure (`thoth/grpc-identity-from-plaintext-metadata`)
- generatePdf Cloud Function appends the static robot token to a caller-chosen URL and loads it in headless Chromium (`s/src/pdf.ts-generatePdf-url-ssrf-token-exfil`)
- nilocloud Gerrit Checks endpoints (/v1/gerrit/checks, /checks/log, /checks/run) have no authentication (`nilocloud/gerrit-checks-unauthenticated`)
- Unauthenticated GraphQL introspection with no depth/complexity limit may allow resource-exhaustion amplification on the shared api (`phql-introspection-cycle-amplification-unauth`)
- Profile logo URL fetched server-side without destination restriction when rendering document PDFs (blind SSRF) (`H5-logo-ssrf`)
- Zip-slip in harvester Potatoes SA archive extraction (no containment of entry names) (`harvester-potatoessa-unzip-path-traversal`)
- For all of these: ingress setting, `allUsers` invoker bindings, VPC/egress, container user for each Cloud Run service and function.

**Secrets / rotation owner**
- Hardcoded shared robot bearer token accepted by the public GraphQL auth middleware yields platform-admin robot identity (`auth/hardcoded-shared-robot-token`)
- Shared Nile robot token literal committed in three client dev-tooling files (`c7-robot-token-client-copies`)
- Firebase functions env files and runtimeconfig hold NILE_API_KEY values in the source tree (`se/functions/functions-env-committed-api-keys`)
- Slack incoming-webhook URL hardcoded in client/website package.json postdeploy script (`c6-website-slack-webhook-committed`)
- Xcode Cloud post-build script echoes SENTRY_AUTH_TOKEN value to the build log (`c4-ios-ci-sentry-token-echoed-to-build-log`)
- Check whether each committed value is live, rotate, then remove from source and history. Never paste values into tickets.

**Product / platform owner**
- Admin-party GraphQL resolvers do not bind the target profile to the caller's platform (AdminProfileID) (`H5-admin-not-platform-scoped`)
- Horus /horus Slack command and unblock action have no operator allowlist or approval step beyond the Slack signature (`nilocloud/horus-no-operator-allowlist`)
- nilocloud: one NILO_ROBOT_TOKEN gates both inbound Sentry/Grafana webhooks (token in URL query) and the browser-callable consumer- (`nilocloud/shared-robot-token-webhook-unblock`)
- Market FileViewer renders unvalidated server-supplied file URL as iframe src (possible javascript:/data: execution in market origi (`c3-fileviewer-iframe-unvalidated-src`)
- iOS wrapper WebView lets any non-blocklisted third-party page load in-app with the startDownload bridge and deviceToken injection  (`view-thirdparty-page-reaches-bridge-and-token`)
- Decisions needed: are the four platform admins separate organisations; who may use `/horus`; who can author Explore/action URLs; is a CSP deployed on market hosting; are Firestore/Storage rules restrictive (not in the repo; unreviewed).

## 6. Rejected (2)
- `H5-signup-admin-selfassign` (backend): production `checkUser` blocks self-registered Nile admins; staging/dev lack the check (hardening).
- `c7-mock-prod-storage-capability-urls` (client): test/Storybook fixtures only, ordinary product photos.

## 7. Unified priorities
1. **Close the authorization gaps:** operation-name gate, default-deny resolver authorization, SetUser role binding, EditShipment/packhouse ownership (backend).
2. **Fix the XSS chain** at the backend (escape on output, URL allow-list on input) and in the market client (no `dangerouslySetInnerHTML` for user-derived text, sandbox/validate iframe sources); add a CSP.
3. **Authenticate the ops surface:** Pub/Sub OIDC on nilocloud subscriptions, Gerrit webhook secret/IAM, restrict Cloud Run ingress for internal gRPC services.
4. **Rotate the shared robot token and committed secrets** (robot token in 6 locations, Slack webhook, functions env keys, Sentry token if logged); remove literals; fix the Xcode Cloud echo.
5. **Owner-verify** the deployment checklist in §5 and report back so the needs-validation leads can be confirmed or closed.
6. **Re-run at `standard` profile** over the 24 deferred units, especially service-side tenant scoping (ledger/trader/administrator), per-FormType handlers, and the client's offline/sync paths.

## 8. Files
- `findings.json` — validated union (28 records).
- `../run-1/`, `../run-2/` — per-run reports, detail files, ledgers, hunter and verifier verdicts.
