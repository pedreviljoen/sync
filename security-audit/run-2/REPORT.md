# Security audit report — nile/core client/ (run-2)

## 1. Run scope and limits
- **Profile:** `quick`, scoped to `client/` (market web app, ios wrapper, ios-native Farmer app, android TWAs and native stub, website, freshtrader-software). Backend findings from run-1 were used only to judge what the server enforces. **Partial pass, not a clean bill of health.**
- **Source ref:** none (Sapling checkout, not a git repository).
- **Budget:** none set. Agents: 4 reconnaissance + 7 hunters + 1 coverage critic + 7 candidate verifiers = 19.
- **Execution policy:** source-only; nothing was built or run, no network, no deployed services. "Confirmed" means a source-level observation, not a runtime result. Same deviations as run-1 (skill text read by path; agent write isolation by instruction; quick-profile merged verification). Mechanical edits by the parent: path normalisation and trace-step labelling.
- **Duplicates consolidated:** the CI Sentry-token echo was reported by two hunters and the robot-token copies by two hunters; each is one record.
- **Deferred coverage:** 10 units (section 7).

## 2. Posture summary
The clients are thin: the real authorization boundary is the backend (run-1). The one confirmed client-side issue is a **cross-tenant stored XSS** whose root cause spans both tiers (unescaped names in server-built form descriptions rendered as HTML by the market app). The rest are leads that depend on deployment facts: a committed shared token (same root cause as the backend finding), a CI log leak, a webview with no navigation allowlist, an unvalidated file-URL iframe, and a committed Slack webhook. The iOS Farmer app, the Android wrappers and the websites showed little attack surface; most recon leads were refuted or reduced to hardening after tracing.

## 3. Confirmed findings (1) — source-level

| Severity | Finding | Boundary | Observed result (source-level) |
|---|---|---|---|
| high | Stored XSS: buyer/seller profile name rendered unescaped via dangerouslySetInnerHTML in server-driven form description (hits admin session) | `backend/go/api/internal/graph/schema.resolvers.go:1146` | profile owners may set Name, no escaping or sanitizing exists on the path, and the sink uses dangerouslySetInnerHTML for the Normal-variant description. Nothing was execu |

### 3.1 [HIGH] Stored XSS: buyer/seller profile name rendered unescaped via dangerouslySetInnerHTML in server-driven form description (hits admin session)

- **Fingerprint:** `c1-market-form-description-stored-xss-profile-name`
- **Source location (entry):** `backend/go/api/internal/graph/schema.resolvers.go:1146` (path continues into `client/market/src/components/Form.tsx:122`)
- **Lower-trust principal:** A registered buyer or seller changes their own profile Name to a payload with no double quotes. An admin later opens the allocation form for that profile's shipment, and the payload executes in the admin's session.
- **Bounded reproduction (not executed):** `<img src=x onerror=alert(document.domain)>`
- **Conditions:** Attacker holds an authenticated buyer or seller profile-owner account on their own profile. A platform admin must open the Add Outbound product or Add Inbound product form for a shipment linked to the attacker's profile. This is a routine admin workflow. A strict deployed CSP or equivalent response headers are not visible in source. None was found in the repo (grep for Content-Security-Policy and DOMPurify found nothing under client/market). If one exists it could blunt inline-handler payloads.
- **Result and impact:** A buyer or seller profile owner can set their profile Name (FormTypeSetProfileCompany, field profileName) to an HTML payload. The only server-side name checks are a double-quote ban and a 100-character cap. Backend form builders interpolate that name into form.Description with fmt.Sprintf and no escaping. For example, OutboundAddProduct uses buyer.Name and InboundAddProduct uses seller.Name. Form.tsx in the market client renders the description of any non-callout form with dangerouslySetInnerHTML and no sanitizer. The Description helper does not escape, and the form defaults to the Normal variant. When a platform admin opens the Add Outbound product or Add Inbound product form for a shipment tied to the attacker's profile, the attacker's script runs in the admin's browser session on the market origin.
- **Priority rationale:** likelihood medium (Any registered buyer or seller can plant the payload. It fires only when an admin opens the specific form for that profile's shipment, and a deployed CSP could mitigate it.) / impact high (Script execution in a platform admin session on the market origin crosses the tenant boundary (buyer or seller to admin). It permits admin-level GraphQL actions as that admin.). Confidence medium: Every source hop was read and the sink is unsanitized. The admin-only audience of the carrier forms and the absence of a CSP are inferred from source, since deployment headers are not visible. No runtime execution.
- **Smallest fix:** Render form.description as text, or sanitize it with a vetted HTML sanitizer such as DOMPurify. On the backend, html.EscapeString every user-controlled value interpolated into descriptions (profile name, email, recipient). Optionally reject '<' and '>' in profile names and add a CSP.

## 4. NEEDS VALIDATION (5) — leads, no severity

Full detail in `NEEDS-VALIDATION.md`. All checks are owner-observed or local dummy-data tests; none require probing live systems.

| Lead | Repository trace | Exact blocker | Safe next step |
|---|---|---|---|
| Market FileViewer renders unvalidated server-supplied file URL as iframe src (possible javascript:/data:  (`c3-fileviewer-iframe-unvalidated-src`) | `backend/go/api/internal/shipments/dispatch.go:177` | Whether the counterparty viewer can see the attacker-written field (per-role visibility and authorization of the shipment detail builders) was not fully traced  | Owner to inspect response headers of the deployed market origin for Content-Security-Policy (script-src, frame-src) in a test or staging environment and confirm which rol |
| Xcode Cloud post-build script echoes SENTRY_AUTH_TOKEN value to the build log (`c4-ios-ci-sentry-token-echoed-to-build-log`) | `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:1` | Whether Xcode Cloud masks secret environment variables in build logs is platform behaviour that cannot be established from source. | Owner-observed, no live probe: in App Store Connect, open the Xcode Cloud logs of a recent build of the Nile and NileStaging workflows and check whether the post-xcodebui |
| iOS wrapper WebView lets any non-blocklisted third-party page load in-app with the startDownload bridge a (`c4-ios-webview-thirdparty-page-reaches-bridge-and-token`) | `client/market/src/screens/Explore/Post.tsx:127` | Whether any principal below Nile admin staff (for example sellers, buyers or other tenants) can author or influence the URL of an Explore post or action link th | Owner-observed: review the backend authoring path and roles for Explore posts and action URLs (who can set post.url), and the production Explore data for non-Nile, non-so |
| Slack incoming-webhook URL hardcoded in client/website package.json postdeploy script (`c6-website-slack-webhook-committed`) | `client/website/firebase.json:3` | Whether the webhook is still active, not revoked, and which Slack channel it posts to is a Slack workspace fact not visible in source. | Owner check, with no live probe: in the Slack workspace admin (Apps > Incoming Webhooks or the owning app's Incoming Webhooks page), see whether a webhook matching the co |
| Shared Nile robot token literal committed in three client dev-tooling files (`c7-robot-token-client-copies`) | `client/market/graphql.config.ts:13` | Source cannot show whether the committed literal is the live production/staging secret, already rotated, or a dev-only value (deployment fact). | Owner-observed check, no live probe: compare the committed value with the current token in Secret Manager or deploy configuration (compare hashes, not printed values) and |

## 5. Rejected (1)
- `c7-mock-prod-storage-capability-urls`: tokenised production Storage URLs in mocks/stories. The files are imported only by tests and Storybook (not bundled), and the objects are ordinary marketplace product photos. Hygiene note: replace with placeholders.

Recon leads refuted after tracing (not findings): `?robotToken=` giving server privilege (the UI only shows an Admin-shaped state; the server requires the secret); `appToken` plant/login-CSRF; PDF URL builder origin escape (`method-download-pdf.ts` always stays same-origin); iOS universal-link loading arbitrary hosts (host re-checked in `NileWebView.updateUIView`); `startDownload` filename traversal (stays inside the app sandbox); `/form` query params (prefill only, no auto-submit); chat/upload XSS (rendered as text; uploads use random UUID paths on a different origin); Keychain token reuse and client-chosen `X-Platform` in ios-native (backend rejects a mismatch).

## 6. Hardening notes and positive patterns
**Hardening:**
- market hosting: no CSP, HSTS or Permissions-Policy; `firebase.json` and the Dockerfile disagree on headers; nginx stage runs as root with a floating `nginx:1.25-alpine` tag and nginx `add_header` inheritance drops server-level headers in the container image.
- `isNileUrl` is an unanchored substring regex; `window.open(post.url)` without scheme check or `noopener`; the `/debug` route is registered unconditionally (menu link gated only).
- `get-pdf-url.ts` does not URL-encode `name`; `hasRobotToken` is a substring match so any visitor reaches the Admin-shaped UI via `?robotToken=x` (UI only); Sentry receives full `window.location.href` (may contain `robotToken` in the headless PDF render).
- `@urql/devtools` exchange is in the production exchange chain without an explicit env gate.
- ios (wrapper): `deviceToken` interpolated into `evaluateJavaScript` and posted with `targetOrigin '*'`; FCM token printed; Sentry breadcrumbs include full URLs; `aps-environment` hard-coded `development`; `supplyCategory` registered with the checkout identifier (functional bug); dSYM upload destinations look swapped; `curl https://sentry.io/get-cli/ | bash` unpinned; checked-in `upload-symbols` binary with no checksum.
- ios-native: Keychain item not cleared on environment switch and no explicit accessibility class; `X-Platform` read from two different UserDefaults keys; offline queue, caches and staged images have no file protection and are backed up and not wiped on sign-out; Sentry `sendDefaultPii=true` with 100% error session replay; email and CLIENT_ID printed to console.
- android: TWA manifests have empty `fingerprints`/`additionalTrustedOrigins` and the generated manifests are not committed (Digital Asset Links is server-side and unverifiable here); freshmark `fullScopeUrl` covers the whole origin; build tools on EOL node 16 and floating bubblewrap version; native stub has `allowBackup=true`, minify off, a test label.
- website: `.yarnrc.yml` enables install scripts, no package age gate, any git dependency; `define:vars` serialises all of `import.meta.env` (unused variable today); no security headers on hosting; freshtrader README claims headers its `firebase.json` does not set.
- Firebase web API keys and Sentry DSNs are committed but public by design; API-key restrictions and Firestore/Storage rules are not in the repo and cannot be assessed.

**Positive patterns:** logout clears localStorage, IndexedDB, outbox and sessionStorage; Firebase ID tokens are the only runtime bearer in the market app; service-worker notification URLs are re-rooted onto the app origin; chat and most data render as React text; ios-native stores the token in the Keychain and clears it on normal sign-out, uses a correct Apple sign-in nonce, and uses client-generated UUID storage names; the iOS wrapper pins universal-link hosts in `updateUIView` and builds push navigation from fixed category identifiers; ATS defaults with no exceptions or trust-all delegates.

## 7. Coverage summary (from the ledger)
- Units: 17 total — covered 1, candidate 6, blocked 0, deferred 10.
- Final critic: ran once (quick profile); 10 missing units recorded as `deferred` (reason `quick_profile_final_critic`). No clean-coverage claim.
- **Deferred (not reviewed):**
  - iOS wrapper token/bridge injection into webview localStorage and push token sync, native auth (`client/ios/Nile/Nile/NileWebView.swift`)
  - ios-native Firebase image upload and offline image staging, Dispatch/Count screens consuming server strings (`client/ios-native/Farmer App/Nile Farmer/Shared/FirebaseImageUpload.swift`)
  - ios-native SyncEngine/OfflineQueue replay, cached data, per-user isolation on logout/profile/environment switch (`client/ios-native/Farmer App/Nile Farmer/Shared/SyncEngine.swift`)
  - market form field rendering and dynamic server-driven field/option/label values (`client/market/src/components/DynamicInputField/fieldRenderers.tsx`)
  - market custom-scheme/query and WhatsApp entry handlers, route/return-path redirects (open redirect) (`client/market/src/hooks/useHandleCustomSchemeAndQuery.ts`)
  - market Firestore chat client paths/Debug screen/auth bootstrap and role/profile gating from client claims (`client/market/src/screens/Chat/useChat.ts`)
  - market per-screen rendering of other-user-controlled strings (notes, names, descriptions, addresses, chat, notifications, quotes, orders, customers) (`client/market/src/screens/Notifications`)
  - market service worker/PWA caching, notification URL handling, web manifests (`client/market/src/serviceWorker.ts`)
  - market offline mutation outbox, IndexedDB store and queue replay across auth/profile switch (`client/market/src/services/outbox.ts`)
  - market file download/export and URL-to-filename helpers, CSV/JSON export (formula injection), PDF viewers (`client/market/src/utils/download-file.ts`)
- Not assessable from source: Firestore and Storage security rules, Firebase API-key restrictions, assetlinks/AASA files, Xcode Cloud log masking, live validity of every committed credential.

## 8. Suggested priorities
1. Fix the XSS at both tiers: render `form.description` as text (or sanitise) and HTML-escape user values in `form.Description` callers; add a CSP to the market hosting config.
2. Validate and fix the CI log leak (`ci_post_xcodebuild.sh:11`), rotate the Sentry token if it appears in a log.
3. Owner-verify and rotate the committed shared robot token together with the backend copies; revoke or move the website Slack webhook.
4. Restrict the iOS webview to first-party hosts and scope the `startDownload` bridge and token injection to them; validate file/image URL schemes where values are stored (backend) and rendered (`FileViewer`).
5. Re-run at `standard` profile over the 10 deferred units (form field renderers, offline outbox/service worker, ios-native sync, wrapper `appToken` injection).
