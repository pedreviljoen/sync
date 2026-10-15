# Needs validation (unresolved leads — no severity)

These are source-grounded hypotheses blocked on facts outside the repository. They are not confirmed vulnerabilities. All checks are owner-observed configuration reviews or local dummy-data tests; **do not send live probes**.

## Market FileViewer renders unvalidated server-supplied file URL as iframe src (possible javascript:/data: execution in market origin)

**Fingerprint:** `c3-fileviewer-iframe-unvalidated-src`  
**Claimed root cause:** No scheme or host allow-list (for example firebasestorage.googleapis.com or gs://) is applied to file/image URL strings either when accepted by the backend (ParseValidURLs only checks that url.Parse succeeds) or when rendered by the client (FileViewer uses the value directly as iframe/img src with no sandbox). The ref(storage, src) failure path only shows an error toast and does not prevent the click-to-render path.

Row detail file/image values are split from a server-provided string (RowDetailItem.tsx:11 for Images/Documents labels, or data.images at :83) and passed to Files.tsx:15 and then FileViewer.tsx. There the value is used as src for an img or an iframe with no scheme or host check and no sandbox attribute (FileViewer.tsx:165, :172). The ref(storage, src) guard (FileViewer.tsx:40-46) does not gate rendering. When ref() throws (as it would for a javascript: string), storageRef is null, the effect sets showError and clears isCheckingContentType (FileViewer.tsx:50-55). The button therefore stays enabled and contentType stays '' (not image/), so the click opens the Modal and takes the iframe branch with the raw src. The backend accepts arbitrary strings for these fields: field.ParseValidURLs (backend/go/api/internal/form/field/field.go:811-826) only calls url.Parse, which accepts javascript: and data: strings. These flow through dispatch.go:177-201 and 257-281 (and the update_notes, receive, inbound_edit and outbound_edit handlers) into ledger image infos, and are then returned via model.DetImages and the Images info pair (graph/shipments.go:5489-5562). No CSP is defined in the client or backend source. The remaining unknowns are deployment and browser facts that source cannot settle: whether any CSP or header is applied at hosting, whether a counterparty (the victim) actually views the attacker-written field, and the browser behaviour of a javascript: iframe src.

### Trace
1. **entrypoint** `backend/go/api/internal/shipments/dispatch.go:177` (dispatch form handling (and sibling handlers update_notes.go:192-210, receive.go:207-223, inbound_edit.go:203-217, outbound_edit.go:232-242)) — Authenticated form user submits a FieldInput value for a reference-image/dispatch-images/driver-docs field; it is parsed with field.ParseValidURLs.
2. **propagation** `backend/go/api/internal/form/field/field.go:818` (ParseValidURLs) — Only url.Parse(s) is checked; any scheme (javascript:, data:, https://attacker) is accepted and appended to values.
3. **propagation** `backend/go/api/internal/graph/shipments.go:5489` (shipment detail builders (DetImages at 5493-5523; Images info pair joined with ';' at 5555-5562)) — Stored image URLs are returned unchanged to other users in DetailItem.images / info.value.
4. **propagation** `client/market/src/components/SubTableActionCard/RowDetailItem.tsx:83` (RowDetailItem) — data.images (and info.value split on ';' at :11 for Images/Documents labels, rendered at :75) are passed to <Files>.
5. **propagation** `client/market/src/components/Files.tsx:15` (Files) — Each string is passed as src to FileViewer with no validation.
6. **sink** `client/market/src/components/FileViewer.tsx:172` (FileViewer modal render) — Non-image (contentType '' or failed metadata) branch renders <iframe src={src}> with no sandbox; on user click the value is loaded in the viewer's browser.

### Verified evidence
- `client/market/src/components/FileViewer.tsx:40` — storageRef is built in try/catch and returns null on throw; this is a crash guard, not a gate on rendering.
- `client/market/src/components/FileViewer.tsx:50` — Null storageRef only sets name, showError and isCheckingContentType=false, leaving the open button enabled (disabled at :118 depends only on checking state and online status).
- `client/market/src/components/FileViewer.tsx:172` — iframe has no sandbox attribute and src is the raw string.
- `backend/go/api/internal/form/field/field.go:818` — Only url.Parse is applied to file field values.

### Exact blockers
- Whether the counterparty viewer can see the attacker-written field (per-role visibility and authorization of the shipment detail builders) was not fully traced from source.
- Browser behaviour for a javascript: iframe src (executes inheriting parent origin in common browsers) and whether any CSP or response header is applied at hosting are deployment facts not present in source.
- Auth token storage (Firebase persistence in the market origin) determines impact if script runs; not verified here.

### Resolution plan
- **Local (dummy data, isolated):** In a dev build, seed a shipment dispatch field value containing a harmless marker URL (for example a javascript: URL that only writes document.title) via the normal form submission, open the row detail as a second test user, click 'File 1', and observe whether the marker runs in the market origin. Also add a unit test that FileViewer rendered with a non-storage src still produces an iframe with that src.
- **Owner-observed deployment check:** Owner to inspect response headers of the deployed market origin for Content-Security-Policy (script-src, frame-src) in a test or staging environment and confirm which roles can view which dispatch/reference file fields. Do not probe production.

---

## Xcode Cloud post-build script echoes SENTRY_AUTH_TOKEN value to the build log

**Fingerprint:** `c4-ios-ci-sentry-token-echoed-to-build-log`  
**Claimed root cause:** Inverted or misused parameter expansion: ${SENTRY_AUTH_TOKEN:-NOT SET} was meant to print only a placeholder, but it expands to the token value whenever the token is set. It is combined with ${...:+SET (hidden)}, which only adds a prefix.

client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh runs under #!/bin/bash with set -e. Line 11 is an unconditional top-level statement: echo "SENTRY_AUTH_TOKEN: ${SENTRY_AUTH_TOKEN:+SET (hidden)}${SENTRY_AUTH_TOKEN:-NOT SET}". In POSIX/bash parameter expansion, ${V:+word} yields word when V is set and non-empty, and ${V:-default} yields the value of V when it is set and non-empty. When the token is set, the line therefore prints 'SET (hidden)' immediately followed by the raw token value. It prints 'NOT SET' only when the token is unset or empty, so the 'hidden' label is misleading. Lines 73-76 make the script exit 1 if the token is unset, and lines 79-82 pass it to sentry-cli upload-dif for org nile-ag, project ios. A successful release run therefore has the token set and logs it. No other line echoes a secret: lines 8-10 print only CI_* variables and the token is otherwise used only as a sentry-cli argument. Whether Xcode Cloud masks the secret in logs, and who can read those logs, are deployment facts not visible in source.

### Trace
1. **entrypoint** `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:1` (Xcode Cloud post-xcodebuild hook (bash, set -e); SENTRY_AUTH_TOKEN is injected as a workflow secret environment variable) — Script runs after each Xcode Cloud xcodebuild action with the Sentry token in its environment. The log is readable by the Xcode Cloud / App Store Connect users and anyone with log access.
2. **propagation** `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:73` (top-level of ci_post_xcodebuild.sh, inside if [[ -n "$CI_ARCHIVE_PATH" ]]) — Script exits 1 if the token is empty, so any run that reaches the Sentry upload has the token set. Line 11 itself is unconditional and runs on every invocation.
3. **sink** `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:11` (top-level echo, unconditional) — echo expands ${SENTRY_AUTH_TOKEN:-NOT SET} to the token value when set, and writes it to stdout, which Xcode Cloud captures in the build log.

### Verified evidence
- `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:1` — Shebang #!/bin/bash, so bash expansion semantics apply.
- `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:11` — echo with ${SENTRY_AUTH_TOKEN:+SET (hidden)}${SENTRY_AUTH_TOKEN:-NOT SET}: for a set value this prints 'SET (hidden)' followed by the token value. The line is not inside any conditional.
- `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:73` — Script aborts if the token is unset, so the token must be set for the script to complete successfully.
- `client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh:79` — Token is passed to sentry-cli --auth-token for upload-dif to org nile-ag, project ios, which shows it carries project upload scope at least.

### Exact blockers
- Whether Xcode Cloud masks secret environment variables in build logs is platform behaviour that cannot be established from source.
- Who can read Xcode Cloud build logs (App Store Connect role set, log export or artifact retention) is not in the repository.
- The scopes and live status of the Sentry token stored in the workflow are unknown from source.

### Resolution plan
- **Local (dummy data, isolated):** Source-only check already done: in bash, SENTRY_AUTH_TOKEN=dummy; echo "${SENTRY_AUTH_TOKEN:+SET (hidden)}${SENTRY_AUTH_TOKEN:-NOT SET}" prints 'SET (hidden)dummy'. Run it only with a dummy value, never the real token.
- **Owner-observed deployment check:** Owner-observed, no live probe: in App Store Connect, open the Xcode Cloud logs of a recent build of the Nile and NileStaging workflows and check whether the post-xcodebuild log line 'SENTRY_AUTH_TOKEN: ...' shows only 'SET (hidden)' followed by asterisks or masking, or a readable value. Also list which roles can view the logs. If a readable value appears, rotate the Sentry auth token (org nile-ag), check its scopes, and purge or restrict the old logs. Remediate by removing the :- expansion, e.g. echo "SENTRY_AUTH_TOKEN: ${SENTRY_AUTH_TOKEN:+SET (hidden)}${SENTRY_AUTH_TOKEN:-NOT SET}" becomes if [[ -n "$SENTRY_AUTH_TOKEN" ]]; then echo "SENTRY_AUTH_TOKEN: SET (hidden)"; else echo "SENTRY_AUTH_TOKEN: NOT SET"; fi.

---

## iOS wrapper WebView lets any non-blocklisted third-party page load in-app with the startDownload bridge and deviceToken injection attached

**Fingerprint:** `c4-ios-webview-thirdparty-page-reaches-bridge-and-token`  
**Claimed root cause:** WKWebView navigation policy is a small blocklist rather than a host allowlist, and the native bridge (startDownload handler plus deviceToken evaluateJavaScript injection) is attached to the web view without origin or frame checks, so any third-party page that gets loaded in-app inherits the bridge and receives the device token.

NileWebView's navigation policy only diverts Notion, social-media and 'firebasestorage' URLs to the system browser. Every other URL is allowed, and target=_blank popups are cancelled and reloaded in the same WKWebView. The 'startDownload' script message handler is registered on the webView configuration, so it applies to all frames and origins, and it never checks message.frameInfo or the sender's host. The handler fetches a page-supplied URL with URLSession.shared, accepts it if the response begins with %PDF, and writes it to the temp directory under a page-supplied filename that is not path-normalised. Separately, updateLocalStorage and notifyJavaScriptOfStorageChange run evaluateJavaScript into whatever page is current. They write localStorage.deviceToken (the FCM token) and postMessage it with targetOrigin '*', with no host check. The only host gate in the file is on universal-link reloads (line 148). The market web app does send server-supplied external URLs to window.open(url,'_blank') or window.location.href (Post.tsx:127, Explore.tsx:92, useHandleLink.ts:33). Source therefore shows an unguarded path once a third-party page is loaded, but the exploit depends on whether any lower-trust party can author such a URL (Explore post URLs and action URLs). I found no backend source showing that, and the post-authoring role is a deployment/data fact. Impact is also bounded: the exposed secret is an FCM device token, which is not a Nile session credential. The file write is limited to PDFs in the app temp directory, and the URL fetch is a blind PDF-only SSRF-like request from the device. Not confirmable from source alone.

### Trace
1. **entrypoint** `client/market/src/screens/Explore/Post.tsx:127` (Read more onClick) — For non-Nile post URLs the web app calls window.open(post.url,'_blank') with a server-supplied URL. Explore.tsx:92 and hooks/useHandleLink.ts:33 do the same via window.open/location.href. Who authors these URLs is not established from source.
2. **propagation** `client/ios/Nile/Nile/NileWebView.swift:431` (Coordinator.webView(_:decidePolicyFor:navigationAction:)) — externalLinkPolicy (line 475) cancels only Notion, social and 'firebasestorage' URLs. A nil targetFrame (target=_blank) is cancelled and reloaded in the same webView (lines 442-445). All other URLs, including top-frame and subframe loads, are allowed. decidePolicyFor navigationResponse allows everything (line 456). No other navigation or UI delegate exists in the iOS sources that I found.
3. **propagation** `client/ios/Nile/Nile/NileWebView.swift:253` (setupMessageHandler / MessageHandler.userContentController(didReceive:)) — The 'startDownload' handler is added to the webView's userContentController (all frames). The handler at line 591 parses only body.url and body.filename. It performs no check of message.frameInfo or the origin.
4. **propagation** `client/ios/Nile/Nile/NileWebView.swift:662` (MessageHandler.processDownload) — URLSession.shared fetches the page-supplied URL (line 649). If the body begins with %PDF it is written to temporaryDirectory.appendingPathComponent(page-supplied filename) (line 681) and a share sheet is presented. The filename is not sanitised.
5. **sink** `client/ios/Nile/Nile/NileWebView.swift:181` (updateLocalStorage / notifyJavaScriptOfStorageChange) — evaluateJavaScript writes localStorage.setItem('deviceToken', ...) (line 181) and window.postMessage({type:'storageChange',key:'deviceToken',newValue:...},'*') (line 159) into the current page, whatever its origin.

### Verified evidence
- `client/ios/Nile/Nile/NileWebView.swift:431` — decidePolicyFor allows every URL not matched by the Notion/social/firebasestorage blocklist. target=_blank popups load in the same webView.
- `client/ios/Nile/Nile/NileWebView.swift:148` — Only the universal-link reload path checks the host (market.nile.ag, market-staging.web.app, *.nile.ag). The token-injection paths at lines 129-199 do not check webView.url's host. The only guard is a skip while on Google OAuth or the Firebase auth handler.
- `client/ios/Nile/Nile/NileWebView.swift:591` — The message handler does not inspect message.frameInfo or the sending origin.
- `client/ios/Nile/Nile/NileWebView.swift:681` — The page-supplied filename is appended to the temp directory with no normalisation. Written bytes are limited to content starting with %PDF and the destination to the app temp directory.
- `client/market/src/hooks/useHandleLink.ts:33` — Assigns window.location.href = fullUrl for isExternal targets, so the top-level wrapper webView can be navigated to a third-party site.

### Exact blockers
- Whether any principal below Nile admin staff (for example sellers, buyers or other tenants) can author or influence the URL of an Explore post or action link that the web app opens externally. The backend source for post authoring and its authorisation was not located, and it depends on deployed data and roles.
- Which production URLs actually reach the in-app webView (production Explore content, Firebase remote config for the navigation flag). This is deployment data, not source.
- Behaviour of the startDownload bridge when invoked from a cross-origin top-level page in a shipped build is not observed. No code was executed in this run.

### Resolution plan
- **Local (dummy data, isolated):** In a simulator build with a test device token, load a controlled non-Nile HTTPS page in the wrapper. For example, point a staging Explore post URL at a test page and tap Read more. Confirm the page stays in-app and that localStorage.deviceToken and the storageChange postMessage are visible to the page. Call webkit.messageHandlers.startDownload.postMessage({url:<test PDF URL>,filename:'x.pdf'}) and confirm the fetch and share sheet occur. Use a dummy token and a test server only.
- **Owner-observed deployment check:** Owner-observed: review the backend authoring path and roles for Explore posts and action URLs (who can set post.url), and the production Explore data for non-Nile, non-social, non-firebasestorage URLs. If only trusted Nile admins can author them, close as accepted risk or low. If sellers, buyers or any tenant can author them, upgrade to confirmed at medium. Remediation is a host allowlist in decidePolicyFor (open everything else in SFSafariViewController or the system browser), a message.frameInfo.securityOrigin and host check in the startDownload handler, filename sanitisation (lastPathComponent), and removing the '*' targetOrigin and injecting the token only on *.nile.ag hosts.

---

## Slack incoming-webhook URL hardcoded in client/website package.json postdeploy script

**Fingerprint:** `c6-website-slack-webhook-committed`  
**Claimed root cause:** A webhook URL that acts as a bearer secret is committed in plaintext in a package.json script instead of being injected from CI or deploy-time environment or a secret store.

The npm script 'slack' in client/website/package.json embeds a full hooks.slack.com/services incoming-webhook URL (real format, not a placeholder or env reference) in a curl POST. client/website/firebase.json hosting.postdeploy runs 'npm run slack' after each Firebase deploy. Anyone with read access to the repository or package can post arbitrary messages as the webhook's bot into the bound Slack channel (spoofed deploy notices, phishing links). Incoming webhooks are write-only, so channel data cannot be read. Impact is limited to message spoofing. No other file under client/ references hooks.slack.com. Whether the webhook is live, which channel it targets, and whether the repo is private or the file is tracked cannot be determined from source (client/website is not a git repo checkout here).

### Trace
1. **entrypoint** `client/website/firebase.json:3` (hosting.postdeploy) — Firebase deploy hook runs 'npm run slack' after each hosting deploy. This is the execution path. The attacker entrypoint is read access to the repository contents.
2. **propagation** `client/website/package.json:13` (scripts.slack) — Script holds the literal webhook URL and the curl command with a static JSON text payload that interpolates $GCLOUD_PROJECT.
3. **sink** `client/website/package.json:13` (scripts.slack curl target) — POST to hooks.slack.com/services/<T>/<B>/<token>. Possession of the URL alone authorizes posting to the Slack channel.

### Verified evidence
- `client/website/package.json:13` — Literal committed hooks.slack.com/services webhook URL in the slack script (token value not reproduced here).
- `client/website/firebase.json:3` — postdeploy hook invokes npm run slack.

### Exact blockers
- Whether the webhook is still active, not revoked, and which Slack channel it posts to is a Slack workspace fact not visible in source.
- Whether the repository is private and who has read access (and whether this file is git-tracked) is a deployment fact not visible in source.

### Resolution plan
- **Owner-observed deployment check:** Owner check, with no live probe: in the Slack workspace admin (Apps > Incoming Webhooks or the owning app's Incoming Webhooks page), see whether a webhook matching the committed one's trailing identifier exists and which channel it targets. Check repository visibility and collaborator list, and git history for the file. If the webhook is live, rotate or revoke it, and move the URL to a CI secret or environment variable referenced by the script (for example $SLACK_WEBHOOK_URL).

---

## Shared Nile robot token literal committed in three client dev-tooling files

**Fingerprint:** `c7-robot-token-client-copies`  
**Claimed root cause:** A shared robot bearer token was pasted into client developer tooling and docs (codegen config, iOS README, Apollo schema script) instead of being read from an env var or secret store, duplicating the backend hardcoded-secret exposure.

The same literal as the backend robotToken constant (backend/go/auth/auth.go:30, run-1 finding auth/hardcoded-shared-robot-token) is committed in three client files. A grep -cF of the backend literal gave exactly one match in each file, so all three are the same value as the backend. Occurrences: client/market/graphql.config.ts:13 (Authorization Bearer header; X-Platform 1 at line 14), client/ios/README.md:10 (swift-graphql CLI example command) and client/ios-native/Farmer App/Nile Farmer/apollo-ios-gen-schema.sh:12 (--header Authorization). This is NOT a distinct root cause: these are additional locations of the run-1 hardcoded-shared-robot-token finding (secret committed to source). It only adds exposure to anyone with read access to the client tree. None of the three is shipped in a runtime bundle. graphql.config.ts is referenced only by the package.json generate:gql script (graphql-codegen --config) and by tsconfig.node.json include. It is not imported from src, vite.config.mts or tsconfig.app.json. The market Dockerfile does 'COPY . .' in the builder stage (line 9), but the final nginx stage copies only /app/build (line 103), so the file does not reach the runtime image. The iOS README and shell script are docs and tooling. Whether the literal is the live production secret is a deployment fact not visible in source. The impact is that of the run-1 finding (platform-admin robot access via the public GraphQL auth middleware) if live. Git tracking could not be checked, since core is not a git repository here.

### Trace
1. **entrypoint** `client/market/graphql.config.ts:13` (graphql-codegen config for the market app) — Literal robot Bearer token placed in the Authorization header for introspecting a hardcoded staging GAPI URL; run via package.json generate:gql.
2. **propagation** `client/ios/README.md:10` (iOS README swift-graphql command) — Same literal in a documented CLI --header argument; developers copy and paste it, and it sits in the repo.
3. **propagation** `client/ios-native/Farmer App/Nile Farmer/apollo-ios-gen-schema.sh:12` (Apollo iOS schema download script) — Same literal passed as an Authorization header when the script downloads the schema.
4. **sink** `backend/go/auth/auth.go:30` (auth package constant robotToken (via GetRobotToken)) — The backend constant is the same value. If it is live, anyone who can read the client repo holds a credential accepted as the platform-admin robot (see run-1 auth/hardcoded-shared-robot-token).

### Verified evidence
- `client/market/graphql.config.ts:13` — Authorization header holds the robot token literal (grep -cF against the backend literal: same).
- `client/ios/README.md:10` — Command example includes the same literal (same as the backend).
- `client/ios-native/Farmer App/Nile Farmer/apollo-ios-gen-schema.sh:12` — --header Authorization carries the same literal (same as the backend).
- `client/market/Dockerfile:103` — The final stage copies only /app/build into nginx, so graphql.config.ts (copied in the builder stage at line 9) is not in the runtime image.
- `client/market/package.json:8` — generate:gql is the only consumer of graphql.config.ts; there are no imports from src or vite config.

### Exact blockers
- Source cannot show whether the committed literal is the live production/staging secret, already rotated, or a dev-only value (deployment fact).
- Git tracking and history of the three files could not be checked (core has no .git in this environment), so it is not known whether the secret was ever pushed to a shared remote.

### Resolution plan
- **Local (dummy data, isolated):** Source-only follow-up: confirm via the repo host (not a live probe) that the three files are tracked and check history for the first commit introducing the literal. Confirm the iOS build does not embed apollo-ios-gen-schema.sh or the README.
- **Owner-observed deployment check:** Owner-observed check, no live probe: compare the committed value with the current token in Secret Manager or deploy configuration (compare hashes, not printed values) and check the staging GAPI URL in graphql.config.ts against it. If it matches, rotate the token once for the backend, pdf.ts, loadtests and these client files together, and replace the client copies with an env var read (for example GAPI_TOKEN) in graphql.config.ts, the shell script and the README.

---

