# Combined needs-validation leads

# Backend leads (run-1)

These are source-grounded hypotheses blocked on facts outside the repository. They are not confirmed vulnerabilities. All checks are owner-observed configuration reviews or local dummy-data tests; **do not send live probes**.

## Admin-party GraphQL resolvers do not bind the target profile to the caller's platform (AdminProfileID)

**Fingerprint:** `H5-admin-not-platform-scoped`  
**Claimed root cause:** Authorization for Admin party type is role-only (PartyTypeAdmin) with no comparison of the target profile's AdminProfileID to the caller's AdminProfileID. The platform check at login/request time (checkPlatform) binds the caller to one platform header but not the data they may address.

Admin-party callers can supply an arbitrary profile ID to GraphQL resolvers (Profile, ProfileNew, AccountingDoc and similar) and the target profile's AdminProfileID is never compared with the caller's AdminProfileID. checkPlatform only checks that the caller's own AdminProfileID equals the X-Platform header. It does not limit which profiles the caller may read. Whether this is a real cross-tenant break or intended staff-wide access depends on whether the four platforms (1 Nile, 2 Freshmark, 3 Nile Inputs, 4 Villa) are separate organizations or all Nile-staffed. Source cannot decide that, so the verdict stays needs_validation. This was a source-only review; no code was run.

### Trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:2461` (queryResolver.Profile) — Authenticated Admin caller supplies input.ID. If PartyType is Admin and ID is non-zero, the value is used as-is. Non-admins are forced to their own ProfileID.
2. **propagation** `backend/go/api/internal/graph/auth_checks.go:78` (AccountingDocAuthorized) — The check only requires that the caller is Admin or that profileUUID equals the caller's ProfileID. Admin bypasses the profile comparison, with no AdminProfileID comparison.
3. **propagation** `backend/go/auth/auth.go:494` (checkPlatform) — Requires usr.AdminProfileID to equal the X-Platform header. This binds the caller to one platform but does not restrict which profile IDs they may query.
4. **sink** `backend/go/api/internal/graph/schema.resolvers.go:2478` (queryResolver.Profile) — r.Ledger.Profile, r.Administrator.Profiles and r.Ledger.Transactions are called with the caller-chosen input.ID. In the lines reviewed, no profile.AdminProfileID == caller.AdminProfileID check was found.

### Verified evidence
- `backend/go/api/internal/graph/schema.resolvers.go:2467` — Admin may pass any non-zero input.ID. Only non-admins are overridden with their own profile ID.
- `backend/go/api/internal/graph/auth_checks.go:78` — AccountingDocAuthorized gives Admin an unconditional pass on profile ownership.
- `backend/go/auth/auth.go:504` — checkPlatform compares only the caller's AdminProfileID with the X-Platform header.
- `backend/go/ledger/types.go:165` — Profile carries AdminProfileID, so a per-platform comparison was feasible but is not applied in these resolvers.
- `backend/go/ledger/internal/ops/shipment_actions.go:1483` — Calibration: some write paths do compare seller and buyer AdminProfileID, so platform scoping is enforced selectively in places. This suggests it is a known concern. It does not cover the read resolvers named in the candidate.
- `docs/shipit-core-connector-plan.md:53` — Docs describe platforms by admin ID (1 Nile, 2 Freshmark, 3 Nile Inputs, 4 Villa) and say the platform check is a sign-in binding. Nothing in the docs says whether the platforms are separate legal or organizational tenants.

### Exact blockers
- Whether the four platforms are separate organizations or tenants with distinct staff, as opposed to one company's staff operating multiple brands, is a business and deployment fact that is not in source. If all admins are Nile staff, this is a design choice and not a security boundary.
- Source review covered only the resolvers and auth checks. It did not exhaustively confirm that the ledger and administrator services (r.Ledger.Profile, Administrator.Profiles, Transactions) do not scope by the caller's AdminProfileID in the database queries. The auth context is passed in, so a downstream filter is possible.
- Whether Admin-party users are in practice provisioned per platform, so that a Villa or Inputs admin is a different population from Nile staff, is not visible in source.

### Resolution plan
- **Local (dummy data, isolated):** Read the ledger Profile, Transactions and administrator Profiles implementations to see whether any query filters by auth.UserFromContext(ctx).AdminProfileID. Then run a local test with seeded profiles under two different AdminProfileIDs. Query as a platform-1 admin with a platform-2 profile ID and check whether data is returned. Use the repo's own test harness on dummy data only.
- **Owner-observed deployment check:** The owner should state whether Freshmark, Nile Inputs and Villa admins are distinct organizations, or whether external or partner staff hold Admin party type on any platform. In production Firebase and the users table, list the distinct Admin-party users per AdminProfileID. Review resolver access logs for admin queries whose profile ID belongs to a different AdminProfileID than the caller. Do not probe live.

---

## Profile logo URL fetched server-side without destination restriction when rendering document PDFs (blind SSRF)

**Fingerprint:** `H5-logo-ssrf`  
**Claimed root cause:** User-controlled logo URL is validated only by url.Parse and later fetched by LogoCache.fetch with an unrestricted http.Client, with no allow-list of hosts or schemes (for example the upload bucket or CDN), no blocking of private or link-local IPs, and no response size limit.

A user holding ProfileInformation:Write on a company profile can store an arbitrary URL string as the profile logo resource. The only validation is url.Parse, which accepts any string. When a shipment document is built, the admin or seller logo URL becomes SourceDoc.Info.Logo. GET /docs/pdf then renders the document in the API process. docpdf.header treats any value starting with 'http' as a logo URL and calls LogoCache.fetch. That fetch uses http.DefaultClient (NewLogoCache(nil)), which has no scheme, host, IP-range or redirect restriction. The result is an authenticated, blind, GET-only server-side request to any host the API process can reach, with a 15s timeout. The response is not returned to the caller. A non-image or non-200 response draws nothing. A 5xx response surfaces as an error. The only visible effect is that a response that decodes as an image is embedded in the rendered PDF. Impact is limited by the GET-only method, the lack of attacker-chosen headers, the lack of a response channel for non-images, and the likely IAM or authentication requirements on internal services. io.ReadAll on the response body is unbounded, so a large response could cause memory pressure. Whether the render host can reach valuable unauthenticated internal HTTP targets is a deployment fact that cannot be settled from source.

### Trace
1. **entrypoint** `backend/go/api/internal/graph/customers/company.go:631` (company profile form save (profileLogo case), reachable by users with ProfileInformation Write (editProfile at line 67)) — The profileLogo field value is parsed with field.ParseValidURLs. The URLs are stored at line 705 as ap.Resources[administrator.RscLogo].
2. **propagation** `backend/go/api/internal/form/field/field.go:811` (field.ParseValidURLs) — Each delimited value is checked only with url.Parse, which accepts nearly any string. No scheme or host check is applied.
3. **propagation** `backend/go/api/internal/graph/sourcedoc.go:311` (buildLogo (and buildLogo_legacy at line 44)) — The admin profile's first logo URL, or the seller's logo URL for seller shipments (lines 316-319), is returned as doc.Info.Logo (assigned at lines 171 and 302).
4. **propagation** `backend/go/api/docs/docpdf/docpdf.go:467` (resolveLogo and renderer.header (lines 359-363)) — Any logo string starting with 'http' is classified logoDoc and passed to opts.Logos.logo(ctx, info.Logo).
5. **sink** `backend/go/api/docs/docpdf/logocache.go:99` (LogoCache.fetch) — c.client.Do(req) issues a GET to the attacker-supplied URL using http.DefaultClient (handler.go line 48, NewLogoCache(nil)). The body is read in full at line 114 and decoded with image.DecodeConfig at line 118.

### Verified evidence
- `backend/go/api/internal/form/field/field.go:819` — Only url.Parse is checked for logo URLs.
- `backend/go/api/docs/docpdf/logocache.go:49` — A nil client falls back to http.DefaultClient with no dialer, redirect or IP restrictions.
- `backend/go/api/docs/handler.go:48` — PDFHandler constructs the cache with NewLogoCache(nil). The handler is authenticated via AuthHTTP (line 58), and the document resolves through the caller's own authorization.
- `backend/go/api/docs/docpdf/logocache.go:105` — Only status 200 proceeds. 5xx returns an error that is surfaced to the caller (limited error oracle). Other statuses return an empty result. Non-images draw nothing, so there is no response-body exfiltration for non-image content.
- `backend/go/api/docs/docpdf/logocache.go:114` — io.ReadAll has no size limit.

### Exact blockers
- Egress and reachability facts are not in source: whether the API/docs process can reach internal HTTP services that are unauthenticated or lack a Metadata-Flavor-style header requirement.
- Which roles hold ProfileInformation Write on seller and admin profiles in production, and whether those are external lower-trust tenants or only staff.
- Source shows no response channel beyond image embedding in the PDF and a 5xx error oracle, so the value of the SSRF depends on deployment network layout.

### Resolution plan
- **Local (dummy data, isolated):** In a dev environment with synthetic data only, set a logo on a test seller profile to a URL on a local listener that logs requests. Render a shipment document through GET /docs/pdf and confirm one GET arrives from the API process. Then point the logo at a local image served by that listener and confirm it is embedded. Also confirm a non-image response and a non-200 response draw no logo. Confirm that no private-IP block exists on the client.
- **Owner-observed deployment check:** Owner check: review the Cloud Run service egress and VPC connector or firewall configuration for the API service and list any internal HTTP endpoints reachable without authentication. Review the profile-permission role assignments to see whether external sellers hold ProfileInformation Write. Optionally query stored logo resources for URLs pointing to non-upload hosts. Do not probe live.

---

## Unauthenticated GraphQL introspection with no depth/complexity limit may allow resource-exhaustion amplification on the shared api service

**Fingerprint:** `api-graphql-introspection-cycle-amplification-unauth`  
**Claimed root cause:** newServer registers handler.New without extension.FixedComplexityLimit or a depth validator. It always enables extension.Introspection{}, and AuthOperation lets unauthenticated users through by op.Operation.Name allowlist, which is attacker-controlled. http.ListenAndServe is used with no timeouts or MaxBytesReader.

The api GraphQL server is built with no query complexity or depth limit. Introspection is always enabled. The auth middleware admits an unauthenticated caller whenever the client-chosen operation name is ValidateCurrentToken, SignUp or Signup. An anonymous client can therefore send a small, deeply nested introspection query that walks the cyclic __Type graph (for example __schema{types{fields{type{fields{type{...}}}}}} or interfaces/possibleTypes), under one of those operation names. Response size and CPU grow roughly exponentially with nesting depth, while the request grows linearly. The http.Server has no read, write or body-size limits. Source confirms the missing controls and the auth bypass by operation name. Whether the amplification is large enough to degrade the service depends on the gqlgen v0.17.90 introspection and validation behaviour, which could not be executed here, and on Cloud Run request timeouts, concurrency, autoscaling and any fronting WAF or limit. These are not visible in source, so this stays needs_validation.

### Trace
1. **entrypoint** `backend/go/api/cmd/server/main.go:289` (main: http.Handle("/graphql", gzipHandler)) — Public /graphql endpoint wrapped by CORS and gzip only. Anonymous POST or GET is accepted.
2. **propagation** `backend/go/auth/auth.go:373` (Client.AuthOperation) — Operation middleware. For an unauthenticated user (FIDUnauthed) it blocks only when op.Operation.Name is not in publicOperations (line 422). A client-chosen operation name of Signup or ValidateCurrentToken passes, and the check is on the name, not on the selected fields, so an introspection selection set is admitted.
3. **propagation** `backend/go/api/cmd/server/main.go:75` (newServer) — Server is built with transports, an LRU query cache and APQ. No complexity limit, depth limit or query-size limit extension is registered. I found no ComplexityLimit or FixedComplexityLimit usage anywhere under backend/go.
4. **sink** `backend/go/api/cmd/server/main.go:123` (newServer: server.Use(extension.Introspection{})) — Introspection is enabled in all environments. The nested cyclic __Type traversal is executed and serialised for an anonymous caller, and the ListenAndServe at line 303 adds no timeouts or body limits.

### Verified evidence
- `backend/go/api/cmd/server/main.go:123` — extension.Introspection{} is unconditionally enabled with no environment gate.
- `backend/go/api/cmd/server/main.go:303` — http.ListenAndServe on the default mux, with no http.Server timeouts or MaxBytesReader.
- `backend/go/auth/auth.go:404` — Unauthenticated users are rejected only if op.Operation.Name is not in publicOperations.
- `backend/go/auth/auth.go:422` — publicOperations = ValidateCurrentToken, SignUp, Signup, matched by client-supplied operation name.
- `backend/go/go.mod:20` — gqlgen v0.17.90. This version is not in the local module cache (only v0.17.73 and v0.17.76), so framework behaviour could not be read.

### Exact blockers
- No runtime execution is allowed, so the actual CPU, memory and response-size amplification of nested introspection on gqlgen v0.17.90 and gqlparser validation is not measured.
- Cloud Run request timeout, max instances, concurrency, CPU limits and any Cloud Armor or WAF or gateway query limits are not in source.
- gqlgen v0.17.90 source is not available locally, so I could not confirm whether it adds an introspection depth bound or default limits.

### Resolution plan
- **Local (dummy data, isolated):** In a local dev instance with dummy data, send the Signup-named introspection query at depths 3, 5, 7 and 9. Record response bytes, CPU time and peak RSS per depth to see if growth is exponential. Then check whether adding FixedComplexityLimit or a depth validator bounds it. Run this only against localhost.
- **Owner-observed deployment check:** The service owner should review the Cloud Run config for the api service (request timeout, concurrency, max instances) and any Cloud Armor or load-balancer policy. They should also check the staging request-latency and memory dashboards for a controlled, owner-run query at moderate depth. Do not probe production.

---

## Hardcoded shared robot bearer token accepted by the public GraphQL auth middleware yields platform-admin robot identity

**Fingerprint:** `auth/hardcoded-shared-robot-token`  
**Claimed root cause:** A long-lived shared secret is committed in source and compared directly in the authentication path. The tenant it applies to is chosen by the caller through X-Platform. The secret cannot be rotated without a code change and redeploy, and any copy of the source gives cross-tenant admin-equivalent access if the value is live.

backend/go/auth/auth.go defines the constant robotToken (line 30, key robotToken; value not reproduced here). userFromIDToken (line 467) accepts it with a plain switch match (case at line 468) on the Authorization bearer. It then parses the caller-supplied X-Platform header as an admin id (line 469) and returns DetermineRobotUser(aid) (line 473). That returns a User with PartyTypeAdmin, ProfileID and AdminProfileID set to the chosen platform's admin id, and RoleRobot (UsrRobot, lines 183-192; mapping at 246-257 covers Nile, Freshmark, Inputs and Villa). AuthOperation (line 373) is installed on the public GraphQL server (backend/go/api/cmd/server/main.go:120). It calls userFromIDToken at line 393, and checkPlatform passes because AdminProfileID equals the header value. No environment gate, expiry, IP restriction or per-tenant secret exists in source. The same literal is embedded in backend/functions/firebase/functions/src/pdf.ts:30 and is also usable on AuthHTTP (auth.go:432). Source establishes the acceptance path. It does not establish that the literal is the live production secret, or that the secret reaches anyone outside the trusted engineering boundary, or that the endpoint is internet-reachable. A newer Google service-account OIDC path (robotFromServiceAccount, auth.go:480) exists as a replacement, which suggests the shared literal is a legacy path that may still be live.

### Trace
1. **entrypoint** `backend/go/api/cmd/server/main.go:120` (gqlgen server setup) — AuthOperation middleware is attached to the public /graphql server, so the Authorization and X-Platform headers are caller-controlled.
2. **propagation** `backend/go/auth/auth.go:393` ((*Client).AuthOperation) — Bearer token and X-Platform header are read (lines 379-392) and passed to userFromIDToken.
3. **propagation** `backend/go/auth/auth.go:468` ((*Client).userFromIDToken) — A token equal to the hardcoded robotToken matches this case. X-Platform is parsed as an int64 admin id (line 469).
4. **sink** `backend/go/auth/auth.go:473` ((*Client).userFromIDToken / DetermineRobotUser) — Returns an admin-party robot User for the caller-chosen tenant. AuthOperation then places it in context (line 410), and the checkPlatform, rejected-status and unauthed-operation checks all pass.

### Verified evidence
- `backend/go/auth/auth.go:30` — Hardcoded robotToken constant, plus potatoesSaToken at line 31 (a separate hardcoded secret with the same pattern). Exposed via GetRobotToken at line 34.
- `backend/go/auth/auth.go:183` — UsrRobot is PartyTypeAdmin with ProfileID and AdminProfileID set to the platform admin id and RoleRobot. DetermineRobotUser at line 246 selects the robot by caller-supplied admin id.
- `backend/functions/firebase/functions/src/pdf.ts:30` — The same literal is embedded in the pdf Cloud Function.

### Exact blockers
- Cannot tell from source whether the committed literal is the live production secret, or already rotated, or a dev-only value.
- Cannot tell from source who has read access to the repository or its copies, which determines whether 'source copy' is a lower-trust principal.
- Cannot tell from source whether the /graphql ingress is reachable by unauthenticated internet callers, or only via an IAP, VPN or private ingress.
- The effective permissions of the Robot admin user across resolvers and access checks (e.g. RoleRobot handling) were not fully enumerated in this pass.

### Resolution plan
- **Local (dummy data, isolated):** In a dev environment, send a GraphQL request with Authorization set to the robot token and X-Platform set to a dev admin id. Confirm the resolver context user is the robot admin, and enumerate which resolvers or directives authorize PartyTypeAdmin or RoleRobot. Run only against a local or dev instance.
- **Owner-observed deployment check:** Owner-observed check, not a live probe: confirm in Secret Manager or deploy configuration whether the committed value matches the production token. Review repository and fork access lists and any past leakage. Review Cloud Run ingress and IAM for the GraphQL service. Review auth logs for FIDRobot users arriving from non-service IPs. Rotate the secret and migrate callers to the OIDC service-account path (robot_oidc.go) as a precaution.

---

## Firebase functions env files and runtimeconfig hold NILE_API_KEY values in the source tree

**Fingerprint:** `backend/functions/firebase/functions/functions-env-committed-api-keys`  
**Claimed root cause:** Environment secrets for a server-to-server call (NILE-API-KEY header to the API Jobs/sendPriceMailer endpoint) are stored as plaintext files in the repository working tree and are not excluded by any ignore rule, rather than being held in Secret Manager or a git-ignored local file.

The files .env.nile-production, .env.nile-staging and .runtimeconfig.json in backend/functions/firebase/functions each hold a NILE-API-KEY credential (key names NILE_API_KEY and nile_api.key; values not reproduced here). The only ignore file on the path, functions/.gitignore, lists only 'lib', and the repo root .gitignore has no .env* or .runtimeconfig.json rule. The Sapling treestate (.sl/treestate) records all three file names, so they are very likely tracked. The only in-repo consumer, priceMailer.ts, is commented out of index.ts. No code under backend/ validates the NILE-API-KEY header or serves the Jobs/sendPriceMailer endpoint it calls, so what the key authenticates to, and whether it is live, cannot be established from this scope.

### Trace
1. **entrypoint** `backend/functions/firebase/functions/.env.nile-production:4` (dotenv file for the nile-production Firebase functions deployment) — Plaintext NILE_API_KEY next to NILE_API_URL pointing at the production API host. Readable by anyone with repository access.
2. **propagation** `backend/functions/firebase/functions/src/config.ts:3` (config module) — NILE_API_KEY is read from process.env, which Firebase populates from the .env.<project> file at deploy time.
3. **sink** `backend/functions/firebase/functions/src/priceMailer.ts:12` (sendPrices()) — The key is sent as the NILE-API-KEY header on PUT Jobs/sendPriceMailer. All exports are commented out in src/index.ts lines 8 and 15-17, so this is currently not deployed from this source.

### Verified evidence
- `backend/functions/firebase/functions/.env.nile-staging:3` — Staging NILE_API_KEY in plaintext.
- `backend/functions/firebase/functions/.runtimeconfig.json:3` — Legacy runtime config nile_api.key credentials in plaintext; lines 3-4 hold values.
- `backend/functions/firebase/functions/.gitignore:1` — Contains only 'lib'; none of the three secret files is ignored.
- `backend/functions/firebase/functions/src/index.ts:8` — priceMailer import and exports are commented out (lines 8 and 15-17), so the consumer is disabled.
- `.gitignore:1` — Root .gitignore (core/.gitignore) ignores .firebaserc, .firebaseConfig.json and .firebase, but has no .env* or .runtimeconfig.json pattern.

### Exact blockers
- Sapling tracking is only inferred: .sl/treestate lists the three filenames, but whether they are committed in history (or only present in the working copy) was not confirmed without running sl.
- The receiving API (Jobs/sendPriceMailer, NILE-API-KEY validation) is not in backend/ scope, so the key's privileges and whether it is currently valid or rotated cannot be determined from source.
- The only consumer function is disabled, which lowers the likelihood that the key is still active.

### Resolution plan
- **Local (dummy data, isolated):** Repository owner runs 'sl files' or 'sl log -f' on the three paths to confirm they are tracked and in how many commits, and checks who can read the repo.
- **Owner-observed deployment check:** Owner checks whether the production and staging NILE_API_KEY values are still accepted by the API (via the key store or audit logs, not a live probe). If active, rotate them, move them to Secret Manager or a git-ignored file, add .env.* and .runtimeconfig.json to .gitignore, and purge them from history.

---

## generatePdf Cloud Function appends the static robot token to a caller-chosen URL and loads it in headless Chromium

**Fingerprint:** `backend/functions/firebase/functions/src/pdf.ts-generatePdf-url-ssrf-token-exfil`  
**Claimed root cause:** An unauthenticated, CORS-open HTTP function concatenates a hardcoded long-lived bearer secret onto an unvalidated user-supplied URL and navigates a headless browser to it, with no host allowlist or caller authentication.

The generatePdf onRequest function (europe-west1) has no authentication code and uses cors({origin:true}). It takes ?url= from the query string with no scheme or host validation. It appends the hardcoded robotToken=<static value> (pdf.ts:27-30) and loads the result with Puppeteer page.goto (pdf.ts:49). An attacker who can reach the function can supply a URL on a host they control and receive the token in the request line. The same string is accepted by the Go API as the shared robot credential (auth.go:30 defines it and auth.go:468 matches it in userFromIDToken, returning DetermineRobotUser(admin id from the platform header)), so a leaked token yields robot/admin-level API access. The browser also fetches arbitrary URLs from inside the Cloud Functions network (SSRF, including the metadata server), and the rendered result is returned as a PDF to the caller. Source review found no URL allowlist, no caller check and no invoker restriction in pdf.ts, index.ts or firebase.json. The remaining unknown is deployment: whether the deployed function is publicly invokable. The firebase-functions v2 onRequest default is a public invoker, and the web client needs browser access, which points to public. That cannot be proven from source. The repo's own docs/shipit-core-connector-plan.md:371-381 describes the same issue as open. Secondary: the name parameter is interpolated unescaped into footerTemplate HTML (pdf.ts:95), giving HTML injection into the PDF footer, which is limited and low impact. Content-Disposition (pdf.ts:101-104) uses name unquoted, but Node rejects CR/LF in header values, so there is no header splitting; the effect is limited to filename and parameter manipulation.

### Trace
1. **entrypoint** `backend/functions/firebase/functions/src/pdf.ts:10` (generatePdf = onRequest({memory,timeoutSeconds,region}, ...) with cors({origin:true}) at line 5; no invoker option and no auth check) — Public HTTP entrypoint; any caller who can reach the function can invoke it.
2. **propagation** `backend/functions/firebase/functions/src/pdf.ts:19` (generatePdf handler) — url = request.query.url, attacker-controlled; the only validation is a non-empty check (lines 22-25).
3. **propagation** `backend/functions/firebase/functions/src/pdf.ts:27` (generatePdf handler) — Appends the hardcoded robotToken=<static token> as a query parameter to the attacker-supplied URL (lines 27-30).
4. **propagation** `backend/functions/firebase/functions/src/pdf.ts:49` (generatePdf handler, page.goto(url) in Puppeteer launched with --no-sandbox (line 34)) — Headless Chromium requests the attacker-chosen URL including the token, sending it to the attacker host (or to internal addresses). The page is rendered to PDF (line 81) and returned to the caller.
5. **sink** `backend/go/auth/auth.go:468` (Client.userFromIDToken) — The leaked value matches robotToken (auth.go:30) and maps to DetermineRobotUser(admin id from the platform header), so the exfiltrated token is a usable credential against the API.

### Verified evidence
- `backend/functions/firebase/functions/src/pdf.ts:19` — url taken straight from the query string; only an emptiness check (22-25).
- `backend/functions/firebase/functions/src/pdf.ts:30` — Hardcoded robot token literal appended to the URL (key name robotToken; value not reproduced here).
- `backend/functions/firebase/functions/src/pdf.ts:49` — page.goto(url) on the unvalidated URL.
- `backend/functions/firebase/functions/src/pdf.ts:95` — name interpolated unescaped into footerTemplate HTML.
- `backend/functions/firebase/functions/src/index.ts:12` — generatePdf exported with no invoker/auth wrapper; setGlobalOptions sets only region.
- `backend/functions/firebase/firebase.json:1` — No invoker, ingress or IAM configuration for the function.
- `backend/go/auth/auth.go:30` — Same static string defined as the Go API robotToken constant; accepted at line 468.
- `docs/shipit-core-connector-plan.md:371` — Internal doc states the function is unauthenticated and leaks the token to caller-supplied URLs, and that rotation is still pending.

### Exact blockers
- Whether the deployed Cloud Run service behind generatePdf grants roles/run.invoker to allUsers (public) is not visible in source. firebase-functions v2 onRequest defaults to a public invoker, but IAM could have been changed out of band.
- Whether the deployed robotToken value is still live (not rotated) and whether egress from the function is unrestricted is not visible in source.
- Whether the Go API at the deployed ingress honours the platform header for robot callers so the token yields real admin access, which depends on deployment configuration.

### Resolution plan
- **Local (dummy data, isolated):** In the Firebase emulator (port 5001 per firebase.json), call generatePdf with url set to a local listener the owner controls and confirm the listener receives robotToken in its query string; confirm that name containing HTML renders in the footer and that CR/LF in name causes a header error.
- **Owner-observed deployment check:** Owner-observed checks only, no live probe: (1) in GCP console or via 'gcloud run services get-iam-policy generatepdf --region europe-west1', check whether allUsers or allAuthenticatedUsers holds roles/run.invoker, and review ingress settings; (2) confirm in Secret Manager or the deployment config whether the robot token has been rotated since the commit; (3) review Cloud Run logs for generatePdf requests whose url host is not a Nile market origin.

---

## Zip-slip in harvester Potatoes SA archive extraction (no containment of entry names)

**Fingerprint:** `harvester-potatoessa-unzip-path-traversal`  
**Claimed root cause:** unzipFile builds the output path with path.Join(os.TempDir(), date+'_'+f.Name) and calls os.Create and io.Copy without checking that the cleaned path remains inside the intended extraction directory. The date prefix does not prevent escape, because a single prefix segment is cancelled by one '..' during path.Clean.

The harvester downloads a zip from a URL returned by the third-party api.potatoes.co.za endpoint and extracts every entry using the attacker-controlled entry name in the destination path with no containment check. The path arithmetic does not neutralise traversal. The entry name is prefixed with 'YYMMDD_', which becomes one extra path segment. path.Join then lexically cleans 'tmp/260101_/../../x' to '<parent of tmp>/x', so the prefix consumes one '..' and a second '..' escapes os.TempDir(). Entries with three or more '..' go further up. Absolute entry names stay under the temp dir because of the prefix. Go's archive/zip accepts '..' names by default; no GODEBUG zipinsecurepath setting was found in the repo. The result is an arbitrary file create/truncate and write as the harvester process user, with contents controlled by the zip provider. The directory branch (os.MkdirAll on a relative, prefixed name) is a lesser variant. The source path is fully established. Exploitability depends on the provider being malicious or compromised, on the process user and filesystem permissions in the harvester container, and on what is writable and later consumed. These are deployment facts, so the verdict is needs_validation and not confirmed.

### Trace
1. **entrypoint** `backend/go/harvester/internal/ops/potatoesSA/methods.go:63` (getZipFileURL) — The JSON body from the third-party https://api.potatoes.co.za/external/nile/<date> endpoint (authenticated with a Bearer token) is decoded, and ex.URL is returned unvalidated. This is the lower-trust external data feed.
2. **propagation** `backend/go/harvester/internal/ops/potatoesSA/methods.go:82` (downloadZipFile) — The provider-supplied URL is fetched with no host or scheme check. The body is written to os.TempDir()/<date>_potatoes_sa.zip (lines 88-94), so the provider controls the full zip contents.
3. **propagation** `backend/go/harvester/internal/ops/potatoesSA/methods.go:105` (unzipFile) — zip.OpenReader opens the archive; f.Name for each entry is attacker-controlled. Go's default behaviour does not reject '..' names (the zipinsecurepath GODEBUG setting is not set in the repo).
4. **propagation** `backend/go/harvester/internal/ops/potatoesSA/methods.go:125` (unzipFile) — fp = path.Join(os.TempDir(), 'YYMMDD_' + f.Name). The name '../../x' cleans to '<parent of tmp>/x', escaping the temp dir. There is no prefix or containment check.
5. **sink** `backend/go/harvester/internal/ops/potatoesSA/methods.go:126` (unzipFile) — os.Create(fp) creates or truncates the file at the escaped path, and io.Copy (line 132) writes the entry contents into it. The sink is an arbitrary file write as the harvester user.

### Verified evidence
- `backend/go/harvester/internal/ops/potatoesSA/types.go:10` — fileDelimiter is '_' and dateFormat is '060102' (line 8). The prefix is therefore the single segment 'YYMMDD_', which one '..' cancels, so it does not block traversal.
- `backend/go/harvester/internal/ops/potatoesSA/methods.go:33` — newFileName concatenates the date, the delimiter and the raw entry name with no sanitisation.
- `backend/go/harvester/internal/ops/potatoesSA/methods.go:118` — The directory branch calls os.MkdirAll on the prefixed relative name, with no containment and no temp-dir anchoring.
- `backend/go/harvester/internal/ops/potatoesSA/potatoes_sa.go:44` — unzipFile is called directly on the downloaded archive, with no intermediate validation of entry names.
- `backend/go/go.mod:3` — The toolchain is Go 1.27. The repo has no zipinsecurepath GODEBUG setting, so '..' entry names are accepted by archive/zip.
- `backend/go/harvester/Dockerfile:21` — The runtime image is docker.io/chromedp/headless-shell:stable. No USER directive was seen in the grep, so the container user and filesystem writability are unresolved from source.

### Exact blockers
- The provider (api.potatoes.co.za) is a contracted partner feed. Whether it is a realistic lower-trust principal, or could be compromised or tampered with in transit, is a threat-model fact not in source.
- The harvester container runtime user, read-only root filesystem setting and writable mounts are not in source (the Dockerfile has no USER directive). These determine what an escaped write can overwrite and what impact follows.
- The runtime Go behaviour (GODEBUG zipinsecurepath) in the deployed binary was not observed, and no code could be run in this review.

### Resolution plan
- **Local (dummy data, isolated):** In a throwaway Go test or sandbox with a scratch directory and no network, build a zip containing an entry named '../../probe.txt' and call unzipFile on it with TMPDIR set to a nested scratch subdirectory. Confirm whether the file appears outside that TMPDIR. Also confirm that zip.OpenReader does not return ErrInsecurePath under the repo's Go 1.27 and GODEBUG defaults.
- **Owner-observed deployment check:** Owner to inspect the harvester Cloud Run or container configuration for the runtime UID, read-only root filesystem and writable mounts (inspect only, no live probing). Also confirm the contractual and TLS trust relationship with the Potatoes SA API and whether the endpoint or token has ever been exposed. If the container runs non-root with a read-only filesystem, downgrade to low or informational. Regardless, fix by rejecting entries whose cleaned path is not inside a dedicated extraction directory, using filepath.IsLocal or filepath.Rel, and by extracting into os.MkdirTemp instead of the shared temp dir.

---

## nilocloud Gerrit Checks endpoints (/v1/gerrit/checks, /checks/log, /checks/run) have no authentication

**Fingerprint:** `nilocloud/gerrit-checks-unauthenticated`  
**Claimed root cause:** Gerrit checks routes were registered without authMiddleware or any other identity or authorization check, and rely on CORS (Allow-Origin https://code.nile.ag) as if it were access control, on a service deployed with --allow-unauthenticated.

Source-level: the three Gerrit Checks routes are wrapped only by gerritCorsMiddleware, which just sets CORS headers (and CORS is not an access control for non-browser callers). Every other sensitive route in the same mux uses authMiddleware (robot token). The nilocloud Cloud Run service is deployed with --allow-unauthenticated. An unauthenticated caller can therefore (a) POST /v1/gerrit/checks/run?change=N&patchset=M to enqueue a verify Cloud Task, which first deletes queued verify tasks whose names start with change-N-ps-, marks pending runs for that change stale in Firestore, then enqueues a new task and rewrites GCS state with a bumped attempt number; (b) GET the per-patchset checks state JSON; (c) GET check logs by externalId. Impact is bounded by source: the ref is always built server-side by RefForChange as refs/changes/NN/N/M from validated positive ints, the task is the same verify that webhook.go:169 and reconcile.go:121 already trigger for every uploaded patchset, and ValidExternalID restricts the log id to the anchored regex ^\d+-\d+-\d+-(known check name)$, so there is no path traversal in LogPath. The verify task runs checks (codegen, lint, test) on whatever the Gerrit change contains, but anyone able to upload a change already gets that automatically, so forged verifies do not create new code-execution reach for an outsider. Real effects are limited to unauthenticated CI cost and queue abuse, cancel-and-replace of legitimate queued verifies and attempt counter churn (integrity and availability of CI status), and disclosure of CI state and log content. Whether this is a meaningful boundary violation depends on facts not in source: network exposure of the service (Cloud Run ingress, any fronting proxy or IAP), whether the checks bucket logs contain sensitive output, and whether the Gerrit instance itself is internet reachable.

### Trace
1. **entrypoint** `backend/go/nilocloud/internal/handlers.go:26` (Resolver.ServeHTTP) — Routes /v1/gerrit/checks, /checks/log, /checks/run (lines 26-28) are registered with gerritCorsMiddleware only; no authMiddleware, unlike the webhook, events and subscription routes above them.
2. **propagation** `backend/go/nilocloud/internal/middleware.go:24` (gerritCorsMiddleware) — Only sets Access-Control-* headers and short-circuits OPTIONS; performs no authentication or origin enforcement on the actual request.
3. **propagation** `backend/go/nilocloud/internal/gerrit.go:78` (Resolver.gerritChecksRunHandler) — Requires POST and positive integer change and patchset query params (lines 85-103), then calls task.CreateVerify at line 115 without any caller identity check.
4. **propagation** `backend/go/gerrit/task/checks.go:64` (CreateVerify) — deleteQueuedTasks removes queued verify tasks for the change (line 64), a new Cloud Task is enqueued, queued runs are superseded in Firestore (line 83), and initial SCHEDULED state is written to GCS (line 93). Ref is built by RefForChange from integers only.
5. **sink** `backend/go/nilocloud/internal/gerrit.go:151` (Resolver.gerritChecksLogHandler) — Reads and returns GCS log object for an id that passes the anchored ValidExternalID regex (line 137); the checks state handler similarly reads state at line 48. Both return data to any caller.

### Verified evidence
- `backend/go/nilocloud/internal/handlers.go:10` — Contrast: sentry/grafana webhooks and subscriptions are wrapped in authMiddleware; the Gerrit checks routes at lines 26-28 are not.
- `backend/go/nilocloud/cloudbuild.yaml:45` — nilocloud is deployed to Cloud Run with --allow-unauthenticated (deployment config as written; live IAM and ingress not verified).
- `backend/go/gerrit/checks/checks.go:77` — externalIDRe is anchored and limited to digits plus a known check-name alternation, so log reads cannot traverse paths.
- `backend/go/gerrit/task/task.go:270` — RefForChange builds the ref from integers only, so an attacker cannot select an arbitrary ref or repo.
- `backend/go/gerrit/functions/webhook/webhook.go:169` — The same CreateVerify is invoked automatically for every uploaded patchset, so the forged trigger adds no new code-execution capability for outsiders.

### Exact blockers
- Cloud Run ingress and IAM for nilocloud (and any fronting proxy or IAP) are not visible in source; --allow-unauthenticated in cloudbuild.yaml may be overridden or the service may sit behind an internal-only network.
- Sensitivity of content in the GCS checks bucket (state JSON and full check output logs) is unknown; it may include source snippets or env-derived output.
- Cloud Tasks queue and agent concurrency or cost limits that bound the abuse impact are not in source.

### Resolution plan
- **Local (dummy data, isolated):** Source-only: confirm via a unit test using httptest against Resolver.ServeHTTP with a stubbed task client that an unauthenticated POST to /v1/gerrit/checks/run reaches CreateVerify; then decide on a fix such as requiring a Gerrit-issued or shared-secret token, a Google ID token check, or restricting ingress.
- **Owner-observed deployment check:** Owner check, read-only: run gcloud run services describe nilocloud --region europe-west4 and inspect ingress annotation and the IAM policy for allUsers roles/run.invoker; confirm whether code.nile.ag or the service URL is reachable from outside the corporate network. Review a sample of objects in the checks bucket for sensitive content. Do not probe the live service with forged requests against real changes.

---

## Horus /horus Slack command and unblock action have no operator allowlist or approval step beyond the Slack signature

**Fingerprint:** `nilocloud/horus-no-operator-allowlist`  
**Claimed root cause:** Authorization for privileged CI/CD operations is delegated entirely to Slack workspace membership. After verifySlack, HandleSlack dispatches on the text field with no identity-based authorization (no user_id, channel_id or team_id check), and task.CreateDeploy, CreateMigrate, CreateBuildMarket and CreateAndroidBuild enqueue Cloud Tasks without any actor check. handleSlackActions ignores cb.User and the channel.

The /horus slash-command endpoint and the Slack interactive-actions endpoint authenticate only that the request was signed by Slack (SLACK_SIGNING_SECRET). Nothing in nilocloud or the gerrit task layer checks who invoked the command. user_name is read from the form and used only as a display or attribution string. Any Slack workspace member who can invoke /horus can enqueue production deploys, production DB migrations (including direction down), Play Store Android builds, and market image builds. Any member who can click the Grafana unblock button can unblock a consumer; the interaction user in the callback is never consulted. Source shows no per-user, per-channel, per-team or approval gate on any path. Whether this is a real violation depends on the intended authority of Slack workspace members and on Slack-side command or channel restrictions, which are deployment facts outside source.

### Trace
1. **entrypoint** `backend/go/nilocloud/internal/handlers.go:14` (mux route POST /v1/slack/commands/horus) — Slash-command endpoint reachable by Slack. A request is accepted if it carries a valid Slack signature.
2. **propagation** `backend/go/nilocloud/internal/slack.go:65` (slackHorusHandler / verifySlack (lines 21-39)) — Only control is the HMAC signing-secret check. The form is parsed and passed to horus.HandleSlack at line 78. No user or channel allowlist.
3. **propagation** `backend/go/nilocloud/internal/horus/horus.go:47` (HandleSlack) — Reads text and user_name (lines 48-49) and dispatches on parts[0] with no identity check. user_name is passed as an attribution string only.
4. **propagation** `backend/go/nilocloud/internal/horus/horus.go:124` (handleDeploy / handleMigrate (line 202) / handleBuild*) — Accepts env=production from arbitrary args, validated only against a service-name list. Calls task.CreateDeploy, CreateMigrate (direction up or down), CreateBuildMarket and CreateAndroidBuild directly.
5. **propagation** `backend/go/gerrit/task/migrate.go:63` (CreateMigrate (CreateDeploy at gerrit/task/deploy.go:107 is the sibling)) — Validates only the service name, then enqueues a Cloud Task (createTask) that runs the migration or deploy against the chosen environment. actor/triggerName is only recorded as TriggerName. No authorization or approval.
6. **sink** `backend/go/nilocloud/internal/slack.go:112` (handleSlackActions block-action loop) — Signed interaction callback. For ActionIDUnblockConsumer it calls GrafanaResolver().UnblockConsumer (line 121) using service, consumer id and cursor from the button value. cb.User and the channel are never checked.

### Verified evidence
- `backend/go/nilocloud/internal/slack.go:28` — Signature verification uses SLACK_SIGNING_SECRET (key name only). It is the sole authentication on the horus, actions and events handlers.
- `backend/go/nilocloud/internal/horus/horus.go:70` — deploy, build, migrate, test and verify handlers all receive only userName for attribution. No allowlist, role or approval logic exists anywhere in the horus package (grep for allow, authori, user_id, channel_id, team_id, approv returned nothing).
- `backend/go/nilocloud/internal/horus/horus.go:186` — Production and down are accepted as plain args for migrate, with no extra confirmation.
- `backend/go/gerrit/task/deploy.go:139` — The actor is stored only as TriggerName. The task layer has no authorization.
- `backend/go/AGENTS.md:136` — The Horus section describes only the Slack bot and mise CLI parity. It states no authorization model, so the intended operator authority is undocumented in source.

### Exact blockers
- Intended authority of Slack workspace members is a design fact outside source. If /horus is meant to be usable by all members of a private, trusted engineering workspace or channel, this is accepted design, not a violation.
- Slack app configuration is not in source. The slash command's availability (restricted channels or user groups, workspace guest/external-member policy, Slack Connect) is unknown.
- Downstream enforcement is not in source. The worker may require Gerrit/IAM-level or environment-level protections for production, and Cloud Run ingress or IAM for the endpoint is unknown.

### Resolution plan
- **Local (dummy data, isolated):** Source-only check already done: no allowlist or approval exists in nilocloud/internal/horus or gerrit/task create paths. A further local check could run unit tests against HandleSlack with a stub task layer, but this is unnecessary because the absence of a check is already visible in source.
- **Owner-observed deployment check:** Owner-observed, read-only. (1) In the Slack app admin console, list who can use /horus: which workspaces and channels, whether guests, restricted accounts or Slack Connect members are in them, and whether the command is limited via Slack app permissions or workflow restrictions. (2) Confirm with the platform owners whether any workspace member is intended to be able to queue production deploys and migrate down. (3) Check the Cloud Run IAM and ingress settings on nilocloud and the Cloud Tasks consumer's production guards in the infra config. Do not send live probes or trigger production tasks.

---

## nilocloud: one NILO_ROBOT_TOKEN gates both inbound Sentry/Grafana webhooks (token in URL query) and the browser-callable consumer-unblock action

**Fingerprint:** `nilocloud/shared-robot-token-webhook-unblock`  
**Claimed root cause:** A single shared static secret (NILO_ROBOT_TOKEN) authorizes both low-privilege inbound webhook delivery (credential carried in a URL query string) and a state-changing operational action (consumer unblock/skip), with no scoping, rotation separation or constant-time comparison.

authMiddleware in nilocloud uses a single env secret, NILO_ROBOT_TOKEN, for two different purposes. For /v1/webhooks/* it is read from the query string (?robotToken=), so it sits in webhook URLs configured in third-party tools (Sentry, Grafana) and potentially in request logs. For /v1/events/unblock it is read from 'Authorization: Bearer robotToken=<token>', and the endpoint is called directly from a browser (Grafana table action, CORS allow-origin https://obs.nile.ag). A successful call publishes a consumer-unblock Pub/Sub job. The job handler then advances the named consumer's cursor, which permanently skips the event at expected_cursor+1, and posts a Slack notice. Any holder of the webhook URL (Sentry/Grafana config readers, log readers) therefore also holds authority to skip events in ledger, trader, administrator and other consumers. Source review shows no per-purpose credential separation and a non-constant-time compare. TrimPrefix also means a bare token without the 'Bearer robotToken=' prefix is accepted. Whether this crosses a real trust boundary depends on who can read the Sentry/Grafana webhook configuration, the Grafana action config, and the Cloud Run request logs. Those are deployment facts not visible in source. Same-principal ops staff holding both capabilities would not be a finding. Hardening-grade unless the token is shown to leak to a lower-trust party.

### Trace
1. **entrypoint** `backend/go/nilocloud/internal/handlers.go:23` (Resolver.ServeHTTP) — Route /v1/events/unblock (all methods, so OPTIONS preflight works) wrapped in grafanaCorsMiddleware(authMiddleware(unblockConsumerHandler)); reachable from a browser on obs.nile.ag. Webhook routes at lines 9-10 use the same authMiddleware.
2. **propagation** `backend/go/nilocloud/internal/middleware.go:40` (authMiddleware) — /v1/webhooks* branch (lines 40-53): token taken from URL query robotToken and compared with != to NILO_ROBOT_TOKEN; empty env returns 500.
3. **propagation** `backend/go/nilocloud/internal/middleware.go:55` (authMiddleware) — /v1/events* branch (lines 55-67): the same env var is compared (non-constant-time) against the Authorization header after TrimPrefix 'Bearer robotToken='; a bare token also passes. No scoping by purpose.
4. **propagation** `backend/go/nilocloud/internal/grafana.go:23` (Resolver.unblockConsumerHandler / handleUnblockConsumer) — After auth, service, consumer_id and expected_cursor are taken from the query string (lines 36-52) with no further authorization or allow-list; calls GrafanaResolver().UnblockConsumer.
5. **sink** `backend/go/nilocloud/internal/grafana/handlers.go:154` (Resolver.UnblockConsumer) — Publishes a consumer-unblock UnblockMessage to Pub/Sub (line 165). The job handler in internal/cloud.go (lines 126-155) then calls unblock<Service>Consumer, which skips the event, and notifyEventSkipped posts to Slack.

### Verified evidence
- `backend/go/nilocloud/internal/middleware.go:41` — Webhook credential read from URL query parameter robotToken.
- `backend/go/nilocloud/internal/middleware.go:49` — Plain != comparison on the secret (not subtle.ConstantTimeCompare).
- `backend/go/nilocloud/internal/middleware.go:62` — TrimPrefix on 'Bearer robotToken=' does not enforce the prefix; the same NILO_ROBOT_TOKEN value authorizes the unblock action.
- `backend/go/nilocloud/internal/middleware.go:13` — CORS allows only https://obs.nile.ag. This is a browser-origin constraint, not an authentication control, and it confirms the endpoint is called from browser JavaScript (so the token is held in Grafana action config).
- `backend/go/nilocloud/internal/handlers.go:13` — Sibling Slack routes (events/slack, commands/horus, webhooks/slack/actions) are not wrapped by authMiddleware; they presumably use their own Slack signature checks, which were not reviewed here and are out of scope for this candidate.

### Exact blockers
- Who can read the Sentry/Grafana webhook URL, the Grafana action configuration (which holds the unblock bearer token), and Cloud Run request logs (which may record the query string) is not visible in source.
- It is unknown whether Sentry/Grafana admins or log readers already hold equivalent operational authority to skip consumer events. If they do, this is same-principal authority and not a boundary violation.
- Network exposure and ingress of the nilocloud Cloud Run service (public or restricted) is not in source.

### Resolution plan
- **Local (dummy data, isolated):** Source-only: confirm in a unit test (owner-run, no network) that authMiddleware accepts a bare token on /v1/events/unblock and that no other check exists between the middleware and pubsub.SendMessage. Grep deployment manifests for where NILO_ROBOT_TOKEN is injected and whether the same secret is used for any other service.
- **Owner-observed deployment check:** Owner-observed, non-destructive: (1) list who has view access to the Sentry integration webhook URL and the Grafana contact point and table-action configuration; (2) check whether Cloud Run request logs for nilocloud record query strings and who has logging.viewer on that project; (3) check Cloud Run ingress and IAM for the service. If a lower-trust party (vendor, broad log readers, non-ops Grafana editors) can read the token, upgrade to a confirmed medium finding. Otherwise downgrade to hardening: use separate per-purpose tokens, move the webhook token into a header, and use subtle.ConstantTimeCompare.

---

## Internal gRPC services trust caller identity from unauthenticated metadata; reachability depends on Cloud Run exposure

**Fingerprint:** `thoth/grpc-identity-from-plaintext-metadata`  
**Claimed root cause:** Service-to-service identity propagation uses plaintext gRPC metadata (user-firebase-id) that the server accepts as authoritative. Reserved robot IDs need no proof, and the Firebase-lookup fallback runs without verifying the token. Authentication therefore rests entirely on network or IAM isolation, which the deploy config does not enforce (--allow-unauthenticated).

The shared gRPC server (thoth.Resolver.ServerGRPC) registers no transport credentials and no authentication interceptor, only jetgrpc and serverUnaryInterceptor. serverUnaryInterceptor builds the request user from the caller-supplied metadata key user-firebase-id. The reserved values Robot, RobotFreshMark, RobotInputs, RobotVilla and Unauthed map directly to in-memory users with no credential check. Robot users have PartyTypeAdmin, an AdminProfileID, and for Robot also RoleRobot. Any other value goes to the default branch. There, an optional user-auth-token is only tried via UserFromToken, and a failure is ignored. The code then falls back to ContextWithUser, which loads the user by ID from Firebase (authClient.UserByID) with no credential at all. So the fallback is reachable whenever the token is empty, invalid or mismatched, which means a caller who knows a Firebase UID can act as that user. Source shows no other auth layer: all six services (librarian, ledger, harvester, trader, postman, administrator) call ServerGRPC() and add nothing else in main.go. Their cloudbuild.yaml files deploy with --allow-unauthenticated and no ingress restriction flag. Whether an external attacker can actually reach these ports (Cloud Run ingress setting, any out-of-band IAM change, network path) cannot be established from source. I found no source control that blocks the claim. This is a deployment fact, so the finding stays needs_validation and is not confirmed.

### Trace
1. **entrypoint** `backend/go/thoth/handlers.go:181` ((*Resolver).serverUnaryInterceptor) — Reads user-firebase-id and user-auth-token from incoming gRPC metadata, which is attacker-controllable if the service port is reachable.
2. **propagation** `backend/go/thoth/handlers.go:184` ((*Resolver).serverUnaryInterceptor switch userFID) — Reserved IDs (Unauthed, Robot, RobotFreshMark, RobotInputs, RobotVilla) are turned into robot or admin users without any credential check.
3. **propagation** `backend/go/thoth/handlers.go:202` ((*Resolver).serverUnaryInterceptor default branch) — The token check is optional. If the token is empty, invalid or mismatched, the code falls through to ContextWithUser with the claimed ID.
4. **sink** `backend/go/thoth/handlers.go:135` (ContextWithUser) — Loads the user by claimed Firebase UID (authClient.UserByID) and installs it in the request context via auth.NewContexWithUser, so handlers authorize as that user.

### Verified evidence
- `backend/go/thoth/handlers.go:59` — ServerGRPC options contain no grpc.Creds and no auth interceptor; the chain is jetgrpc plus serverUnaryInterceptor only.
- `backend/go/auth/auth.go:186` — UsrRobot returns an admin-party user (AdminIDNile) with RoleRobot; the other robots (lines 207 to 242) are admin-party too.
- `backend/go/ledger/cmd/server/main.go:68` — Services use thothResolver.ServerGRPC() unmodified; the same call is in librarian:80, harvester:72, trader:63, postman:76 and administrator:70.
- `backend/go/ledger/cloudbuild.yaml:45` — Cloud Run deploy uses --allow-unauthenticated with no ingress restriction flag; the same applies to the other services (librarian:40).
- `backend/go/thoth/handlers.go:120` — Clients dial with TLS when the host contains 443, which gives encryption but no caller authentication.

### Exact blockers
- Cloud Run ingress setting (all, internal, internal-and-cloud-load-balancing) and any out-of-band IAM or invoker changes for each gRPC service are not in source.
- Whether the service URLs are discoverable and reachable from the internet, and whether a front proxy or VPC controls sit in front of them, is not in source.
- Source cannot show which handlers behind this interceptor expose sensitive operations, so impact depends on a service-by-service check.

### Resolution plan
- **Local (dummy data, isolated):** Source review only, no execution: list each gRPC service's handlers and the authorization checks they make on auth.UserFromContext. Check whether any handler treats RoleRobot or an admin PartyType as sufficient for sensitive reads or writes. Optionally write a unit test with an in-process gRPC server (bufconn) built from ServerGRPC that sends user-firebase-id=Robot and confirms the handler context holds the admin robot user. No network and no live Firebase.
- **Owner-observed deployment check:** The owner should run read-only gcloud queries: gcloud run services describe <svc> --region europe-west4 and check the ingress annotation (run.googleapis.com/ingress), then gcloud run services get-iam-policy <svc> and check whether allUsers holds roles/run.invoker. Use the same project that the deploy cloudbuild.yaml targets. Also check whether the service URLs appear in any public DNS or client config. Do not send live requests with forged metadata. If ingress is 'internal' or the invoker is restricted to the caller services' service accounts, downgrade or reject. If it is 'all' with allUsers invoker, upgrade to confirmed with high or critical severity, since robot admin identity gives cross-tenant access.

---



---

# Client leads (run-2)

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

