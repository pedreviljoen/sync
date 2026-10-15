# Combined findings detail

See run-specific files for full traces:
- Backend: `../run-1/FINDINGS-DETAIL.md` (9 confirmed)
- Client: `../run-2/FINDINGS-DETAIL.md` (1 confirmed; the stored XSS is in `../run-2/findings.json` as `c1-market-form-description-stored-xss-profile-name`; note the detail file includes only confirmed medium+ records)

---

# Backend findings (run-1)

All observations are source-level; no code was executed. Secret values are intentionally omitted.

## [HIGH] Any authenticated user can set roles and password on a user account via the SetUser form (self-service role escalation, cross-user password reset)

**Fingerprint:** `H5-setuser-self-role-escalation`  
**Root cause:** The authorization gate for FormTypeSetUser compares the caller's identity to a client-controlled email field rather than to the target user (firebase ID) being modified. No role-assignment permission check (permissions.ProfileRoles) is enforced server-side, and the administrator Set/Update path trusts its caller completely.  
**Intended behavior:** A user may update only their own non-privileged profile attributes (name, mobile, theme, market metric, possibly their own password) and the target ID must be forced to the caller's UID. Role changes must require an admin with the ProfileRoles write permission, enforced server-side. Password or role changes for other users must be admin-only.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:1146` (mutationResolver.Form (GraphQL mutation, any authenticated user)) — Starts with chks = [PartyTypes(Admin)]. In the FormTypeSetUser case (1149-1153) it appends auth.Email(f.Value) for the client-supplied field with ID UserEmail. auth.Checks passes if ANY check passes (auth/checks.go:40), so a caller supplying their own email passes. FormNew has the identical logic at ~1218-1224.
2. **propagation** `backend/go/api/internal/graph/form_input.go:130` (formInput / handleSetUser) — Dispatches FormTypeSetUser to handleSetUser (defined ~515), which calls customers.UserInput(fields) and, for a non-new user (firebase ID present), builds ToUserUpdateInput and calls Administrator.Set(InpUserUpdate).
3. **propagation** `backend/go/api/internal/graph/customers/user.go:166` (UserInput) — Parses the client-supplied firebase ID (userFirebaseID), profileID, password, name, mobile and roles (userRole -> getRoleType) with no role or permission validation. The email field is parsed but is not used as the update target (comment at ~line 223: 'Email is user id, it will be ignored').
4. **propagation** `backend/go/administrator/internal/ops/ops.go:42` (Resolver.Set -> maybeUpdateUsers) — Administrator Set dispatches UserUpdateInput to users.Update with no auth.Checks on the caller (grep of administrator for auth checks finds none on this path).
5. **sink** `backend/go/administrator/internal/ops/users/update.go:66` (updateTx) — Looks up the user by the client-supplied ID (line 56), calls client.UpdateUserPassword(ID, password) (66), then userroles.MatchTx(userDB.Email, input.Roles()) (85), which inserts and deletes rows in user_roles for the target user. prepareClaimsForUserMutation (~92) then pushes the new roles to Firebase custom claims after commit.

### Evidence
- `backend/go/api/internal/graph/schema.resolvers.go:1149` — FormTypeSetUser check is OR(admin party type, caller email equals client-supplied email field). The email is not bound to the target user ID.
- `backend/go/api/internal/graph/schema.resolvers.go:1221` — FormNew duplicates the same weak check, so the sibling mutation is equally affected.
- `backend/go/auth/checks.go:40` — auth.Checks returns nil if ANY check passes, so the Email check alone is sufficient.
- `backend/go/api/internal/graph/customers/user.go:54` — access.Has(permissions.ProfileRoles, Write) only controls whether the role field is rendered or disabled in the form; it is not enforced on submit. The only other use of ProfileRoles is its definition in access/permissions/permissions.go:28.
- `backend/go/api/internal/graph/customers/user.go:166` — UserInput accepts the firebase ID, roles and password from client fields with no checks beyond format validation.
- `backend/go/administrator/internal/ops/users/update.go:85` — Roles are replaced for userDB.Email, resolved from the client-supplied ID rather than the caller. UpdateUserPassword at line 66 is also keyed to that ID. validateUpdateInput only checks that the user exists and that ID and profile ID are present.
- `backend/go/administrator/internal/ops/users/users.go:80` — Claims are rebuilt from the DB roles (auth.WithUserUpdate(... user.Roles)) and pushed to the auth service, so the escalated roles take effect on the user's token/claims.
- `backend/go/access/access.go:48` — RoleSuper grants all permissions except tech-only ones, which demonstrates that role values drive authorization decisions.

### Principal and resource
A low-privilege authenticated buyer or seller who wants admin-level roles on their own account, or who wants to reset another user's password.

### Native input / instructions (do not run against a live target)
- `mutation { form(input:{type:SetUser, fields:[{id:1,value:"<own email>"},{id:-3,value:"<own firebase uid>"},{id:-2,value:"<own profile id>"},{id:7,values:["Super"]}]}) { ... } }`
- Authenticate as an ordinary buyer or seller.
- Send the Form (or FormNew) mutation with type SetUser, the caller's own email in field 1 (to satisfy auth.Email), the caller's own firebase UID in field -3, the caller's profile ID in field -2, and the desired role(s) in field 7.
- Refresh the token so the new claims are issued.
- To target another user, set field -3 to that user's UID and field 2 to the new password while still sending the attacker's own email in field 1.

### Observed result and invariant proven
Source-level observation only; nothing was executed. The only gate is OR(Admin, email equals attacker-supplied field), and the attacker controls the field. No downstream layer (customers.UserInput, administrator.Set, users.Update, userroles.MatchTx) re-checks the caller or the ProfileRoles permission, and the target comes from a client-supplied ID.

### Conditions and containment
- authentication_level: Attacker needs any valid authenticated session (any party type: buyer, seller or admin).
- data_state: For self-escalation the attacker needs their own firebase UID and profile ID (available to them via the SetUser form or their token). To reset another user's password or roles they need that user's firebase UID, which is not a secret but is not necessarily easy to obtain.
- system_configuration: Assumes the auth service applies the pushed custom claims to subsequent tokens, which is the evident design. The deployed token refresh behaviour was not observed.

### Remediation and regression case
Server-side enforcement: for FormTypeSetUser in both Form and FormNew, allow the call only if the caller is an admin or the supplied firebase ID equals the caller's own UID. Ignore the roles field unless access.Has(ctx, permissions.ProfileRoles, permissions.Write) is true. Require admin, or a current-password or re-auth flow, to change a password, and never for other users. Ideally add an authorization check in the administrator service as defence in depth.

```
// After UserInput(): enforce in handleSetUser
if !access.Has(ctx, permissions.ProfileRoles, permissions.Write) { user.roles = nil /* keep existing roles */ }
cu := auth.UserFromContext(ctx)
if cu.PartyType != users.PartyTypeAdmin && user.id != cu.UID { return errors.New("not authorized", codes.CodeUnauthorized) }
```
(file: `backend/go/api/internal/graph/customers/user.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [HIGH] Unauthenticated GraphQL access to any operation by naming it Signup/SignUp/ValidateCurrentToken

**Fingerprint:** `H5-unauth-opname-bypass`  
**Root cause:** The public-operation allowlist is keyed on op.Operation.Name (client-controlled label) instead of the actual root fields being executed, and unauthenticated state is otherwise enforced only by per-resolver checks that some resolvers omit.  
**Intended behavior:** Only the signup/token-validation root fields should be reachable without a valid identity; all other fields should be rejected for the unauthed user regardless of the operation name chosen by the client.

### Ordered trace
1. **entrypoint** `backend/go/api/cmd/server/main.go:120` (gqlgen server setup) — Public GraphQL endpoint; the only auth is AroundOperations(AuthOperation()). No AroundFields/AroundRootFields or schema directives are registered.
2. **propagation** `backend/go/auth/auth.go:379` (Client.AuthOperation) — Authorization header read from the request, passed to userFromIDToken.
3. **propagation** `backend/go/auth/auth.go:466` (Client.userFromIDToken) — The literal token 'unauthenticated' returns UsrUnauthed() (FirebaseUID FIDUnauthed, ProfileID 0) with no credential check; checkPlatform also returns nil for unauthed users (auth.go:495).
4. **propagation** `backend/go/auth/auth.go:404` (Client.AuthOperation) — Unauthed users are rejected only if op.Operation.Name is not in publicOperations (auth.go:422: ValidateCurrentToken, SignUp, Signup). The name is client-chosen, so naming any operation 'Signup' passes; the context is then populated with the unauthed user and next(ctx) runs the real selection set (auth.go:410-417).
5. **propagation** `backend/go/thoth/handlers.go:184` (serverUnaryInterceptor) — Downstream gRPC services accept FIDUnauthed from metadata and install UsrUnauthed without rejecting.
6. **sink** `backend/go/api/internal/graph/schema.resolvers.go:2786` (queryResolver.LogisticsDoc) — Resolver has no auth.Checks; it queries Ledger.Shipments filtered by the attacker-supplied profileID and date and returns a packing list including product, case and location data and shipping addresses (logisticsdocs.go:54+, shipments.go:2597). Ledger.Shipments has no user check (ledger/internal/ops/ops.go:971).

### Evidence
- `backend/go/auth/auth.go:404` — Allowlist check uses op.Operation.Name, the only gate for the unauthed user.
- `backend/go/auth/auth.go:422` — publicOperations list is a set of operation names, not field names.
- `backend/go/auth/auth.go:466` — The string 'unauthenticated' is accepted as a token yielding UsrUnauthed.
- `backend/go/api/cmd/server/main.go:120` — AuthOperation is the only registered auth middleware for the API.
- `backend/go/api/internal/graph/schema.resolvers.go:1932` — UpdateClaims has no auth check; r.updateClaims (graph/claims.go:12) looks up users by arbitrary emails and rewrites Firebase claims via AuthClient.UpdateUsers (auth.go:837).
- `backend/go/api/internal/graph/schema.resolvers.go:1130` — UploadPop has no auth check and writes a proof-of-payment URL for an arbitrary quoteID via Trader.Set (downstream authorization not verified).
- `backend/go/api/internal/graph/schema.resolvers.go:2800` — Sibling resolvers such as Shipments (line 2796 area) do call auth.Checks, showing the per-resolver check is the intended control and LogisticsDoc omits it.

### Principal and resource
Anonymous internet client with no account.

### Native input / instructions (do not run against a live target)
- `POST /query with header Authorization: unauthenticated and body {"operationName":"Signup","query":"query Signup { logisticsDoc(logDocType: SELLER_PACKING_LIST, profileID: 1, date: \"2026-01-01T00:00:00Z\") { info { title } tables { rows { cells } } } }"}`
- Send the request with the literal Authorization value 'unauthenticated' and X-Platform header of any value (checkPlatform returns early for unauthed users).
- Vary profileID and date to enumerate seller shipment data across tenants.
- Optionally issue mutation Signup { updateClaims(userEmails: ["x@y"]) } or uploadPOP the same way.

### Observed result and invariant proven
Source-level observation, not a runtime result: the unauthed user passes auth.go:404 because the operation name matches the allowlist, and LogisticsDoc and Ledger.Shipments contain no user check on the path.

### Conditions and containment
- network_routing: The API GraphQL HTTP endpoint is reachable by the attacker (Cloud Run ingress/IAM not visible in source; the endpoint is the client-facing API).
- authentication_level: None required: Authorization: unauthenticated plus operationName Signup.

### Remediation and regression case
Enforce the allowlist on the actual root field names (inspect op.Operation.SelectionSet) or use an AroundRootFields/directive that rejects the unauthed user for every field except signUp/validateCurrentToken; also remove the plain 'unauthenticated' sentinel from client-reachable token handling; add auth.Checks to LogisticsDoc, UpdateClaims and UploadPop.


Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [HIGH] nilocloud /v1/subscriptions/* routes have no effective authentication (discarded r.WithContext result); unauthenticated callers can drive Pub/Sub job dispatch

**Fingerprint:** `nilocloud/subscriptions-auth-noop`  
**Root cause:** The middleware branch for /v1/subscriptions does `r.WithContext(auth.NewContexWithUser(...UsrRobot()))` and drops the result (http.Request.WithContext returns a new request). Even if it had been used, it would only inject a robot identity into the context rather than verify the caller. No Pub/Sub push OIDC token verification exists anywhere in the nilocloud handler chain (handlers.go mux, main.go has only sentryhttp wrapping).  
**Intended behavior:** Only Google Pub/Sub push (and Cloud Build via Pub/Sub) should be able to invoke these handlers: verify the Google-signed OIDC bearer token (issuer accounts.google.com, audience = service URL, email = the push subscription service account), or at minimum a shared secret like the sibling prefixes, and reject otherwise with 401.

### Ordered trace
1. **entrypoint** `backend/go/nilocloud/internal/handlers.go:18` (Resolver.ServeHTTP) — Public HTTP route POST /v1/subscriptions/nilo wrapped only by authMiddleware (cloudbuild route at line 19 likewise). Service is exposed unauthenticated at the Cloud Run layer per cloudbuild.yaml.
2. **propagation** `backend/go/nilocloud/internal/middleware.go:70` (authMiddleware) — Branch for /v1/subscriptions (line 69) calls r.WithContext(...) and discards the result; no rejection path exists, so next.ServeHTTP runs for every caller.
3. **propagation** `backend/go/nilocloud/internal/pubsub.go:36` (Resolver.pubSubHandler) — Reads the body, unmarshals WrappedMessage with no signature/OIDC/secret verification and passes message.data to handlePubSubMessage.
4. **propagation** `backend/go/nilocloud/internal/cloud.go:63` (Resolver.handlePubSubMessage) — Switches on attacker-chosen job.Type: nexport-start (line 64), nexport-pause-consumers (86), nexport-export/import/finish/resume, consumer-unblock (125) with attacker-chosen service/consumer/expected_cursor, mache-restore (157) with attacker-chosen store/revision.
5. **sink** `backend/go/nilocloud/internal/consumers.go:73` (unblock*/pause*Consumers and recoverLedgerMacheStore (mache.go:18)) — Issues privileged gRPC Jobs calls (JobUnblockConsumer, JobPauseConsumer, JobRestoreShipmentsStores/JobRestoreProfilesStore) to administrator, ledger, trader, postman, harvester, librarian; the Jobs handlers perform no user/role check.

### Evidence
- `backend/go/nilocloud/internal/middleware.go:70` — Result of r.WithContext discarded; only code on the /v1/subscriptions branch.
- `backend/go/nilocloud/internal/middleware.go:24` — Contrast: /v1/webhooks (line 43), /v1/events (54) and /v1/mache (73) branches compare a token and return 401.
- `backend/go/nilocloud/internal/handlers.go:18` — Only authMiddleware wraps the nilo subscription route; no other middleware in handlers.go or cmd/server/main.go (line 181 wraps only with sentryhttp).
- `backend/go/nilocloud/internal/pubsub.go:16` — Handler has no auth/OIDC check, parses and dispatches the body.
- `backend/go/nilocloud/internal/cloudbuild.go:21` — Cloud Build handler likewise has no verification.
- `backend/go/nilocloud/cloudbuild.yaml:45` — Deploy step uses --allow-unauthenticated.
- `backend/go/thoth/handlers.go:249` — clientUnaryInterceptor forwards a user FID only if present in context; server interceptor (line 160) tolerates an empty user and ops Jobs (e.g. ledger/internal/ops/ops.go:1058) check no role, so downstream does not gate the call.

### Principal and resource
Unauthenticated internet client with the nilocloud service URL.

### Native input / instructions (do not run against a live target)
- `POST /v1/subscriptions/nilo with body {"message":{"data":"<base64 of {\"type\":\"nexport-pause-consumers\",\"info\":\"<base64 JSON string of a database name>\"}>","id":"1"},"subscription":"x"} and no Authorization header`
- `consumer-unblock variant: data = base64 of {"type":"consumer-unblock","service":"ledger","consumer":"<id>","expected_cursor":<n>}`
- Send the POST without any credentials.
- Handler returns 200 and the dispatched job runs; a failing job returns 500 with errors logged.

### Observed result and invariant proven
Source-level observation only, not a runtime result: the middleware has no rejecting path for /v1/subscriptions, the handler performs no verification, and the dispatch reaches the gRPC Jobs calls. Nothing was executed.

### Conditions and containment
- network_routing: Attacker must reach the nilocloud Cloud Run URL; source (cloudbuild.yaml --allow-unauthenticated; Slack/Sentry webhooks must also be reachable) indicates it is public, but live IAM/ingress settings were not observed.
- environmental_dependency: Attacker needs the service URL and valid job JSON (types/consumer names are visible in the repository).

### Remediation and regression case
Verify the Pub/Sub push OIDC token (google.golang.org/api/idtoken.Validate with audience and expected service-account email) for /v1/subscriptions/*, returning 401 on failure; also set the Cloud Run service to require authentication for these paths where feasible (separate internal service or IAM invoker only for the push service account), and fix the discarded WithContext by assigning `r = r.WithContext(...)` only after verification.

```
if strings.HasPrefix(r.URL.Path, "/v1/subscriptions") {
	if err := verifyPubSubOIDC(r); err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	r = r.WithContext(auth.NewContexWithUser(r.Context(), auth.UsrRobot()))
}
```
(file: `backend/go/nilocloud/internal/middleware.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] editShipment/editShipmentItem authorize by party type only, with no check that the caller's profile is a party to the shipment (cross-tenant write)

**Fingerprint:** `H5-editshipment-no-ownership`  
**Root cause:** EditShipmentAuthorised (auth_checks.go:127) gates on auth.PartyTypes(...) and shipment-type predicates (smt.HasSeller(), smt.HasBuyer()) only. It has no ownership check (ShipmentAuthorized/IsParty, or auth.PartyTypeForID). fetchLedgerShipment does not scope by caller profile, and the edit handlers and Ledger.Set take no user identity.  
**Intended behavior:** A Seller or Buyer may mutate a shipment only if their profile is a party to it (shipment.IsParty(user.ProfileID)), as enforced for reads by ShipmentAuthorized and by EditShipmentAuthorized (auth_checks.go:182) on the read path. Admins are exempt.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:1595` (mutationResolver.EditShipment) — Authenticated GraphQL mutation editShipment(input: EditShipmentInput!) (schema.gql:10099). input.ID is a caller-supplied shipment KSUID.
2. **propagation** `backend/go/api/internal/graph/shipments.go:59` (Resolver.fetchLedgerShipment) — Parses the ID and fetches the shipment via Ledger.Shipments with NewShipmentFilterByIDs (shipments.go:83). The filter has no caller-profile scoping.
3. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:1608` (mutationResolver.EditShipment) — Calls EditShipmentAuthorised(ctx, input, smt). The same check is used at schema.resolvers.go:1746 (EditShipmentItem) and shipment_edits.go:519.
4. **propagation** `backend/go/api/internal/graph/auth_checks.go:127` (EditShipmentAuthorised) — Builds a role list (admin, plus buyer/seller if smt.HasBuyer()/HasSeller() for the intent) and returns auth.Checks(ctx, auth.PartyTypes(roles...)). auth.PartyTypes (auth/checks.go:50) compares only usr.PartyType. No ProfileID vs BuyerID/SellerID/AdminID comparison exists.
5. **sink** `backend/go/api/internal/graph/shipment_edits.go:87` (mutationResolver.editShipment) — Dispatches by intent to handlers (applyEditShipmentForSeller :242, applyEditShipmentNonAdmin :220, applyEditShipmentUpdate :319, dispatchSellerCustom, receiveBuyerCustom) that write via Ledger.Set or EditOrders. None of these checks IsParty or the profile ID, so the other tenant's shipment is modified.

### Evidence
- `backend/go/api/internal/graph/auth_checks.go:111` — ShipmentAuthorized (IsParty check) exists but is not called from EditShipmentAuthorised or from the EditShipment/EditShipmentItem resolvers.
- `backend/go/api/internal/graph/auth_checks.go:182` — EditShipmentAuthorized (with the z) does ShipmentAuthorized + CheckRoleMayEdit. It is referenced only at schema.resolvers.go:3670, in a read query, not in the mutations.
- `backend/go/api/internal/graph/schema.resolvers.go:1746` — EditShipmentItem repeats the same fetch followed by EditShipmentAuthorised, then editShipmentItem.
- `backend/go/api/internal/shipments/auth_checks.go:11` — CheckRoleMayEdit is also party-type/platform based only, with no ownership check.
- `backend/go/ledger/shipments.go:5743` — IsParty compares the profile ID to BuyerID/SellerID/AdminID. It is not used on the mutation path.

### Principal and resource
A seller or buyer at tenant A with a valid session who obtains the ID of a shipment between other parties.

### Native input / instructions (do not run against a live target)
- `mutation { editShipment(input:{id:"<other tenant shipment KSUID>", intent:EDIT_FOR_SELLER, ...}) { success } }`
- Authenticate as a Seller or Buyer profile that is not a party to the target shipment.
- Send the editShipment (or editShipmentItem) mutation with the target shipment ID and a permitted intent.
- The resolver passes EditShipmentAuthorised because only PartyType is checked, and the edit is persisted via Ledger.Set.

### Observed result and invariant proven
Source-level observation, not a runtime result: no ownership check exists on any path from the resolvers to Ledger.Set. The only gate is PartyType membership.

### Conditions and containment
- authentication_level: Attacker holds a valid authenticated Seller or Buyer session (any tenant).
- data_state: The attacker must know the target shipment's KSUID, which is not enumerable by guessing. Whether IDs leak to other tenants was not established from source.
- data_state: The shipment's type must have a seller or buyer, and the intent must be one for which that party type is allowed. For example, EditForSeller, DispatchSeller, Complete and Cancel on external shipments.

### Remediation and regression case
Call ShipmentAuthorized(ctx, smt) (or use EditShipmentAuthorized with IsParty) in EditShipment, EditShipmentItem and the shipment_edits.go:519 path before any edit. Admins remain exempt via party-type logic. Consider enforcing ownership inside the shared editShipment entry too, and add a regression test with a non-party seller and buyer.

```
func EditShipmentAuthorised(ctx context.Context, input model.EditShipmentInput, smt ledger.Shipment) error {
	if auth.UserFromContext(ctx).PartyType != users.PartyTypeAdmin {
		if err := ShipmentAuthorized(ctx, smt); err != nil {
			return err
		}
	}
	// ... existing role checks
}
```
(file: `backend/go/api/internal/graph/auth_checks.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] Packhouse allocation mutations accept any seller's sellerID from any Seller/Admin user (ID binding is dead code)

**Fingerprint:** `H5-packhouse-any-seller`  
**Root cause:** The ownership check auth.PartyTypeForID(sellerID) is called with an empty allowed-party-type list. slices.Contains over an empty slice is always false, so the check can never pass. It is also OR-ed with PartyTypes(Admin, Seller), which already admits every seller regardless of sellerID. The client-supplied sellerID is passed straight to the trader and ledger with no binding to the caller's ProfileID.  
**Intended behavior:** A seller-party caller may only act on their own sellerID (PartyTypeForID(sellerID, PartyTypeSeller)). Admins may act on any seller. Per-seller binding should be required, not alternative.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:1015` (mutationResolver.PackhouseSetAllocation) — GraphQL mutation takes a client-supplied input.SellerID. The auth.Checks call passes for any Seller or Admin party type. The same pattern is at lines 1028 (PackhouseItemAllocations), 1041 (PackhouseItemMixed) and 1061 (PackhouseClearInventories).
2. **propagation** `backend/go/auth/checks.go:82` (auth.PartyTypeForID) — With no allowed party types, slices.Contains is always false, so the profile-ID check never passes. auth.Checks (line 40) returns nil if ANY check passes, so PartyTypes(Admin, Seller) alone decides.
3. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:1018` (access.Has(PackhouseAllocations, Write)) — The role permission check is global. It confirms the caller has a role such as Packhouse, PackhouseWorker, Tech or Super, but it is not tied to any sellerID.
4. **sink** `backend/go/api/internal/graph/packhouse.go:1003` (setPackhouseAllocation / setPackhouseItemAllocations / ledger Set) — The victim sellerID is used to fetch that seller's products via the trader service and to write ledger.NewPackhouseSet(input.SellerID, ...) through r.Ledger.Set. PackhouseClearInventories calls r.Ledger.Set with NewPackhouseClear(sellerID) at schema.resolvers.go:1062. No caller-versus-seller check exists downstream in these functions.

### Evidence
- `backend/go/auth/checks.go:40` — Checks returns nil if ANY check passes (OR semantics).
- `backend/go/auth/checks.go:82` — PartyTypeForID requires the profile ID to match AND the party type to be in a variadic list. Called with no list, the second condition is always false.
- `backend/go/api/internal/graph/schema.resolvers.go:1015` — PartyTypes(Admin, Seller) plus PartyTypeForID(input.SellerID) with no party types. Repeated at lines 1028, 1041 and 1061.
- `backend/go/access/access.go:12` — access.Has only inspects the user's roles and is not bound to a seller.
- `backend/go/access/permissions/permissions.go:247` — PackhousePermissions and PackhouseWorkerPermissions (line 252) grant PackhouseAllocations Write to those roles.

### Principal and resource
A seller-party user with a packhouse role, for example a packhouse operator at one seller, calls the mutation with another seller's profile ID.

### Native input / instructions (do not run against a live target)
- `mutation { packhouseClearInventories(sellerID: <victimSellerID>) }`
- `mutation { packhouseSetAllocation(input:{sellerID:<victimSellerID>, allocations:[...]}) }`
- Authenticate as a Seller-party user holding the Packhouse role.
- Send packhouseClearInventories or packhouseSetAllocation with a sellerID different from the caller's profile ID.
- The auth.Checks call passes on the PartyTypes(Admin, Seller) branch and access.Has passes on the role, so the ledger write executes for the victim seller.

### Observed result and invariant proven
Source-level observation, not a runtime result. The ownership check is absent on every path through these four resolvers. Nothing was executed.

### Conditions and containment
- authentication_level: Authenticated user with party type Seller (or Admin).
- authorization_role: The user must hold a role granting PackhouseAllocations/Write (Packhouse, PackhouseWorker, Tech or Super). PackhouseItemMixed additionally requires a native farmer app origin (auth.IsNativeFromContext).
- data_state: A victim seller with products must exist. Another seller's ID must be known or guessable (int64 profile ID).

### Remediation and regression case
Require ownership for seller callers. Allow Admin for any seller, and for Seller allow only PartyTypeForID(sellerID, PartyTypeSeller). Replace the broad PartyTypes(Seller) check with that, and add a regression test for cross-seller calls.

```
auth.Checks(ctx, auth.PartyTypes(users.PartyTypeAdmin), auth.PartyTypeForID(input.SellerID, users.PartyTypeSeller))
```
(file: `backend/go/api/internal/graph/schema.resolvers.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] Read resolvers LogisticsDoc, TableDialog, ShipmentDispatchDialog (and seller-side QualityReport) lack any ownership check, exposing other tenants' shipment data to any authenticated user

**Fingerprint:** `H5-resolvers-no-authz-read`  
**Root cause:** Authorization on these resolvers is either absent or limited to party type. None compare shipment.IsParty(usr.ProfileID) (the existing ShipmentAuthorized helper in auth_checks.go:111) or auth.PartyTypeForID(profileID, ...) against the requested resource. The only global control is AuthOperation (auth/auth.go:373), which authenticates the token but does not authorize per resource, and the ledger Shipments fetch (ledger/internal/ops/ops.go:971) applies no caller scoping.  
**Intended behavior:** Sibling resolvers (Shipments :2808, TableGroup, SellerSetup) gate on auth.PartyTypeForID(profileID, ...) or admin, and document resolvers use SourceDocAuthorized/ShipmentAuthorized. These read resolvers should require the caller to be admin or a party to the shipment, or the owner of the requested profileID.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:2786` (queryResolver.LogisticsDoc) — Authenticated Buyer/Seller supplies arbitrary profileID and date. No auth.Checks and no comparison with the caller's profile.
2. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:2792` (queryResolver.LogisticsDoc) — The client profileID goes straight into ledger.SmdProfileIDs for the shipment filter.
3. **propagation** `backend/go/api/internal/graph/shipments.go:2597` (Resolver.fetchShipmentsAndProfiles) — Fetches shipments from Ledger.Shipments (ledger/internal/ops/ops.go:971, no caller scoping) and the associated buyer and seller profiles.
4. **propagation** `backend/go/api/internal/graph/logisticsdocs.go:74` (sellerPackingListTables) — Builds the packing list for the foreign profile, including products and buyer shipping address, and returns it to the caller.
5. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:2922` (queryResolver.TableDialog) — Any authenticated user supplies shipmentID and a dialog type. No auth.Checks and no IsParty check.
6. **propagation** `backend/go/api/internal/graph/payments.go:163` (prepareSettleOrder / paymentDialog / chargeDialog / payCredit) — Settlement and payment dialogs render shipment totals, due amounts and seller or buyer settlement figures for any shipment ID.
7. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:2994` (queryResolver.ShipmentDispatchDialog) — Any authenticated user supplies shipmentID. No checks.
8. **propagation** `backend/go/api/internal/graph/shipments.go:6929` (shipmentDispatchDialog) — Returns shipment name, case count and the buyer or seller destination street and city for another tenant's shipment.
9. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:4245` (queryResolver.QualityReport) — Party-type check only (Seller or Admin). Any Seller supplies any shipmentID.
10. **sink** `backend/go/api/internal/graph/quality.go:505` (qualityReportScreenTabs) — Fetches the shipment and its quality reports by ID without an ownership check and returns inspection results, seller label and delivery address.

### Evidence
- `backend/go/api/internal/graph/schema.resolvers.go:2786` — LogisticsDoc body has no auth call at all.
- `backend/go/api/internal/graph/schema.resolvers.go:2922` — TableDialog uses usr only to fetch the admin profile and has no authorization.
- `backend/go/api/internal/graph/schema.resolvers.go:2994` — ShipmentDispatchDialog has no authorization.
- `backend/go/api/internal/graph/schema.resolvers.go:4245` — QualityReport checks only the Seller/Admin party type.
- `backend/go/api/internal/graph/schema.resolvers.go:2808` — Comparison baseline: sibling Shipments, TableGroup and SellerSetup do apply party/profile checks.
- `backend/go/api/internal/graph/auth_checks.go:111` — ShipmentAuthorized (IsParty) exists but is not called by these resolvers.
- `backend/go/api/internal/graph/shipments.go:59` — fetchLedgerShipment fetches by ID with no identity scoping.
- `backend/go/ledger/internal/ops/ops.go:971` — Ledger Shipments applies no caller scoping.
- `backend/go/api/internal/graph/accounts.go:135` — Counter-evidence: ShipmentTransactions filters transactions to the caller's profile, so it is excluded from the confirmed set.
- `backend/go/auth/auth.go:373` — AuthOperation only authenticates and applies platform checks; no resource authorization.

### Principal and resource
An authenticated seller or buyer on the platform queries another tenant's profile or shipment.

### Native input / instructions (do not run against a live target)
- `query { logisticsDoc(type: <SELLER_PACKING_LIST enum>, profileID: <victim profile id>, date: "<dispatch date>") { ... } }`
- `query { tableDialog(type: SETTLEMENT, shipmentID: "<victim shipment id>") { ... } }`
- `query { shipmentDispatchDialog(shipmentID: "<victim shipment id>") { ... } }`
- Authenticate as an ordinary seller or buyer.
- Call logisticsDoc with another seller's profileID and a dispatch date.
- Call tableDialog or shipmentDispatchDialog with a shipment ID belonging to another tenant.

### Observed result and invariant proven
Source-level observation, not a runtime result: no check on any code path compares the caller's profile with the requested profile or shipment, and the data layer does not scope by caller, so the data is returned to any authenticated caller.

### Conditions and containment
- authentication_level: Valid authenticated Buyer or Seller account. Admin is not required. QualityReport additionally needs a Seller account.
- data_state: TableDialog, ShipmentDispatchDialog and QualityReport need a victim shipment KSUID, which is not guessable and must be obtained from another channel. LogisticsDoc needs only a victim profileID (an int64, enumerable) and a dispatch date with matching created-status shipments.

### Remediation and regression case
Add per-resource authorization to each resolver. For LogisticsDoc, require auth.PartyTypeForID(profileID, Seller) or Admin. For TableDialog, ShipmentDispatchDialog, QualityReport, ShipmentTransactions and DocumentNumber, call ShipmentAuthorized(ctx, shipment) unless the caller is Admin. Consider restricting the settlement and payment dialogs to Admin.


Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] Multiple GraphQL mutations perform cross-tenant writes with no caller role or ownership check

**Fingerprint:** `H5-resolvers-no-authz-write`  
**Root cause:** The resolvers were written without the auth.Checks(PartyTypes(Admin), PartyTypeForID(...)) pattern used by sibling mutations. The API layer relies only on authentication in AuthOperation, and the downstream trader, ledger and administrator services trust the passed IDs and do no per-caller authorization.  
**Intended behavior:** Seller-scoped and admin mutations should require an admin or the owning seller (auth.Checks with PartyTypes and PartyTypeForID, or access.Has). Quote and shipment mutations should require that the caller is a party to the quote or shipment (ShipmentAuthorized or equivalent). ChatNotify and EnqueueShipmentLabels should be limited to a party of the profile or shipment, or to admins.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:1518` (mutationResolver.VolumePriceAdjustment) — GraphQL mutation volumePriceAdjustment(sellerID, productTypeID, quantity, percentage) is reachable by any authenticated user; the resolver has no auth check.
2. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:1563` (mutationResolver.UpdateSellerCutoff -> Resolver.updateSellerCutoff (graph/seller.go:46)) — Same pattern: caller-supplied sellerID selects the profile, which is rewritten via Administrator.Set with no ownership check.
3. **propagation** `backend/go/api/internal/graph/schema.resolvers.go:1941` (mutationResolver.SetShipmentItemStatus / SetInventoryStatus (:1955)) — Caller-supplied item IDs go straight to Ledger.Set with no shipment party check.
4. **sink** `backend/go/trader/internal/ops/inputs.go:88` (Resolver.maybeSetVolumeAdjustments) — Persists the volume adjustment for the supplied seller in the DB (volumeadjustments.SetTx) with no caller authorization, changing buyer pricing for another seller's products.

### Evidence
- `backend/go/api/internal/graph/schema.resolvers.go:1518` — VolumePriceAdjustment builds trader.VolumeAdjustmentInput from raw args and calls r.Trader.Set with no auth.Checks.
- `backend/go/api/internal/graph/schema.resolvers.go:1534` — Sibling SeasonalityToggle uses auth.Checks(Admin, PartyTypeForID(sellerID, Seller)), showing the intended control is missing on VolumePriceAdjustment.
- `backend/go/api/internal/graph/schema.resolvers.go:1563` — UpdateSellerCutoff has no check before updateSellerCutoff.
- `backend/go/api/internal/graph/seller.go:46` — updateSellerCutoff fetches the profile by caller-supplied sellerID and writes SellerCutOff and SellerMarketClose through Administrator.Set.
- `backend/go/api/internal/graph/schema.resolvers.go:1130` — UploadPop attaches a caller-supplied URL to any quoteID via Trader.Set, with no check.
- `backend/go/api/internal/graph/schema.resolvers.go:1941` — SetShipmentItemStatus and SetInventoryStatus (:1955) pass IDs to Ledger.Set with no check.
- `backend/go/ledger/internal/ops/set.go:916` — Downstream ledger op completes moved inventory for the supplied IDs with no caller authorization.
- `backend/go/api/internal/graph/schema.resolvers.go:1871` — ChatNotify looks up any profileID and notifies its user emails with no check.
- `backend/go/api/internal/graph/schema.resolvers.go:1647` — EnqueueShipmentLabels passes any shipment KSUID to Ledger.EnqueueShipmentLabels with no check (ledger/internal/ops/printjobs.go:26 also has none).
- `backend/go/auth/auth.go:404` — The only global gate in AuthOperation is that the user is authenticated (or the operation name is in publicOperations) plus a platform check. There is no role check, and gqlgen has no schema directives on these fields.

### Principal and resource
A logged-in Buyer on another tenant sends GraphQL mutations naming another seller's or profile's IDs.

### Native input / instructions (do not run against a live target)
- `mutation { volumePriceAdjustment(sellerID: <victimSellerID>, productTypeID: <id>, quantity: 1, percentage: 90.0) }`
- `mutation { updateSellerCutoff(sellerID: <victimSellerID>, marketClose: "<day>", cutoff: 0) }`
- `mutation { chatNotify(profileID: <victimProfileID>) }`
- Authenticate as an ordinary Buyer.
- Send the mutation with a victim seller or profile ID.
- The call returns true and the victim's data is modified or a notification is sent.

### Observed result and invariant proven
Source-level observation, not a runtime result: no auth.Checks, access.Has or ownership comparison exists in the resolver, in its helper, or in the downstream trader, ledger or administrator ops on these paths. The calls were not run.

### Conditions and containment
- authentication_level: Attacker needs any valid authenticated account, e.g. a Buyer, on a permitted platform.
- data_state: Attacker needs a target seller, profile, quote, shipment or item ID. Several of these are sequential or enumerable ints; shipment KSUIDs must be known.
- environmental_dependency: Downstream services are assumed to accept the API's calls as trusted. No per-caller check was found in the trader, ledger or administrator ops reviewed. Network-level ingress is not verified.

### Remediation and regression case
Add auth.Checks(ctx, auth.PartyTypes(users.PartyTypeAdmin), auth.PartyTypeForID(sellerID, users.PartyTypeSeller)) to seller-scoped mutations (VolumePriceAdjustment, UpdateSellerCutoff). Add a quote or shipment party check, as ShipmentAuthorized does, to UploadPop, SetShipmentItemStatus, SetInventoryStatus and EnqueueShipmentLabels. Restrict ChatNotify to a participant of the chat or to admins. Consider enforcing a default-deny mutation-level directive.


Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] PotatoesSA export-only token user can run any Admin-party-type query because the scope gate only inspects the first top-level field that has an argument

**Fingerprint:** `auth/potatoessa-scope-first-field-only`  
**Root cause:** isExportDataQuery() (auth.go:323-332) returns on the first top-level field that has an argument and ignores all other selections. Argument-less fields are skipped, and non-Field selections such as fragment spreads would panic on the type assertion instead of being checked. The PotatoesSA scope restriction is also implemented only as this operation-shape check, not as an allow-list enforced per resolver or field. The user is given the full Admin party type, which many resolvers accept as sufficient.  
**Intended behavior:** The PotatoesSA user may execute only the exportData(type: PotatoesSA) query and nothing else. Every top-level selection, including fragments and aliases, must be exportData with the PotatoesSA argument, and any other field must be rejected.

### Ordered trace
1. **entrypoint** `backend/go/auth/auth.go:373` (Client.AuthOperation (GraphQL operation middleware, registered at api/cmd/server/main.go:120)) — Every GraphQL operation passes through this middleware. The caller controls the Authorization header and the query document.
2. **propagation** `backend/go/auth/auth.go:474` (Client.userFromIDToken) — A bearer value equal to the hardcoded potatoesSaToken constant (auth.go:31) returns UsrPotatoesSA(): PartyTypeAdmin, ProfileID and AdminProfileID = AdminIDNile, no Roles (auth.go:198-206). X-Platform must equal the Nile admin id for checkPlatform to pass.
3. **propagation** `backend/go/auth/auth.go:407` (AuthOperation, PotatoesSA gate) — The only restriction is `user.IsPotatoesSA() && !isExportDataQuery(op.Operation)`. If isExportDataQuery returns true, the user is placed in the context and next(ctx) runs the whole operation.
4. **propagation** `backend/go/auth/auth.go:323` (isExportDataQuery) — The loop iterates the top-level selections, skips fields with no arguments, and returns on the first field with an argument via authorisedExternalQueries[op][field][arg]. Later selections are never examined, so exportData(type: PotatoesSA) first (or after argument-less fields) makes the check true for the whole document.
5. **sink** `backend/go/api/internal/graph/schema.resolvers.go:3262` (queryResolver.Seller (also Buyer :3275, AccountTransactions :2567, OrderStatementEntries :3236)) — These resolvers check only auth.PartyTypes(Admin) or CheckIfPartyTypeAllowed(Admin), which the PotatoesSA user satisfies. They return tenant data for caller-chosen seller or buyer ids and ledger data, far beyond the signed export URL.

### Evidence
- `backend/go/auth/auth.go:323` — isExportDataQuery returns inside the first loop iteration that has an argument and never checks other selections. It also asserts every selection to *ast.Field.
- `backend/go/auth/auth.go:407` — The single enforcement point for the PotatoesSA restriction. Other than this, no per-resolver deny exists for the PotatoesSA user.
- `backend/go/auth/auth.go:198` — UsrPotatoesSA sets PartyTypeAdmin and the Nile admin id and leaves Roles empty. The comment states it should be limited to certain areas, i.e. the export query.
- `backend/go/auth/auth.go:31` — The PotatoesSA token is a constant in source (key potatoesSaToken); its value is not reproduced here.
- `backend/go/api/internal/graph/schema.resolvers.go:4270` — ExportData itself is gated only by PartyTypes(Admin), the same check that admits the PotatoesSA user elsewhere.
- `backend/go/api/internal/graph/schema.resolvers.go:3263` — Seller admits any Admin party type for an arbitrary sellerUUID (cross-tenant read). Buyer (3277) and AccountTransactions (2569) are similar.
- `backend/go/api/cmd/server/main.go:120` — AuthOperation is the only auth middleware on the GraphQL server. No gqlgen directive or other layer blocks the PotatoesSA user on other fields.
- `backend/go/auth/auth.go:448` — The plain HTTP path (AuthHTTP) explicitly rejects the PotatoesSA user, which shows the intent that this user be kept out of other surfaces. The GraphQL path has only the bypassable check.

### Principal and resource
A holder of the PotatoesSA token, who should only be able to fetch the export URL, sends one GraphQL query that begins with the allowed exportData selection and appends Admin-readable fields for other tenants.

### Native input / instructions (do not run against a live target)
- `query { exportData(type: PotatoesSA) seller(sellerUUID: 1, search: "") { __typename } }`
- Send POST to the api GraphQL endpoint with Authorization set to the PotatoesSA token and X-Platform set to the Nile admin id.
- Use a document whose first argument-bearing top-level field is exportData(type: PotatoesSA), followed by other query fields such as seller, buyer, accountTransactions or orderStatementEntries. Selections with no arguments listed before exportData are also skipped by the gate.
- Expected: the gate at auth.go:407 passes and the additional fields execute under the Admin-party-type PotatoesSA user.

### Observed result and invariant proven
Source-level observation only, not a runtime result. The loop in isExportDataQuery returns at the first selection with an argument and checks nothing else. The code shows no other control on the path, and the target resolvers admit Admin party type. This was derived by reading the code and nothing was executed.

### Conditions and containment
- authentication_level: The caller must present the PotatoesSA token. That is the legitimate partner holder, or anyone who has read it from the source repository or build artifacts.
- system_configuration: The request must reach the api GraphQL endpoint with X-Platform set to the Nile admin id so that checkPlatform passes. Whether the endpoint is publicly reachable is not determined from source.
- data_state: Only query operations are reachable, because the gate map is keyed to 'query'. Resolvers that also require role-based access.Has permissions are not reachable, because the user has no roles.

### Remediation and regression case
Replace the first-field heuristic with a strict check. Require every top-level selection (resolving fragments and rejecting non-Field selections safely) to be exportData with the PotatoesSA argument, and reject if any other selection exists. Better still, remove the Admin party type from this user, or add an explicit deny for IsPotatoesSA in resolvers or a gqlgen directive. Also move the token out of source and rotate it.

```
func isExportDataQuery(op *ast.OperationDefinition) bool {
	if len(op.SelectionSet) == 0 {
		return false
	}
	for _, set := range op.SelectionSet {
		f, ok := set.(*ast.Field)
		if !ok || len(f.Arguments) != 1 {
			return false
		}
		if !authorisedExternalQueries[string(op.Operation)][f.Name][f.Arguments[0].Value.String()] {
			return false
		}
	}
	return true
}
```
(file: `backend/go/auth/auth.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

## [MEDIUM] Gerrit webhook Cloud Function is public and accepts forged events without any authentication, enabling attacker-chosen staging deploys

**Fingerprint:** `gerrit-webhook-unauthenticated-event-forgery`  
**Root cause:** Authentication was delegated to a non-existent application-layer HMAC check: the Cloud Run service is opened to allUsers and Handle() trusts the unauthenticated JSON body, including type, Change.Branch and NewRev.  
**Intended behavior:** Only Gerrit (webhook with shared-secret HMAC or authenticated invoker) and Cloud Scheduler (OIDC) should be able to invoke the function; event content should be accepted only from an authenticated sender.

### Ordered trace
1. **entrypoint** `backend/go/gerrit/functions/webhook/webhook.go:62` (Handle) — Public HTTP handler reads the raw body and unmarshals it with no signature, secret, token or IP check, then switches on attacker-controlled event.Type.
2. **propagation** `backend/go/gerrit/functions/webhook/webhook.go:283` (handleChangeMerged) — Trusts event.Change.Branch (only must equal master) and event.NewRev as the merged commit; no verification against Gerrit that the SHA was merged.
3. **propagation** `backend/go/gerrit/task/deploys.go:76` (RecordMerge) — Writes attacker-supplied SHA as staging targetSha and into pending changelog in Firestore, which also marks legitimate pending deploys as superseded.
4. **sink** `backend/go/gerrit/task/deploy.go:107` (CreateDeploy) — Cancels queued auto-deploys and enqueues a staging deploy Task with Ref set to the forged SHA; the agent (agent/main.go:669 git.Checkout, agent/actions/git/checkout.go:60 fetch and :95 reset --hard FETCH_HEAD) fetches that ref with the bot credential and deploys it to staging.

### Evidence
- `backend/go/gerrit/terraform/functions.tf:64` — google_cloud_run_v2_service_iam_member gerrit_webhook_invoker grants roles/run.invoker to allUsers (line 69); preceding comment at line 63 claims HMAC verification that does not exist in code.
- `backend/go/gerrit/functions/webhook/webhook.go:62` — Handle has no authentication; grep of the gerrit module finds no hmac/signature/X-Gerrit/oidc verification anywhere in the function path.
- `backend/go/gerrit/terraform/scheduler.tf:18` — Scheduler jobs call the function URL with plain POST and no oidc_token, confirming the function is intended to be callable unauthenticated.
- `backend/go/gerrit/functions/webhook/webhook.go:353` — RecordMerge and CreateDeploy (line 358) are called with event.NewRev taken directly from the request body.
- `backend/go/gerrit/functions/webhook/webhook.go:256` — tryAutoSubmit relies on Gerrit ChangeSubmittable/ChangeMergeable checks, so forged comment-added cannot force-submit unapproved changes; impact there is limited to triggering legitimate submits early.

### Principal and resource
Anonymous internet caller who knows the webhook function URL.

### Native input / instructions (do not run against a live target)
- `POST <function-url> {"type":"change-merged","change":{"number":<n>,"branch":"master","subject":"x"},"patchSet":{"number":1},"newRev":"<fetchable-commit-sha>"}`
- Send the POST with Content-Type application/json to the public function URL.
- Handler records the SHA as staging targetSha and enqueues a staging deploy; the builder fetches and deploys it.

### Observed result and invariant proven
Source-level observation, not a runtime result: no check exists on any path between the allUsers invoker binding and the deploy enqueue, so the forged event is accepted and acted upon.

### Conditions and containment
- authentication_level: None required to call the function; attacker needs only the function URL (not secret, deterministic cloudfunctions/run.app URL).
- environmental_dependency: For arbitrary code to reach staging the attacker needs a SHA fetchable from code.nile.ag by the bot (e.g. a pushed unreviewed refs/changes patchset, which requires a Gerrit account, or any existing unmerged/merged SHA). Without a Gerrit account the attacker can only replay existing commits, supersede/disrupt legitimate staging deploys, and spam builder tasks.
- system_configuration: Only staging is auto-targeted by this path; production deploys are manually requested and not reachable via this event. Cloud Run ingress is not restricted in the Terraform (no ingress setting found).

### Remediation and regression case
Remove allUsers invoker. Require authentication: configure Gerrit webhook with a shared secret and verify the HMAC (constant-time) over the raw body in Handle before parsing, and give Cloud Scheduler an oidc_token with an invoker-only service account. Additionally, in handleChangeMerged confirm via the Gerrit API that NewRev is the merged tip of master for the given change before recording/deploying.


Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---



---

# Client findings (run-2)

All observations are source-level; no code was executed. Secret values are intentionally omitted.

## [HIGH] Stored XSS: buyer/seller profile name rendered unescaped via dangerouslySetInnerHTML in server-driven form description (hits admin session)

**Fingerprint:** `c1-market-form-description-stored-xss-profile-name`  
**Root cause:** The backend treats form.Description as plain text and interpolates user-controlled profile names into it without HTML escaping. The client treats the same field as trusted HTML in the Normal variant. The name validator (field.ValueFor) blocks only the double-quote character.  
**Intended behavior:** Form descriptions containing user-supplied data should be rendered as text, or HTML-escaped or sanitized before rendering. User-controlled names should not be able to inject markup into other tenants' or admins' sessions.

### Ordered trace
1. **entrypoint** `backend/go/api/internal/graph/schema.resolvers.go:1146` (mutationResolver.Form (auth chks, ~1146-1160)) — Lower-trust entrypoint. The FormTypeSetProfileCompany case allows Seller or Buyer party types for their own profile ID (auth.PartyTypeForID), in addition to Admin.
2. **propagation** `backend/go/api/internal/graph/customers/company.go:557` (ProfileCompanyInput switch on profileName) — ap.Name is set from field.ValueFor. MaxLength is 100 (company.go:1058). ValueFor (backend/go/api/internal/form/field/field.go:405-416) rejects only double quotes. The value is persisted via handleSetProfileCompany (backend/go/api/internal/graph/form_input.go:1025) and Administrator.Set. The ProfileOwner role has Write ProfileInformation (backend/go/access/permissions/permissions.go:215).
3. **propagation** `backend/go/api/internal/graph/form.go:272` (queryResolver.form case FormTypeAddOutboundShipmentProduct (~272-286); the inbound case at 223-238 is analogous) — The buyer profile is loaded by ID from the shipment (stored Name) and passed to shipments.OutboundAddProduct. The Form query default auth (schema.resolvers.go:3286) is Admin only for these form types, so the victim is a platform admin.
4. **propagation** `backend/go/api/internal/shipments/outbound_add_product.go:21` (OutboundAddProduct) — form.Description(fmt.Sprintf("Allocate inventory to outbound shipment to %s", buyer.Name)) with no escaping. form.Description (backend/go/api/internal/form/form.go:58-62) assigns the string verbatim, and the variant defaults to Normal (form.go:25). inbound_add_product.go:56 does the same with seller.Name.
5. **sink** `client/market/src/components/Form.tsx:122` (Form component, non-Callout description branch) — dangerouslySetInnerHTML={{ __html: form.description }} with no sanitizer. Only the Callout variant (line ~112) renders as text. Neither OutboundAddProduct nor InboundAddProduct sets Callout. The form is opened from the admin EditShipment screen (client/market/src/screens/Shipments/EditShipment.tsx:370).

### Evidence
- `client/market/src/components/Form.tsx:122` — dangerouslySetInnerHTML with form.description. No DOMPurify or sanitize usage found anywhere in client/market outside node_modules.
- `backend/go/api/internal/shipments/outbound_add_product.go:21` — Sprintf embeds buyer.Name into the description.
- `backend/go/api/internal/shipments/inbound_add_product.go:56` — Sprintf embeds seller.Name into the description.
- `backend/go/api/internal/form/field/field.go:405` — ValueFor enforces only MaxLength and a no-double-quote rule. HTML tags, single quotes and backticks pass.
- `backend/go/api/internal/graph/customers/company.go:1058` — profileName MaxLength is 100, which is enough for a short onerror payload.
- `backend/go/api/internal/graph/packhouse/shipment_info.go:87` — Sibling sink: recipient/prf.Name interpolated into the description, which is likely rendered through the same Form.tsx path.
- `backend/go/api/internal/graph/customers/delete_user.go:15` — Sibling sink: userEmail interpolated, but the viewer is limited to the user's own email (schema.resolvers.go:3321), so it is self-only and low value.

### Principal and resource
A registered buyer or seller changes their own profile Name to a payload with no double quotes. An admin later opens the allocation form for that profile's shipment, and the payload executes in the admin's session.

### Native input / instructions (do not run against a live target)
- `<img src=x onerror=alert(document.domain)>`
- As the buyer or seller profile owner, submit FormTypeSetProfileCompany with the profileName field set to the payload (it is under 100 characters and contains no double quotes).
- Get a shipment created that references the profile. An admin then opens the Add Outbound product or Add Inbound product form for it from the EditShipment screen.
- The server returns the description containing the raw payload, and Form.tsx injects it as HTML.

### Observed result and invariant proven
Source-level observation only, not a runtime result. Every hop was read in source: profile owners may set Name, no escaping or sanitizing exists on the path, and the sink uses dangerouslySetInnerHTML for the Normal-variant description. Nothing was executed.

### Conditions and containment
- authentication_level: Attacker holds an authenticated buyer or seller profile-owner account on their own profile.
- user_interaction: A platform admin must open the Add Outbound product or Add Inbound product form for a shipment linked to the attacker's profile. This is a routine admin workflow.
- system_configuration: A strict deployed CSP or equivalent response headers are not visible in source. None was found in the repo (grep for Content-Security-Policy and DOMPurify found nothing under client/market). If one exists it could blunt inline-handler payloads.

### Remediation and regression case
Render form.description as text, or sanitize it with a vetted HTML sanitizer such as DOMPurify. On the backend, html.EscapeString every user-controlled value interpolated into descriptions (profile name, email, recipient). Optionally reject '<' and '>' in profile names and add a CSP.

```
form.Description(fmt.Sprintf("Allocate inventory to outbound shipment to %s", html.EscapeString(buyer.Name))),
```
(file: `backend/go/api/internal/shipments/outbound_add_product.go`)

Regression: add a test asserting the unauthorised principal described above is rejected before the sink listed in the trace.

---

