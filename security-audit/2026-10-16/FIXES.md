# Security fixes

This file explains each security finding that we fix. Each section shows the problem, the fix, and what the fix does not cover.

We add a section when we address a finding. The findings are in `REPORT.md` in this folder.

---

## Fix 1: Profile takeover (finding 5)

**Status:** The fix is in the code. The check runs only when the feature flag `SecurityReview` is on.

### The problem

A user can link their account to the profile of another customer. Then the user can use that profile.

### Words used in this section

- **Profile:** the account of a buyer or seller.
- **Linked profile:** the sibling profile of a profile on the other platform. A profile can have 1 linked profile. The field is `LinkedProfileID`.
- **Link:** a row in the `profile_users` table. The row connects a user to a profile.

### How the attack works

1. The attacker has a normal account. Their current profile is A. Profile A has a linked profile B.
2. The attacker calls `switchUserProfile` with the ID of profile C. Profile C belongs to another customer.
3. The server finds no link between the attacker and profile C.
4. The server calls `relinkProfile`. This function repairs a lost link.
5. `relinkProfile` checks that profile A has a linked profile. It does not check that profile C is that linked profile.
6. The server links the attacker to profile C. Then the server changes the profile of the attacker to C.

Profile IDs are whole numbers. An attacker can try many numbers.

```
switchUserProfile(pid)                    caller = user U, current profile = A
        │                                 A.LinkedProfileID = B
        ▼
Is U linked to pid in profile_users?
        │
   ┌────┴─────┐
  YES         NO
   │           │
   │           ▼
   │      relinkProfile(pid)
   │           │
   │           ▼
   │   A.LinkedProfileID != 0 ?
   │     yes → link U to pid     ← any pid works. This is the problem.
   │     no  → return nil        ← no link, but the profile still changes
   │           │
   ▼           ▼
 set U.ProfileID = pid
```

The code is in `backend/go/api/internal/graph/customers.go`, function `relinkProfile`.

```go
if cp.LinkedProfileID != 0 { // re-link a profile
    input := []administrator.UserLink{{UserEmail: usr.Email, ProfileID: profileID}}
    r.Administrator.Set(ctx, administrator.NewInput(administrator.InpUsrLinks(input)))
}
return nil
```

The check uses `cp.LinkedProfileID` only to see if a linked profile exists. The link uses `profileID`, which the client sends.

### The fix

`relinkProfile` now accepts only the linked profile of the current profile.

```go
if features.Has(features.SecurityReview) {
    if cp.LinkedProfileID == 0 || profileID != cp.LinkedProfileID {
        return je.New("profile is not linked to your account")
    }
}
```

The repair of a lost link to the real linked profile still works. All other requests return an error.

```
BEFORE                                      AFTER

 U's profile A ──linked── B                  U's profile A ──linked── B
       │                                           │
       ├── change to B   ✔ link repaired           ├── change to B   ✔ link repaired
       ├── change to C   ✔ U is linked   ✖ BAD     ├── change to C   ✖ error
       └── change to D   ✔ U is linked   ✖ BAD     └── change to D   ✖ error
```

Profiles C and D belong to other customers.

| Request | Result with the fix |
|---|---|
| U changes to a profile that U is already linked to | Allowed |
| U changes to B, and the link row is missing | The link is repaired. The change succeeds. |
| U changes to a profile that is not B | Error |
| Profile A has no linked profile, and U asks for an unlinked profile | Error. The profile does not change. |

### What the fix does not cover

- **The `SetUser` form (finding 3).** This form lets the client send a profile ID. It can give the same result. We fix it separately.
- **Old links.** The fix does not remove links that the old code made. Look in `profile_users` for users that are linked to a profile that is not their linked profile.
- **Users with other profiles.** Before the fix, the server repaired a lost link to any profile. Now, if the lost link is not to the linked profile, an administrator must repair it.

### How to test

1. U changes to B, and the link row is missing. The link is repaired. The change succeeds.
2. U changes to profile C. The server returns the error "profile is not linked to your account".
3. Profile A has no linked profile. U changes to an unlinked profile. The server returns an error. `U.ProfileID` does not change.
4. U changes to a profile that U is already linked to. The change succeeds.

---

## Fix 2: Stored XSS in form descriptions (finding 9)

**Status:** The fix is in the code and pushed. The check runs only when the feature flag `SecurityReview` is on.

### The problem

A user can write a script in the name of their company. The server puts the name in the description of a form. The client shows the description as HTML. The script runs in the browser of an admin.

This attack is called stored cross-site scripting (XSS). The server stores the script, and the script runs later in the browser of another user.

### Words used in this section

- **Form description:** the line of text at the top of a form. The server builds it.
- **Escape:** replace the characters `<` and `>` with codes, for example `&lt;`. The browser then shows them as text.
- **Callout:** a form variant. The client shows the description of a Callout form as plain text.

### How the attack works

1. The attacker is a buyer or seller. They change the name of their own profile to `<img src=x onerror=...>`.
2. The server accepts the name. The name check blocks only the double quote. The limit is 100 characters.
3. A shipment is linked to the profile of the attacker.
4. An admin opens the form to add a product to the shipment.
5. The server puts the name in the description with no escape. The code is in `outbound_add_product.go:21` and `inbound_add_product.go:56`.
6. The client shows the description as HTML. The script runs with the rights of the admin.

```
 BUYER / SELLER                 SERVER                      ADMIN BROWSER
      │                            │                             │
      │ 1. set company name:       │                             │
      │    <img src=x onerror=…>   │                             │
      ├───────────────────────────►│ 2. saves the name           │
      │                            │                             │
      │                            │   3. admin opens the form   │
      │                            │◄────────────────────────────┤
      │                            │ 4. builds description:      │
      │                            │    "…shipment to <img …>"   │
      │                            ├────────────────────────────►│
      │                            │                             │ 5. shows description
      │                            │                             │    as HTML (Form.tsx)
      │                            │                             │ 6. SCRIPT RUNS as admin
```

### The cause

The server treats the description as plain text. The client treats the description as HTML. Nothing escapes the name between the two.

The server puts the name in the text. This is `outbound_add_product.go:21`.

```go
form.Description(fmt.Sprintf("Allocate inventory to outbound shipment to %s", buyer.Name))
```

The client shows the text as HTML. This is `client/market/src/components/Form.tsx:122`.

```tsx
dangerouslySetInnerHTML={{ __html: form.description }}
```

### The fix

Every form passes through `form.New`. The fix escapes the description in this one place. It skips Callout forms, because the client already shows their description as text. The file is `backend/go/api/internal/form/form.go`.

```go
if features.Has(features.SecurityReview) {
    if f.DescriptionVariant != model.DescriptionVariantCallout {
        f.Description = html.EscapeString(f.Description)
    }
}
```

The server sends the escaped text. The browser reads `&lt;` as the character `<` in a text node. The browser does not read it as the start of a tag.

```
 stored name      <img src=x onerror=…>
      │
      ▼  html.EscapeString in form.New
 description      &lt;img src=x onerror=…&gt;
      │
      ▼  browser reads the description as HTML
 admin sees       <img src=x onerror=…>      ← plain text, no tag, no script
```

The client code does not change. No call site changes. The fix uses only the standard library.

| Form variant | How the client shows the description | Escape needed |
|---|---|---|
| Normal | As HTML (`dangerouslySetInnerHTML`) | Yes |
| Callout | As plain text (React child) | No. An escape would show `&lt;` as typed. |

The 5 Callout forms are in `receive.go`, `update_notes.go`, `dispatch.go`, `shipment_flag.go` and `documents/docadd.go`.

### What the fix does not cover

- **HTML in descriptions.** The fix escapes all of the description. A tag that a developer adds later, for example `<b>`, shows as text. No description has a tag today.
- **Content security policy (CSP).** The market hosting has no CSP. The fix does not add one.
- **Other places that build HTML.** The fix covers the form description only. We did not check PDF templates and email templates that contain user names.
- **Other services.** We checked the `api` package only. Another service can build a form that skips `form.New`.
- **Links and iframes.** The client has a few places that use a URL from the server with no check of the scheme. Examples are `FileViewer.tsx:171` and `window.open(post.url)` in the Explore screen. These are separate findings.

### How to test

1. Build a Normal form with the name `<img src=x onerror=alert(1)>`. The description contains `&lt;img src=x onerror=alert(1)&gt;`.
2. Build a Callout form with the same name. The description is unchanged.
3. Turn the flag off. The description is unchanged.
4. Use a description with `&`, for example `Tom & Jerry`. The page shows `Tom & Jerry`.
5. Set a profile name to the script. As an admin, open the Add outbound product form for a linked shipment. No script runs, and the page shows the name as text.

---

## Fix 3: Unauthenticated operation-name bypass (finding 4)

**Status:** The fix is in the code (commit `ad7e86a4fd62`). The gate change applies at once. The new checks on each mutation run only when the feature flag `SecurityReview` is on.

### The problem

A caller with no account could run any GraphQL operation. The caller only had to give the operation the name `Signup`. The server checked the name of the operation. It did not check what the operation does.

### Words used in this section

- **Operation name:** a label that the client chooses, for example `mutation Signup { ... }`. The label has no effect on what the operation runs.
- **Root field:** the first call inside an operation, for example `setShipmentItemStatus`. The root field decides what the server runs.
- **Unauthenticated caller:** a caller that sends the placeholder token `unauthenticated` and has no account.

### How the attack works

1. The attacker has no account. They send the token `unauthenticated`.
2. The attacker sends `mutation Signup { setShipmentItemStatus(...) }`.
3. The server reads the name `Signup`. The name is in the list of public operations. The server lets the request in.
4. The server runs `setShipmentItemStatus`. This resolver has no check of its own, so it changes the data.

Seven mutations had no check of their own. A user with an account could also use them on the data of another customer.

```
 ATTACKER (no account)                 SERVER
      │                                   │
      │ token: unauthenticated            │
      │ mutation Signup {                 │
      │   setShipmentItemStatus(...)      │
      │ }                                 │
      ├──────────────────────────────────►│ is "Signup" a public name?  YES
      │                                   │ → run setShipmentItemStatus
      │                                   │   (no check inside)
      │◄──────────────────────────────────┤ data changed
```

The code is in `backend/go/api/internal/gql/auth.go`.

```go
if user.FirebaseUID == auth.FIDUnauthed && !slices.Contains(publicOperations, op.Operation.Name) {
    return errorWithCode(ctx, errors.New("forbidden operation (unauthorized)", codes.CodeForbidden))
}
```

The gate reads `op.Operation.Name`. The client chooses this value.

### The fix

The fix has 2 parts.

**Part 1: the gate reads the root fields.** An unauthenticated caller can select only `signUp`, `signup` and `validateCurrentToken`. The old name is no longer used.

```go
var publicRootFields = map[ast.Operation][]string{
    ast.Mutation: {"validateCurrentToken", "signUp", "signup"},
    ast.Query:    {"validateCurrentToken"}, // deprecated, still sent by older app versions
}
```

The gate rejects an operation with no root fields. It rejects an operation with a fragment at the root. It checks the real field name, so an alias cannot hide another field.

```
BEFORE                                          AFTER

 mutation Signup {                               mutation Signup {
   setShipmentItemStatus(...)                      setShipmentItemStatus(...)
 }                                               }
 name = "Signup"  → ALLOWED  ✖ BAD               root field = setShipmentItemStatus
                                                 not in the public list → REJECTED  ✔

 mutation Signup { signUp(input: ...) }          mutation Signup { signUp(input: ...) }
 → allowed                                       root field = signUp → allowed  ✔
```

The market app, the iOS farmer app and the older apps send only these root fields. Each public operation has 1 root field.

**Part 2: each mutation checks its caller.** Seven mutations used the gate as their only check. Each one now checks the caller. These checks run only when `SecurityReview` is on.

| Mutation | Who can call it |
|---|---|
| `volumePriceAdjustment` | An admin, or the named seller |
| `updateSellerCutoff` | An admin, or the named seller |
| `uploadPOP` | An admin, or the buyer of the quote |
| `setShipmentItemStatus` | An admin |
| `setInventoryStatus` | An admin |
| `emailPriceList` | An admin |
| `chatNotify` | An admin |

The market client calls `volumePriceAdjustment`, `updateSellerCutoff`, `uploadPOP` and `emailPriceList`. We found no call to `setShipmentItemStatus`, `setInventoryStatus` or `chatNotify` in the market client or the iOS farmer app.

### What the fix does not cover

- **The checks on each mutation are behind the flag.** Until the flag is on, a user with an account can still call these mutations on the data of another customer. The gate change is not behind the flag.
- **`updateClaims`.** The audit names this mutation. The commit does not change it. The gate now blocks anonymous callers. We did not find a check in the resolver, so a user with an account may call it for any email. We read only the start of the helper. Check this.
- **Read resolvers.** `LogisticsDoc` and other read resolvers have no ownership check. These are in the finding for access to the data of other customers.
- **The PotatoesSA token (finding 10).** The scope check for this token is not in this commit.
- **The services behind the API.** We did not check if the gRPC services reject an unauthenticated caller. This stays an open question (N1 in the report).
- **Other callers.** We searched the market client and the iOS farmer app. We did not search the Android apps and the internal tools for admin-only mutations.

### How to test

1. Send `mutation Signup { setShipmentItemStatus(...) }` with the token `unauthenticated`. The server rejects it.
2. Send an operation with an alias, for example `mutation { a: signUp(...) b: setShipmentItemStatus(...) }`. The server rejects it.
3. Send an operation with a fragment at the root. The server rejects it.
4. Send `mutation Signup { signUp(input: ...) }` with no account. The server accepts it.
5. Send `mutation ValidateCurrentToken { validateCurrentToken }` as a mutation and as a query. The server accepts both.
6. With the flag on, call `volumePriceAdjustment` as a seller for another seller. The server rejects it. Call it for the seller of the caller. The server accepts it.
7. With the flag on, call `setShipmentItemStatus` as a seller. The server rejects it. Call it as an admin. The server accepts it.
8. With the flag on, call `uploadPOP` as a buyer for the quote of another buyer. The server rejects it.

---

## Fix 4: The Potatoes SA token can run more than the export (finding 10)

**Status:** The fix is in the code (commit `b54d830c9bb3`). It is not behind a feature flag. It applies at once.

### The problem

The Potatoes SA token is for one job: the `exportData` query. The Potatoes SA user is a Nile admin. The check that keeps the token to the export looked at one field only. A caller with the token could add other fields to the same request. The server ran those fields with admin rights.

A second problem is in the same file. A request with a fragment at the root made the server panic. This happened for any caller, before the login check.

### Words used in this section

- **Root field:** the first call inside an operation, for example `exportData` or `users`.
- **Potatoes SA token:** the token of a partner. The user for this token is an admin.
- **Fragment:** a named or inline block of fields, for example `...F`. A fragment at the root hides the real fields from a simple check.
- **Panic:** the server code stops with an error. The request fails.

### How the attack works

1. The attacker has the Potatoes SA token.
2. The attacker sends one request with 2 root fields: `exportData(type: PotatoesSA)` and `users { email }`.
3. The check finds the first field that has an argument. This is `exportData(type: PotatoesSA)`. The argument is on the allowed list. The check says yes.
4. The server runs both fields. The field `users` runs with the rights of an admin. The response has the email of each user.

The attacker can also put the field with no argument first: `users { email } exportData(type: PotatoesSA)`. The check skips a field with no arguments, so it also says yes.

```
 ATTACKER (Potatoes SA token)                 SERVER
      │                                          │
      │ query {                                  │
      │   exportData(type: PotatoesSA)           │ check: first field with an argument
      │   users { email }                        │ = exportData(type: PotatoesSA) → OK
      │ }                                        │
      ├─────────────────────────────────────────►│ runs exportData   (allowed)
      │                                          │ runs users        (admin rights!)
      │◄─────────────────────────────────────────┤ export + all user emails
```

The code is in `backend/go/api/internal/gql/auth.go`.

```go
for _, set := range operation.SelectionSet {
    fields := set.(*ast.Field)                       // panics if the root is a fragment
    for _, arg := range fields.Arguments {
        return authorisedExternalQueries[...][fields.Name][arg.Value.String()]  // first argument only
    }
}
```

The loop returns on the first argument of the first field that has one. The other fields are never checked. The type assertion `set.(*ast.Field)` panics for a fragment. `isSubscriptionQuery` had the same assertion. It ran before the login check, so any caller could cause the panic.

### The fix

The check now allows one thing only: a query with 1 root field. The field must be `exportData`. It must have 1 argument, `type`, with the literal value `PotatoesSA`.

```go
func isExportDataQuery(operation *ast.OperationDefinition) bool {
    if operation.Operation != ast.Query || len(operation.SelectionSet) != 1 {
        return false
    }
    field, ok := operation.SelectionSet[0].(*ast.Field)
    if !ok || field.Name != "exportData" || len(field.Arguments) != 1 {
        return false
    }
    arg := field.Arguments[0]
    return arg.Name == "type" && arg.Value.Kind == ast.EnumValue && arg.Value.Raw == "PotatoesSA"
}
```

`isSubscriptionQuery` now checks the type of the first root selection. A fragment is not a subscription, so the request no longer panics.

```
BEFORE                                          AFTER

 query {                                         query {
   exportData(type: PotatoesSA)                    exportData(type: PotatoesSA)
   users { email }                                 users { email }
 }                                               }
 first argument is OK → ALLOWED  ✖ BAD           2 root fields → REJECTED  ✔

 query { exportData(type: PotatoesSA) }          query { exportData(type: PotatoesSA) }
 → allowed                                       1 root field, correct field and type → allowed  ✔
```

| Request from the Potatoes SA user | Result |
|---|---|
| `query { exportData(type: PotatoesSA) }` | Allowed |
| `query { url: exportData(type: PotatoesSA) }` (alias) | Allowed. The real field name is `exportData`. |
| `exportData(type: PotatoesSA)` and `users { email }` | Rejected |
| `users { email }` and `exportData(type: PotatoesSA)` | Rejected |
| `query { exportData: users { email } }` (alias that copies the name) | Rejected. The real field is `users`. |
| `exportData(type: Other)` | Rejected |
| `exportData(type: $type)` (variable) | Rejected |
| `mutation { exportData(...) }` | Rejected |
| A fragment or inline fragment at the root | Rejected |

The schema says `exportData(type: DataExportType!)`. The field has 1 argument, so the check fits. The old check also rejected a variable, so this is not a new restriction.

### What the fix does not cover

- **The token in source.** The audit reports that the Potatoes SA token is a constant in `auth.go`. We did not check this again. The fix limits what the token can do. It does not remove the token from the code.
- **The rights of the user.** The Potatoes SA user is still an admin. The gate in `AuthOperation` is the only control. A new route that skips the gate would give admin rights.
- **The check is not behind the flag.** If the export client sends the type as a variable, or sends more than 1 argument, the export fails. We found no such client in the repository. We did not look at the code of the partner.
- **No test of the full gate.** The tests call `isExportDataQuery` and `isSubscriptionQuery` directly. No test sends a request through `AuthOperation` with a Potatoes SA user.

### How to test

1. Send `query { exportData(type: PotatoesSA) }` with the Potatoes SA token. The export runs.
2. Add `users { email }` after the export field. The server rejects the request.
3. Put `users { email }` before the export field. The server rejects the request.
4. Send `exportData(type: Other)`. The server rejects it.
5. Send the type as a variable. The server rejects it.
6. Send a fragment at the root. The server rejects it. The server does not panic.
7. Send a subscription with a fragment at the root, with no token. The server returns an error. The server does not panic.

---

## Fix 5: Shipment and seller ownership checks (findings 6 and 8)

**Status:** A code review is open for the commit `e6815b5c7d16`. The new checks run only when the feature flag `SecurityReview` is on.

### The problem

Several API calls checked the role of the caller. They did not check that the shipment or profile in the request belongs to the caller. A seller or buyer with an account could act on the shipment of another customer.

The shipment ID is a long random value. It is not easy to guess, but it is not secret. It appears in URLs. A person who sees a link can use the ID.

### Words used in this section

- **Party to a shipment:** the buyer, the seller or the admin of the shipment. The shipment stores 3 profile IDs for this.
- **Role check:** a check of the type of the caller, for example seller or buyer.
- **Ownership check:** a check that the shipment or profile in the request belongs to the caller.

### How the attack works

1. Seller B has an account. Seller B gets the ID of a shipment of seller A. The ID is in a link.
2. Seller B sends `editShipment` with the ID and the intent `dispatch`.
3. The server checks the role. Seller B is a seller, so the check passes.
4. The server does not check that the shipment belongs to seller B. It dispatches the shipment of seller A.

The same gap was in these places:

- `editShipmentItem` and the truck bulk changes: a seller could dispatch, undo or edit, and a buyer could receive, a shipment that is not theirs.
- `shipmentTransactions`: the call had no check. Any signed-in user could ask for any shipment.
- `qualityReport`: any seller could read the report of any shipment.
- The inventory and pricing dashboard fields: any seller could ask for the data of any seller profile. The product filters showed the external buyers of that seller.

```
 SELLER B (own account)                  SERVER
      │                                     │
      │ editShipment(id = shipment of A,    │
      │              intent = dispatch)     │
      ├────────────────────────────────────►│ role check: is the caller a seller?  YES
      │                                     │ owner check: none
      │                                     │ → shipment of A is dispatched
      │◄────────────────────────────────────┤ success
```

The code is in `backend/go/api/internal/graph/auth_checks.go`, function `EditShipmentAuthorised`.

```go
func EditShipmentAuthorised(ctx context.Context, input model.EditShipmentInput, smt ledger.Shipment) error {
    roles := []users.PartyType{users.PartyTypeAdmin}
    switch input.Intent {
    ...
    return auth.Checks(ctx, auth.PartyTypes(roles...))   // role only
```

Two functions had almost the same name. `EditShipmentAuthorized` guards the form that opens an edit. It already checked ownership. `EditShipmentAuthorised` guards the submit. It did not. The mutations used the one with no ownership check.

### The fix

**Part 1: edits.** The function for the submit is now `EditShipmentSubmitAuthorized`. It first calls `ShipmentAuthorized`, then it does the role check.

```go
func EditShipmentSubmitAuthorized(ctx context.Context, intent model.EditShipmentIntent, smt ledger.Shipment) error {
    if features.Has(features.SecurityReview) {
        if err := ShipmentAuthorized(ctx, smt); err != nil {
            return err
        }
    }
    ...
```

`ShipmentAuthorized` passes only if the active profile of the caller is the buyer, the seller or the admin of the shipment.

```go
func (s Shipment) IsParty(profileID int64) bool {
    return s.BuyerID == profileID || s.SellerID == profileID || s.AdminID == profileID
}
```

**Part 2: reads.** `shipmentTransactions` and `qualityReport` now call `ShipmentAuthorized`.

**Part 3: dashboards.** A new function, `SellerDashboardAuthorized`, replaces the old check in 6 dashboard fields. With the flag on, it lets in an admin, or the seller whose profile it is. The old check let in any seller. The commit `280224958c12` later renames this function to `SellerAuthorized` (see Fix 6).

```
BEFORE                                          AFTER

 Seller B → shipment of seller A                 Seller B → shipment of seller A
 role check: seller → OK                         owner check: B is not buyer, seller
 → ALLOWED  ✖ BAD                                or admin of this shipment → REJECTED  ✔

 Seller A → own shipment                         Seller A → own shipment
 → allowed                                       owner check passes, role check passes → allowed  ✔
```

| Call | Who passes with the fix |
|---|---|
| `editShipment`, `editShipmentItem`, truck bulk changes | A party to the shipment, and the role for the intent |
| `shipmentTransactions` | A party to the shipment |
| `qualityReport` | A party to the shipment |
| Dashboard fields (6) | An admin, or the seller of the profile |

### What the fix does not cover

- **The checks are behind the flag.** Until the flag is on, the old behaviour stays.
- **Admins.** An admin passes only for shipments of their own admin entity. An admin of one platform cannot edit a shipment of another platform. If staff work across platforms, this can block them. For the dashboards, an admin of any platform still passes.
- **Users with more than one profile.** The check looks at the active profile only. A user who is linked to a second profile can fail the check when the request needs the other profile.
- **Other reads without an ownership check.** We found no ownership check in the resolvers `LogisticsDoc`, `TableDialog` and `ShipmentDispatchDialog`. `DocumentNumber` checks the role only. The commit does not change them. We did not trace the helper functions they call.
- **Other calls in the same finding.** The commit does not change `Seller`, `Buyer` or `AccountTransactions`. We also did not check the `Dashboards` query itself.
- **Packhouse mutations (finding 7).** This is a separate fix. See Fix 6.
- **Exposed data.** The audit judged that `shipmentTransactions` leaks little: the shipment name and the open state. The commit message says any user could read the financial transactions. We did not test which is correct. The check is right in both cases.

### How to test

1. With the flag on, a seller dispatches a shipment of the seller. The server accepts it.
2. With the flag on, another seller dispatches the same shipment. The server rejects it.
3. A buyer receives a shipment of the buyer. The server accepts it. Another buyer does the same. The server rejects it.
4. The seller of the shipment sends the intent that receives for the buyer. The server rejects it.
5. An admin of the entity of the shipment completes it. The server accepts it. An admin of another entity does the same. The server rejects it.
6. Call `shipmentTransactions` and `qualityReport` for a shipment of another customer. The server rejects both.
7. Ask for a seller dashboard as the seller, then as another seller, an admin and a buyer. Only the seller and the admin succeed.
8. Turn the flag off and repeat step 2. The old behaviour returns.

---

## Fix 6: Packhouse mutations accept any seller (finding 7)

**Status:** The fix is in the code (commit `280224958c12`). It builds on the commit of Fix 5. The stricter check runs only when the feature flag `SecurityReview` is on.

### The problem

A seller with the packhouse permission could change the packhouse stock of another seller. The seller only had to send the ID of the other seller.

Four mutations have this problem: `packhouseSetAllocation`, `packhouseItemAllocations`, `packhouseItemMixed` and `packhouseClearInventories`.

### Words used in this section

- **Packhouse stock:** the inventory and the allocations of a seller in the packhouse.
- **Packhouse permission:** the permission that a user needs to write packhouse allocations. A role such as the packhouse worker has it.
- **Seller ID:** the profile ID of the seller. The client sends it in the request.

### How the attack works

1. Seller B has an account and the packhouse permission.
2. Seller B sends `packhouseClearInventories` with the seller ID of seller A.
3. The server runs the seller check. The check passes for any seller.
4. The server runs the permission check. Seller B has the permission, so this check passes.
5. The server clears the packhouse inventory of seller A.

The check had 2 parts. The server accepts the request if one part passes.

- Part 1 is `PartyTypes(Admin, Seller)`. It passes for every seller.
- Part 2 is `PartyTypeForID(input.SellerID)`. It has no party types in the call, so the list of allowed types is empty. This part never passes.

The check meant to tie the request to the seller never worked. The check that remained did not look at the seller ID.

```
 SELLER B (packhouse permission)            SERVER
      │                                        │
      │ packhouseClearInventories(             │
      │    sellerID = seller A )               │
      ├───────────────────────────────────────►│ part 1: caller is a seller?          YES → pass
      │                                        │ part 2: caller is seller A?  (never passes)
      │                                        │ permission: packhouse write?         YES → pass
      │                                        │ → inventory of seller A is cleared
      │◄───────────────────────────────────────┤ success
```

The code is in `backend/go/api/internal/graph/schema.resolvers.go`.

```go
if err := auth.Checks(ctx, auth.PartyTypes(users.PartyTypeAdmin, users.PartyTypeSeller),
    auth.PartyTypeForID(sellerID)); err != nil {   // no party type: this check never passes
    return false, err
}
```

### The fix

The 4 mutations now use `SellerAuthorized`. This is the check that the dashboards use (Fix 5). With the flag on, the caller must be an admin, or the seller whose ID is in the request.

```go
func SellerAuthorized(ctx context.Context, profileID int64) error {
    if !features.Has(features.SecurityReview) {
        return auth.Checks(ctx, auth.PartyTypes(users.PartyTypeAdmin, users.PartyTypeSeller),
            auth.PartyTypeForID(profileID, users.PartyTypeSeller))
    }
    return auth.Checks(ctx, auth.PartyTypes(users.PartyTypeAdmin), auth.PartyTypeForID(profileID, users.PartyTypeSeller))
}
```

The call `PartyTypeForID(profileID, users.PartyTypeSeller)` has the party type. The check passes only for the seller with that ID. The old check for any seller stays in the flag-off branch.

```
BEFORE                                          AFTER

 Seller B → packhouse of seller A                Seller B → packhouse of seller A
 any seller passes → ALLOWED  ✖ BAD              B is not an admin and B is not seller A
                                                 → REJECTED  ✔

 Seller A → own packhouse                        Seller A → own packhouse
 → allowed                                       the seller of the ID → allowed  ✔

                                                 Admin → packhouse of any seller → allowed  ✔
```

| Caller | Flag on | Flag off |
|---|---|---|
| The seller in the request | Allowed | Allowed |
| Another seller | Rejected | Allowed |
| An admin | Allowed | Allowed |
| A buyer | Rejected | Rejected |

The permission check for the packhouse stays. A caller must pass the seller check and have the permission.

### What the fix does not cover

- **The check is behind the flag.** Until the flag is on, any seller with the permission can still use the 4 mutations on another seller.
- **Admins.** An admin of any platform passes. The check does not tie an admin to the platform of the seller.
- **The Farmer app queue.** The Farmer app keeps packhouse changes in an offline queue. Each queued change stores a `sellerID` in its payload. The server checks the ID when the change is sent. If the user changes profile before the queue is sent, the server rejects the change. The commit message says the app sends the profile ID of the caller. We saw the stored payload. We did not trace where the app gets the ID.
- **The web app.** The web app calls two of the mutations (`PackhouseItemAllocations` and `packhouseClearInventories`). We did not check which ID it sends.
- **Users with more than one profile.** With `MultiProfileAuth` on, the check passes for any linked seller profile that has the same status. Without it, only the active profile passes.

### How to test

1. With the flag on, a seller with the packhouse permission calls each of the 4 mutations with their own seller ID. The server accepts them.
2. With the flag on, the same seller calls each mutation with the ID of another seller. The server rejects all 4.
3. An admin calls each mutation with the ID of a seller. The server accepts them.
4. A buyer calls a mutation. The server rejects it.
5. Turn the flag off and repeat step 2. The old behaviour returns.
6. In the Farmer app, send a queued change after the user changes profile. Look at the result.
