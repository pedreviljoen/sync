# Findings detail (confirmed medium/high/critical)

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

