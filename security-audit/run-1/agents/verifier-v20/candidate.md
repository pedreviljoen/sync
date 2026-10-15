# Candidate for verifier-v20
Fingerprint: H5-logo-ssrf
Proposed verdict by hunter: needs_validation

Profile logo URL stored via company form (api/internal/graph/customers/company.go ~:631; ParseValidURLs in api/internal/form/field/field.go ~:811-826 only url.Parse) becomes doc.Info.Logo (graph/sourcedoc.go ~:46-54, :311-318) and is fetched by LogoCache.fetch (api/docs/docpdf/logocache.go ~:96-107) with an unrestricted http client when a document PDF renders (/docs/pdf, api/docs/handler.go). Claim: blind SSRF. Verify who can set the logo resource (seller? admin only? which role), whether render happens in the API process with internal reachability, what a blind GET with image decode yields, response exposure, and decide verdict (rejected if low value / same-principal; needs_validation if egress facts decide).

Use this exact fingerprint in your record.
