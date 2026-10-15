# Candidate for verifier-v13
Fingerprint: H5-unauth-opname-bypass
Proposed verdict by hunter: confirmed (source-level, high)

backend/go/auth/auth.go AuthOperation (~:373-419): Authorization 'unauthenticated' yields UsrUnauthed (~:172-179, PartyTypeBot, ProfileID 0); rejected only if op.Operation.Name not in publicOperations (~:404,422: ValidateCurrentToken, SignUp, Signup) - the name is client-chosen. Claim: any selection set can run anonymously by naming the operation Signup; resolvers without internal authorization (e.g. api/internal/graph/schema.resolvers.go ~:2786 LogisticsDoc, ~:1932 UpdateClaims, ~:1130 UploadPop) then execute. Verify precisely: how op.Operation.Name is obtained, whether checkPlatform/other middleware/gqlgen directives/field middleware (e.g. api/internal/graph directives, resolver middleware, FieldMiddleware, OperationMiddleware in main.go) block unauthenticated users later, whether UserFromContext/Unauthed user is rejected by common resolver wrappers, and confirm at least one concrete reachable resolver with real data impact (not merely the gate). Severity must follow actual reach.

Use this exact fingerprint in your record.
