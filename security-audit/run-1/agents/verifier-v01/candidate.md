# Candidate for verifier-v01
Fingerprint: auth/hardcoded-shared-robot-token
Proposed verdict by hunter: confirmed (source-level)

Hardcoded shared robot token literal in backend/go/auth/auth.go (~:30) accepted unconditionally in userFromIDToken (~:468) on the public /graphql path (AuthOperation wired at api/cmd/server/main.go:120); X-Platform (caller-chosen) selects the tenant robot via DetermineRobotUser (~:246). Same literal in backend/functions/firebase/functions/src/pdf.ts:30. Hunter severity: medium (likelihood medium, impact high). Consider: who is the lower-trust principal (anyone with repo/source copy or leak)? Does source gate on environment? What can a Robot user actually do (check access/permissions RobotUserPermissions and resolvers)? Is 'secret committed in source' itself a boundary violation here?

Use this exact fingerprint in your record.
