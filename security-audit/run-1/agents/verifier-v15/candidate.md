# Candidate for verifier-v15
Fingerprint: H5-setuser-self-role-escalation
Proposed verdict by hunter: confirmed (source-level, high)

api/internal/graph/schema.resolvers.go Form mutation ~:1149-1153: FormTypeSetUser authorized if Admin OR auth.Email(<client-supplied email field>); form_input.go handleSetUser (~:516) -> customers.UserInput (customers/user.go ~:100-200) parses firebase id, roles, password, profileID from client fields -> administrator/internal/ops/users/update.go (~:55,85) updates password (UpdateUserPassword), roles (userroles.MatchTx) and pushes claims. Claim: any authenticated user can set arbitrary roles on self (or password/roles of another UID when supplying own email). Verify every hop for checks: the Form() type gate, any role/permission check inside handleSetUser/customers.UserInput, whether the target id is forced to caller, administrator-side authorization in users/update.go and the gRPC UserUpdate handler, and whether role claims change takes effect. Decide verdict/severity strictly from evidence.

Use this exact fingerprint in your record.
