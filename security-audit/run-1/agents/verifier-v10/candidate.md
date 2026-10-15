# Candidate for verifier-v10
Fingerprint: gerrit-webhook-unauthenticated-event-forgery
Proposed verdict by hunter: confirmed (source-level, medium)

backend/go/gerrit/terraform/functions.tf ~:67-74 grants roles/run.invoker to allUsers on gerrit-webhook with comment claiming Gerrit HMAC verification; backend/go/gerrit/functions/webhook/webhook.go Handle (~:62-99) reads body, dispatches on body-supplied type with no signature/secret/IP check; handleChangeMerged (~:290-358) trusts Branch/NewRev, RecordMerge sets targetSha (task/deploys.go ~:76-83), CreateDeploy staging; agent (agent/main.go ~:658-669, agent/actions/git/checkout.go ~:60-100) fetches and resets to ref and deploys to staging; tryAutoSubmit (~:256-280) relies on Gerrit submittable checks. scheduler.tf calls the function with no oidc_token. Verify there is truly no auth anywhere (middleware, functions.go entry points, any HMAC in a shared lib), what an attacker must know (function URL, a fetchable SHA), whether production is unreachable, whether the agent has other guards (deploy.go stale check, branch checks, Gerrit-side validation of the ref), and severity.

Use this exact fingerprint in your record.
