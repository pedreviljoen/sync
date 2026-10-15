# Candidate for verifier-v04
Fingerprint: backend/functions/firebase/functions/src/pdf.ts-generatePdf-url-ssrf-token-exfil
Proposed verdict by hunter: needs_validation

Firebase function generatePdf (backend/functions/firebase/functions/src/pdf.ts): onRequest, cors origin:true, no auth in code; takes request.query.url (~:19), appends hardcoded robot token (~:27-30), page.goto(url) in Puppeteer --no-sandbox (~:49), returns PDF. Claim: token sent to attacker-chosen host; SSRF/file render. Check: any URL/host validation, deploy options in index.ts/firebase.json that restrict invoker, whether the token in the URL is what the Go API accepts (auth.go), and what is source-visible about invoker IAM. Also assess name param injection (footer HTML / Content-Disposition). Decide verdict.

Use this exact fingerprint in your record.
