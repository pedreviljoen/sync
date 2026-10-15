# Candidate for verifier-v05
Fingerprint: backend/functions/firebase/functions/functions-env-committed-api-keys
Proposed verdict by hunter: needs_validation

Files backend/functions/firebase/functions/.env.nile-production, .env.nile-staging, .runtimeconfig.json hold NILE_API_KEY / nile_api.key values; functions/.gitignore lists only 'lib'; target is a Sapling checkout so git tracking unknown (look for .sl / .gitignore / .hgignore / root .gitignore at /Users/pedreviljoen/Documents/work/nile/core and its Sapling ignore config, and whether these files are ignored by those; the repo root .gitignore may cover .env*). Determine whether the files plausibly are tracked, whether anything consumes NILE_API_KEY (config.ts, priceMailer disabled), and what the key authenticates to. Do NOT print values. Decide verdict (rejected if ignored/unused with no boundary).

Use this exact fingerprint in your record.
