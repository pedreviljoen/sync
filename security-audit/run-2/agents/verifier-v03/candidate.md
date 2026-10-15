# Candidate for verifier-v03
Fingerprint: c4-ios-ci-sentry-token-echoed-to-build-log
Proposed verdict by hunter: needs_validation

Claim: client/ios/Nile/ci_scripts/ci_post_xcodebuild.sh line ~11 `echo "SENTRY_AUTH_TOKEN: ${SENTRY_AUTH_TOKEN:+SET (hidden)}${SENTRY_AUTH_TOKEN:-NOT SET}"` prints the token value when set (':-' expands to the value when set and non-empty), and the script requires the token (later lines) so the real CI run always has it set; readers of Xcode Cloud build logs could obtain a Sentry auth token (org nile-ag). Verify the shell semantics rigorously (POSIX parameter expansion; which shell does the script use: check shebang; whether the line is inside a conditional), the exact line numbers, whether other lines echo secrets, and what the token is used for (sentry-cli upload-dif). Platform behaviour (Xcode Cloud secret masking) and log reader set are deployment facts: keep needs_validation if semantics hold. Reject if the expansion cannot print the value. A second hunter independently reported the same bug (do not rely on that).

Use this exact fingerprint in your record.
