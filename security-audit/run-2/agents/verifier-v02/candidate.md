# Candidate for verifier-v02
Fingerprint: c3-fileviewer-iframe-unvalidated-src
Proposed verdict by hunter: needs_validation

Claim: client/market/src/components/SubTableActionCard/RowDetailItem.tsx (~:83) passes server-provided file/image URL strings to Files.tsx (~:15) -> FileViewer.tsx (~:38,172) which renders <iframe src={src}> for non-image content with no scheme/host validation; a javascript: or data: URL would execute in the market origin when the viewer clicks. Verify the client code exactly (does ref(storage, src) failing gate rendering? is the iframe sandboxed? are these values only ever Firebase Storage URLs by construction?) and trace the origin of these values into the backend: find how file/image field values are submitted (client/market/src/components/FileEditNew.tsx upload then the form field value) and whether backend form handlers (backend/go/api/internal/graph/form*.go, field parsing e.g. field.ParseValidURLs which only does url.Parse) accept arbitrary strings for file fields and return them in table row details. Decide needs_validation vs confirmed (source-only: confirmed only if the entire path from a lower-trust user to another user's render is established with no validation anywhere) vs rejected.

Use this exact fingerprint in your record.
