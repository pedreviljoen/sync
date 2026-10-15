# Candidate for verifier-v06
Fingerprint: c7-mock-prod-storage-capability-urls
Proposed verdict by hunter: needs_validation

Claim: client/market/src/mocks/buyersMarket.mock.ts (~:56,61), client/market/src/mocks/catalogMarket.mock.ts (~:81,86), client/market/src/components/Files.stories.tsx (~:14,15), FileViewer.stories.tsx (~:13) contain full firebasestorage.googleapis.com download URLs for the nile-production bucket with ?alt=media&token=... query tokens (capability URLs), for images/<uuid>.jpg objects. Verify the occurrences, whether the bucket is production (nile-production) vs placeholder, whether the objects look real (UUID names) vs obvious dummies, whether these files are bundled into production builds (mocks/stories excluded from vite build? check vite.config, tsconfig, storybook only), what the content likely is (product photos: look at the mock context), and any other tokenised URLs elsewhere under client/. Impact is likely low (product images). Decide needs_validation, rejected (if clearly placeholders/test images with no sensitive content) or note informational. Do not print token values.

Use this exact fingerprint in your record.
