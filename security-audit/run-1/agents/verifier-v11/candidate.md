# Candidate for verifier-v11
Fingerprint: harvester-potatoessa-unzip-path-traversal
Proposed verdict by hunter: needs_validation

backend/go/harvester/internal/ops/potatoesSA/methods.go: getZipFileURL (~:50-63) reads JSON url from fixed https://api.potatoes.co.za endpoint; downloadZipFile (~:74) fetches it; unzipFile (~:110-132) path.Join(os.TempDir(), date+'_'+f.Name) with no '..' containment, os.Create/io.Copy; directory entries os.MkdirAll. Claim: zip-slip by a malicious/compromised provider. Verify exact path arithmetic (does the '_' prefix actually neutralise '../'? path.Join cleaning of 'dateX_../../x'), whether the provider is a plausible lower-trust principal (it is a third-party data feed), what the harvester process can write, and decide verdict (rejected if not exploitable, needs_validation if only deployment facts missing, confirmed only if directly established with meaningful boundary).

Use this exact fingerprint in your record.
