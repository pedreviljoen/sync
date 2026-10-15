# hunter-h6 result (parent's condensed record; full JSON was returned in-session)
Unit: Resource/file handling + crypto + injection (harvester, fortknox, seshat, ledger, mache) -> disposition: candidate
Candidate (needs_validation): harvester-potatoessa-unzip-path-traversal
 - backend/go/harvester/internal/ops/potatoesSA/methods.go:50 (getZipFileURL) -> :74 downloadZipFile -> :110 unzipFile -> :125 path.Join(os.TempDir(), date_+f.Name), :126 os.Create, :118 os.MkdirAll; no containment check.
 - Blockers: harvester container user/fs perms; whether PotatoesSA provider is a lower-trust principal.
Rejected as findings (hardening only): fortknox AES-CTR no MAC (ciphertext only server-written; random IV; key length fails closed); seshat OData %s filters (inputs numeric-derived); potatoesSA download follows provider URL with no size limit; zip bomb.
Uncovered (not reviewed): ledger shipmentdocs/apuat DownloadFileToDir, mache filestore, nexport, harvester docs archiver/chromedp, billing, repo-wide exec/weak-rand/InsecureSkipVerify/hardcoded-secret/SQL Sprintf sweep.
