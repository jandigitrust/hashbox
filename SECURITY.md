# Security boundary

This Azure CVM demo is not a production security claim. The signed Secure Boot
image path and required guest checks are described in [PLAN.md](PLAN.md). The
current source revision has not completed a fresh end-to-end live run.

Keep Azure credentials, private keys, local profile state and unredacted logs
outside the publishable source. The UEFI DB signing key exists only in an
owner-only builder tmpfs during post-build signing. A successful build or
Gallery publication alone does not prove that the deployed guest booted with
Secure Boot enabled.

There is no published security contact or disclosure SLA for this draft.
