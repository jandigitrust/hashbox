# Image foundation templates and version request

The demo uses ARM templates for one private staging account, one Compute
Gallery and one Gen2 Linux image definition. The version imports the verified
Page Blob and carries the public UEFI DB certificate through one conditional
Compute REST PUT (`2025-12-03`, `If-None-Match: *`). The request body and its
SHA-256 are saved in the run directory before submission. Storage Shared Key
is enabled because Azure Compute Gallery's VHD import requires account-key
permission; the builder uploads and verifies through its managed identity.

The image definition's `TrustedLaunchAndConfidentialVmSupported` feature is
the documented setting for custom UEFI DB settings on a CVM-capable image.
A missing UEFI profile in Gallery GET is inconclusive and requires guest
verification; an explicitly different certificate fails. The demo does not
create a Trusted Launch VM. The root `ARM_TEMPLATE_LOCK.json` tracks current
template hashes, and `ARM_TEMPLATE_CHANGELOG.md` records template changes.
