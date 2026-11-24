# ARM template change log

`ARM_TEMPLATE_LOCK.json` records the exact SHA-256 of each current ARM template.
The active set is:

| Template | Purpose |
| --- | --- |
| `infra/providers/azure/cvm/staging.arm.json` | Private Page Blob staging account and container. |
| `infra/providers/azure/cvm/gallery.arm.json` | Run-owned Compute Gallery. |
| `infra/providers/azure/cvm/gallery-definition.arm.json` | Gen2 Linux image definition with CVM-compatible security features. |
| `infra/providers/azure/deployment/cvm.arm.json` | Secure Boot Confidential VM from an exact Gallery version. |

## Template history

The Gallery template gained run ownership tags and cleanup settings. The image
definition was narrowed to one Gen2 Linux CVM-compatible image. The staging
template was added for the private Page Blob. The CVM template dropped an
optional shutdown schedule while retaining its security settings.

The former Gallery-version template changed its Compute `apiVersion` from
`2025-03-03` to `2025-12-03` and its `contentVersion` from `1.0.0.0` to
`1.1.0.0`. It was later retired when version publication moved to one
conditional Compute REST PUT with a saved request body. The Gallery,
image-definition, staging and CVM templates remain in use.

The current lock revision is 4. This editorial pass removed a legacy source
commit field from lock metadata; **no ARM template bytes changed**. Literal
file digests live in the lock rather than this publishable narrative. The
revised normal publication path has since completed a live build and guest
UEFI db proof. This interface change did not alter ARM template bytes.

## Change procedure

Before editing an ARM template, preserve its current bytes and locked digest
in an owner-only change record. Describe the exact file and fields changed,
reason, validation and live result here. Bump that template's `contentVersion`,
update its digest in `ARM_TEMPLATE_LOCK.json`, and advance the lock revision.
Announce any ARM template change to the user in **BOLD UPPERCASE**. Verify the
lock before Azure effects. A successful deployment is not acceptance: inspect
resource readback and the relevant guest state.
