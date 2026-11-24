# HashBox Preview: Minimal Secure Boot CVM Path

Status: a previous revision's live image passed the guest UEFI db check and a separately
launched Attestor OCI container has passed local Confido verification with a
self-enrolled reference. The current source revision still needs its own live
proof; each new run verifies its own artifacts and guest.

## Goal and scope

Keep one operator journey in Python, Guix and Azure:

```text
local Python CLI -> owned Azure builder -> Guix Gen2 VHD -> signed VHD
                 -> private Page Blob -> exact Gallery version -> first CVM
                                                       -> optional more CVMs
```

The builder produces the VHD; the operator machine holds the owner-only run
record. The first CVM and optional additional instances share one run-owned
CVM group and exact Gallery version. Every CVM uses Secure Boot, vTPM and
`VMGuestStateOnly`. One selected
OCI hello service is available through scripts after CVM deployment; OCI
build and launch are not part of the CLI.

Attestor `0.2.0` source is pinned by exact commit. The CLI checks upstream and
can select a newer descendant. A fresh run builds its OCI archive from that
source on the native Azure builder and embeds it in the Guix image. The
Attestor update check is advisory before new builds and CVM deployments; it
does not change an existing Gallery version. Confido runs on the operator's
machine against a separately selected local `main` checkout.

Keep the pinned Guix image inputs, post-build disposable Secure Boot signing
key, private Blob byte readback, exact resource group ownership, cost display
and explicit cleanup. Do not add a test suite, QEMU, guard, Trusted Launch
probe or generic workflow engine. Claim attestation only after a fresh guest
report passes the local Confido verifier. The Gallery definition's
`TrustedLaunchAndConfidentialVmSupported` metadata remains because Azure uses
it for the custom UEFI DB and CVM-compatible image; there is no Trusted
Launch VM in the journey.

## Supported commands

```text
.venv/bin/hashbox regions --profile PROFILE
.venv/bin/hashbox run --profile PROFILE --region REGION [--group NAME] [--name NAME]
.venv/bin/hashbox list
.venv/bin/hashbox instance list RUN_ID
.venv/bin/hashbox instance create RUN_ID [--name NAME]
.venv/bin/hashbox instance delete RUN_ID INSTANCE_NAME
.venv/bin/hashbox group delete RUN_ID
.venv/bin/hashbox resume RUN_ID
.venv/bin/hashbox status RUN_ID
.venv/bin/hashbox cleanup RUN_ID
.venv/bin/hashbox attestor check
.venv/bin/hashbox attestor upgrade
.venv/bin/hashbox attestor build [--fetch-only]
```

`bin/setup-venv` prepares the local CLI without a package download;
`bin/hashbox` runs directly from the checkout. Both select the same project
root and owner-only run state.

The profile names one subscription, region, builder and CVM size, exact
Ubuntu builder image version or an admitted resolution, SSH public-key file
and operator IPv4 `/32`. `hashbox.toml` remains only the project root marker.
No SSH-agent or default-key selection is used.
Azure CLI and OpenTofu calls receive the profile's explicit subscription ID;
the Azure CLI default subscription need not match.
`regions` scans physical customer regions for the exact CVM and builder SKUs,
their subscription restrictions, both VM-family and total regional vCPU
quotas, and VM-count quota. The operator selects a ready region with
`run --region`; the selected location is saved in the run and used for builder,
Blob, Gallery and CVM.
`run` rechecks its region before effects; quota does not guarantee capacity.
The CVM group and first VM receive generated names, with optional operator
overrides saved in the run record before creation. The CVM group must be new.
`list` and `instance list` count Azure VMs in locally recorded owned groups.
`instance create` reuses the saved exact Gallery version, rechecks CVM quota,
price and source identity, then repeats the Azure and guest proof for one new
VM. It proposes the next numbered name unless the operator sets `--name`.
`instance delete` removes only that VM and its recorded-name disk and network
resources after exact ID and tag checks. `group delete` removes the entire
owned CVM group; `cleanup` removes this run's owned image and builder groups.

By default a completed run retains its builder deallocated. A later run with
matching subscription, region, builder size and SSH key reuses it after fresh
Azure identity and ownership checks. Each run has a separate workspace, while
the Guix store remains cached. `--fresh-builder` bypasses reuse;
`--delete-builder` creates and removes a fresh builder. Borrower cleanup
never deletes the original builder.

`resume` is limited to an existing builder at `source-on-builder`,
`builder-install-resume-submitted`, `builder-ready`, `resume-builder-wait` or
`blob-role-created`. It verifies the saved archive and
remote source before continuing. It starts an exact owned deallocated builder
and can restart an interrupted Guix build only when no process or VHD remains,
with a bounded attempt count. It does not replay an uncertain Gallery
write. `status` reads current Azure facts. `cleanup` checks exact group IDs
and run tags before deleting CVM, image and builder groups in that order.
Owner-only run records and request bodies remain under `.local/`.

## Fresh-run steps

1. Resolve the explicit profile, Azure subscription, providers, region, VM
   sizes, vCPU quota, current retail compute prices and SSH key pair. Capture
   a bounded history-free source archive and reserve three fresh group names.
2. Reuse an exact compatible builder or create a new one with OpenTofu. Pin
   its SSH host key, upload the
   exact archive, install Guix and Azure CLI, build the pinned Attestor OCI
   archive on the builder, and build the raw and fixed VHD with it embedded.
3. After the build finishes, sign the default EFI entry with a disposable key
   in builder tmpfs. Verify the signed VHD and public UEFI DB certificate,
   record their SHA-256 values, and verify private key workspace removal.
4. Create the private image group and staging account. Give the builder only
   the temporary Blob role, upload the signed VHD as a Page Blob, download it
   on the builder and match the full SHA-256 and size.
5. Create Gallery and image definition with their retained ARM templates.
   Confirm the definition's exact ID, ownership and security feature. Save
   the version `1.0.0` REST request body and SHA-256 in the owner-only run
   directory. Record the exact version ID and a submission checkpoint, then
   send one Compute REST `2025-12-03` PUT with `If-None-Match: *`.
6. Wait a bounded period for `Succeeded`, then read the exact version ID,
   tags, source Blob and UEFI settings. A missing `securityProfile` requires
   the guest proof; an explicitly different certificate blocks the run.
   An uncertain PUT reply is never retried automatically.
7. Remove the temporary Blob role and deallocate the builder by default.
   `--delete-builder` removes a fresh builder group instead. Create one owned CVM
   group, deploy the CVM from the exact version, and verify Azure reports
   `ConfidentialVM`, `VMGuestStateOnly`, Secure Boot, vTPM and running power.
   Pin the guest SSH key against Azure serial output and parse its UEFI db
   for the exact DER certificate SHA-256. Confirm Secure Boot and TPM 2.0.
8. Leave the image and CVM groups for explicit cleanup; a retained builder's
   disk and public IP also remain billable. Additional CVMs can be
   deployed from the same exact version in that CVM group. On failure, preserve
   the run record and owned groups; deallocate the builder or CVM where the
   existing failure path can verify ownership.

## Acceptance boundary

The fresh-run path has completed a live build, Gallery publication and guest
UEFI db check. A separate live step launched the embedded Attestor and verified
a second fresh challenge with Confido against a first-snapshot reference of
150 ordered IMA measurements and quoted SHA-256 PCR 10. Every new run must
establish Azure admission and verify its own signed VHD, Gallery version, CVM
configuration and guest before completion.
The additional-instance create and delete commands have local and read-only
Azure checks but no new live multi-instance proof yet.
The selected OCI hello source and Compose files are separate from the demo
CLI; `toolchain/oci/` supplies the guest bundle and `crun` launcher. OCI CLI
automation is a separate task. The Guix declaration enables IMA, makes its
log readable and grants the guest operator TPM access. The builder embeds an
Attestor OCI image whose runtime libraries are checked during build. The
operator launches it from guest tmpfs, collects evidence over pinned SSH and
runs Confido locally. The exact first-snapshot reference and its local commit
are owner-only evidence; independent baseline approval and signed registry
publication remain separate work. The evidence-only result does not
authenticate a TLS application session.
