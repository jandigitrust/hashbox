# HashBox Preview architecture

The checkout launcher `bin/hashbox` and virtual-environment launcher
`.venv/bin/hashbox` enter the Python CLI in `src/hashbox/cli/`. The supported
commands are read-only `regions` and `list`, `run`, bounded builder `resume`,
read-only `status` and `instance list`, `instance create/delete`, `group delete`
and owned group `cleanup`. `attestor check/upgrade/build` manages a separate
pinned source artifact. `src/hashbox/providers/azure/demo.py` keeps the
fresh build order; `instances.py` manages later CVMs. `src/hashbox/operation/state.py` is the sole mutable run-record
writer and commits checkpoints before Azure effects.

The profile reader selects one subscription ID, region, VM sizes and SSH key.
The controller verifies Azure CLI access to that subscription; Azure calls
and OpenTofu receive the explicit ID. Region discovery reads subscription
locations, exact Compute SKUs and family, regional and VM-count quotas;
`run --region` saves the
operator's choice before builder, Gallery or CVM effects. Owner-only profiles
and run records live in ignored `.local/`. See the [setup guide](../README.md)
for prerequisites.

| Module | Responsibility |
| --- | --- |
| `admission.py` | Account, provider, region, quota and retail price reads. |
| `resources.py` | Exact group ownership and bounded ARM deployments for staging, Gallery parent, definition and CVM. |
| `builder.py` | OpenTofu builder, pinned SSH Guix build, Secure Boot signing, bounded retained-builder restart and retirement. |
| `gallery.py` | Private Page Blob upload/readback and one conditional REST Gallery version publication. |
| `cvm.py` | Exact-version CVM deployment, Azure-serial-pinned guest SSH, UEFI db and TPM proof, failure deallocation. |
| `instances.py` | Run-owned CVM inventory, extra-instance admission, exact resource deletion and CVM group deletion. |
| `cli.py` | Bounded Azure CLI calls and instance power-code parsing. |
| `src/hashbox/build/remote.py` | Pinned-host SSH transport shared by builder and guest. |
| `src/hashbox/source/attestor.py` | Exact Attestor source pin, upstream advisory, verified source fetch and OCI archive identity. |

The builder receives a bounded, history-free source archive. It builds a
Guix Azure Gen2 VHD, then signs the default EFI entry using a disposable
tmpfs key. Only the public certificate leaves signing. The builder identity
uploads the signed VHD as a private Page Blob and downloads it for a full
SHA-256 readback.

The Gallery and image definition use ARM templates. Version publication saves
the Compute REST body and its SHA-256, records
the exact version ID, and sends one `If-None-Match: *` PUT. A bounded GET
readback checks provisioning, tags and Blob identity. Missing UEFI settings
in final GET are inconclusive; an explicitly different certificate fails.
The guest proof is required before completion. An earlier revision of this
publication path completed a live run with guest UEFI db verification.

The temporary Blob role is removed after publication. The builder is retained
deallocated by default with its Guix store, disk and public IP. A later run
may borrow it after matching the subscription, region, size, SSH key, exact
Azure IDs and ownership tags. It uses a separate workspace and records the
original owner. A local pool lock serializes builder use and deletion.
`--fresh-builder` bypasses reuse; `--delete-builder` creates and removes a
fresh builder.
The first CVM is created in a tagged group from the exact Gallery version. The
operator can choose this group's new name and the first VM name; both are saved
in the run record. Later CVMs get proposed numbered names, their own network
resources and the same Gallery version. Instance list reads Azure, and
instance deletion checks every exact resource ID and tag before removing it.
Azure readback checks `ConfidentialVM`, `VMGuestStateOnly`, vTPM, Secure Boot
and running power. The guest SSH key is matched to Azure serial output; the
guest UEFI db is parsed for the expected X.509 DER SHA-256, with Secure Boot
enabled and a TPM 2.0 device. `group delete` removes the owned CVM group;
`cleanup` removes only exact owned groups, never a borrowed builder. Owner
cleanup refuses while a borrowing run is unfinished. Both refuse a CVM group containing
unowned resources.

The selected OCI hello source is in `services/oci-hello/`. Its existing
`toolchain/oci/` scripts verify an OCI archive and launch static `crun` on
guest loopback. A pinned SSH tunnel can reach the service. OCI has no CLI route
or reboot restart policy in this demo.

`ATTESTOR_LOCK.json` pins Attestor's Git commit and source-file digests;
`services/attestor/Dockerfile` builds an OCI artifact from that source on the
native `linux/amd64` Azure builder. The CLI checks upstream before a fresh
run, builder resume, standalone Attestor build and extra CVM deployment, but
never silently changes the pin. `make image` creates and verifies the OCI
archive before Guix consumes it. The Guix declaration embeds its archive and
metadata, sets IMA boot arguments, mounts `securityfs` in the initrd, makes
the IMA log readable and grants the operator account TPM device access. The
runtime Docker stage checks shared libraries before embedding. An operator
prepares the OCI bundle in guest tmpfs and launches it with rootless `crun`
on guest loopback; tmpfs contents are lost on reboot.
`toolchain/attestor/verify-local.py` checks the live Azure and guest binding,
collects two reports over pinned SSH, commits the first IMA/PCR snapshot as a
local reference, and runs Confido `main` against the second challenge. This
path passed a live verification in an earlier revision. The first snapshot is
self-enrolled evidence, not an independently approved registry reference, and
the Confido result does not establish TLS session binding.
