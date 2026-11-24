# HashBox Preview

HashBox Preview is a checkout-based command-line demo. It builds a signed Guix Gen2
VHD on an Azure **builder**, stages it in a private Page Blob, publishes one
Azure Compute Gallery image version, and boots a Secure Boot Confidential VM
(CVM). More CVMs can be created from that exact version in the same run-owned
CVM resource group. There is no interactive console or web UI. The CLI is
`hashbox`.

## Requirements

Run the controller from a macOS or Linux machine with:

- Python 3.11 or newer, including `venv`;
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli/) (`az`), installed on the host and signed in with `az login`;
- OpenTofu 1.8 or newer; the builder module pins the AzureRM provider in its
  checked-in lock file;
- Git, for cloning this checkout and checking the selected Attestor source;
- OpenSSH client tools: `ssh`, `scp`, `ssh-keygen` and `ssh-keyscan`;
- outbound HTTPS to Azure, the Azure retail-price API and the OpenTofu provider
  registry, plus SSH access to the builder and CVM public IPs on port 22.

Guix runs on the Ubuntu builder, so the host does not need it. The run also
installs Azure CLI on the builder for Blob transfer; the host still needs its
own Azure CLI session. A local OCI builder is needed only if you later build
the separate [hello service](services/oci-hello/README.md). The Azure builder builds Attestor with Docker Buildx
on native `linux/amd64` before building Guix; it needs access to GitHub, the
pinned base images and the Rust package registry. The optional standalone
`attestor build` command needs the same native Docker host.

An active Azure subscription (state `Enabled`) must be accessible to the
signed-in identity. That identity must be allowed to
create and delete resource groups, VMs, disks, networks, storage and Compute
Gallery resources; run ARM deployments; read VM boot diagnostics and invoke VM
Run Command; and create and delete a temporary **Storage Blob Data Contributor**
role assignment on the staging storage account. The resource providers
`Microsoft.Compute`, `Microsoft.Network`, `Microsoft.Storage` and
`Microsoft.Resources` must be registered. The demo creates new image and CVM
groups. A later compatible run can reuse a retained builder group.

Region discovery checks the selected builder and CVM SKUs, subscription
restrictions, family and total regional vCPU quotas, and the regional VM-count
quota. The run checks its
chosen region again and reads current compute prices before creating resources.
[Azure quota and capacity are separate](https://learn.microsoft.com/en-us/azure/virtual-machines/quotas), so
a region reported ready can still reject a deployment.

**This run creates billable Azure resources.** The builder is retained
deallocated by default so the next compatible run can reuse its Guix store.
Its disk and public IP remain billable. `--delete-builder` creates a fresh
builder and removes it after publication; `--fresh-builder` creates a new
retained builder. The image and CVM groups remain until explicit cleanup. Each
extra instance adds a VM, disk, public IP and network resources. Disks,
public IPs, Blob storage, Gallery replicas and transfer can add to the VM
prices shown before the first resource is created.

## Set up the CLI

Clone the repository and prepare a virtual environment:

```sh
git clone https://github.com/jandigitrust/hashbox.git
cd hashbox
./bin/setup-venv
.venv/bin/hashbox --help
```

The setup script creates ignored `.venv/` and a checkout launcher using its
Python interpreter. It needs no package download or Azure access; `make setup`
does the same.
The CLI has no third-party Python runtime dependencies. If your `python3` is
too old, set `HASHBOX_PYTHON` to a Python 3.11+ executable before setup.
The repository also has standard `pyproject.toml` metadata, so
`.venv/bin/python -m pip install -e .` is available when Python package build
dependencies can be downloaded.

The checkout launcher `bin/hashbox` also works without installation. Both
checkout launchers find the project from their own path. If you use a
`pip`-installed command from outside the checkout, set `HASHBOX_PROJECT_ROOT`
to its absolute path. All forms use the same CLI and local run records.

## Select the Azure subscription and profile

Sign in with Azure CLI and check access to the subscription you will put in
the profile:

```sh
az version
az login
az account show --subscription YOUR_SUBSCRIPTION_UUID \
  --query '{name:name,id:id,state:state}' --output table
```

Create an owner-only profile and SSH key. The key stays outside the checkout;
the private key must be unencrypted because the CLI uses noninteractive SSH.
The commands below keep an existing key pair and profile. If only one file in
the key pair exists, choose another basename and update
`access.ssh_public_key` in the profile.

```sh
umask 077
mkdir -p "$HOME/.ssh" .local/profiles
chmod 700 "$HOME/.ssh" .local/profiles
if [ ! -e "$HOME/.ssh/hashbox-demo" ] && [ ! -e "$HOME/.ssh/hashbox-demo.pub" ]; then
  ssh-keygen -t ed25519 -N '' -f "$HOME/.ssh/hashbox-demo"
fi
if [ ! -e .local/profiles/dev.toml ]; then
  cp examples/dev.toml .local/profiles/dev.toml
fi
chmod 600 "$HOME/.ssh/hashbox-demo" .local/profiles/dev.toml
```

Edit `.local/profiles/dev.toml`:

| Field | What to enter |
| --- | --- |
| `subscription_id` | The UUID checked with `az account show --subscription`; this is the subscription the demo uses. |
| `location` | Default Azure region if `run --region` is omitted. |
| `build.vm_size` | An available Ubuntu builder VM size. |
| `build.source_image_version` | `auto` resolves and records an exact Ubuntu 24.04 image version before creation; an explicit version also works. |
| `deployment.vm_size` | A Confidential VM size available in the region. |
| `access.ssh_public_key` | Path to the `.pub` file; the matching owner-only private key must be beside it without `.pub`. |
| `access.ssh_source` | Your current public IPv4 address with `/32`, for example `203.0.113.10/32`. You can check the address with `curl -4 https://api.ipify.org`. |

The sample VM sizes are illustrative; Azure availability and quota are checked
for the selected subscription. The profile file must be owned by the operator
and readable only by that user (`0600`). The profile holds no Azure password or
private key. The controller uses the Azure CLI session; OpenTofu must also be
authenticated to this subscription, without conflicting Azure credential
environment variables. `--profile dev` loads `.local/profiles/dev.toml`;
another name loads the correspondingly named
file. `HASHBOX_DEMO_PROFILE_FILE` can point to an owner-only profile elsewhere,
but its `name` must still match `--profile`. The profile's subscription ID is
authoritative: the controller passes it explicitly to Azure CLI and OpenTofu
and checks that the signed-in identity can read it. Azure CLI's default
subscription may differ. Use `az account set --subscription ...` only if you
also want your manual Azure CLI commands to default to this subscription.

## Find and choose a region

```sh
.venv/bin/hashbox regions --profile dev
```

`regions` is read-only. It scans the subscription's physical customer regions
for the exact CVM and builder sizes in the profile, CVM capability, SKU
restrictions, and remaining regional, VM-family and VM-count quotas. The table
shows why a region is blocked and marks candidates `ready`; `--json` includes every
scanned region. If needed, set `HASHBOX_DEMO_BUILDER_SIZE` to another builder
size for both the scan and the run. Choose a `ready` region for `run --region`;
the run repeats the check before creating anything in Azure.

`--region` overrides the profile's default for this run. The builder, staging
Blob, Gallery and image version, and CVM all use the chosen region. The saved
run region is used if a builder resume is needed. A later run automatically
selects the newest deallocated builder with matching subscription, region,
size and SSH public key, then verifies its exact Azure identity and ownership.
Each run has a separate remote workspace and shares the Guix store. If no
saved builder is usable, a new builder is created after the quota check.

## Run and clean up

```sh
.venv/bin/hashbox run --profile dev --region REGION
.venv/bin/hashbox list
.venv/bin/hashbox instance list RUN_ID
.venv/bin/hashbox instance create RUN_ID
.venv/bin/hashbox instance delete RUN_ID INSTANCE_NAME
.venv/bin/hashbox group delete RUN_ID
.venv/bin/hashbox status RUN_ID
.venv/bin/hashbox cleanup RUN_ID
```

`run` proposes `hbx-demo-RUN_ID-cvm-rg` for the CVM group and
`hbx-demo-RUN_ID_PREFIX` for the first instance. Set `--group NAME` and
`--name NAME` on `run` to choose other names. Names use lowercase letters,
digits and hyphens. The CVM group must be new; the demo never adopts an
existing group. The selected names, exact group IDs and later instance names
are saved in `.local/demo-runs/RUN_ID/run.json` before Azure effects. Builder
and image groups receive separate generated names. `run` displays the run ID,
names and compute prices before creating the builder. Local records and request
bodies go under `.local/demo-runs/` and are excluded from source archives. The
run signs the VHD, verifies the staged
Blob byte-for-byte, publishes an exact Gallery version with one conditional
REST PUT, deploys the CVM, and finishes only after Azure configuration and the
guest Secure Boot, UEFI db and TPM checks pass. The image build also includes
the pinned Attestor OCI artifact and IMA configuration. A completed `run` by
itself does not launch Attestor or claim attestation.

`list` shows locally recorded runs and counts their current Azure CVMs;
`instance list RUN_ID` shows the count, names, power states and addresses in
one owned group. An unreachable group is reported as unknown, not counted as
zero. `instance create RUN_ID` proposes the next name, such as
`hbx-demo-RUN_ID_PREFIX-2`; `--name NAME` overrides it. It rechecks the saved
source and Gallery identities, current CVM quota and price, then creates and
guest-verifies one CVM without rebuilding the image. Run these commands
sequentially; creating more VMs increases cost.

`instance delete` checks exact IDs and ownership tags before removing that
VM, its disk and its network resources. `group delete` removes the whole owned
CVM group and all its instances, leaving the image group for `cleanup`. A new
full run is needed to create a new CVM group after `group delete`.
`cleanup` removes the groups owned by the run, including the Gallery and
staging storage. It never deletes a borrowed builder; cleanup of its owner
waits until unfinished borrowing runs complete or are cleaned up. Both group
deletion commands refuse a CVM group containing
resources without this run's ownership tags.

If the builder build outlives the SSH connection, use
`.venv/bin/hashbox resume RUN_ID` after inspecting `status`. Resume is
limited to saved builder phases. It checks ownership before starting a
deallocated builder, verifies the saved source, and restarts an interrupted
Guix build only when no build or VHD is present. It never repeats an uncertain
Gallery PUT.
If your public IPv4 changed, set `HASHBOX_DEMO_SSH_SOURCE_CIDR` to the new
`/32` before resuming; the resume path refreshes the owned builder SSH rule.
`status` reads the saved run and current Azure resources. Keep Azure CLI access
to the recorded subscription for deletion and cleanup.

An earlier revision completed a live run with guest UEFI db verification; the
current source revision needs its own live proof. See [PLAN.md](PLAN.md) for the workflow and
[docs/architecture.md](docs/architecture.md) for module ownership. The OCI
hello service is a separate manual step; it has no demo CLI command.

## Attestor source and update check

This checkout pins the unreleased Attestor `0.2.0` source by Git commit and
checks its Git tree, Cargo manifest, lockfile and licence before an optional
OCI build. No prebuilt Attestor package or mutable Git branch is used as the
build input. Inspect the selected source in [ATTESTOR_LOCK.json](ATTESTOR_LOCK.json)
and the build recipe in [services/attestor/Dockerfile](services/attestor/Dockerfile).

```sh
.venv/bin/hashbox attestor check
.venv/bin/hashbox attestor build --fetch-only
.venv/bin/hashbox attestor build
```

`check` compares the selected commit with upstream `main`. Fresh `run`,
builder `resume`, `instance create` and `attestor build` also make this
read-only check before Azure effects. If upstream differs, the CLI prints the
new commit and offers
`hashbox attestor upgrade`; that explicit command advances the source lock to
a verified descendant. Rebuild the OCI artifact after an upgrade. An
unavailable GitHub check leaves the existing pin selected and prints a warning.

`build` needs native `linux/amd64` Docker because this demo does not use QEMU.
It saves a no-replace OCI archive and its source, archive, manifest, config and
layer digests under ignored `.local/attestor/`. A normal fresh run does this
on the Azure builder, then places the exact OCI archive and metadata in the
Guix image. The guest declaration enables IMA, mounts `securityfs` in the
initrd, makes its measurement log readable, and grants `hashbox` access to
TPM devices. A live run has launched this OCI artifact and passed a local
Confido check; each new image still needs its own guest proof.

To verify a completed run, first build Confido `main` on the operator machine.
This step needs Rust 1.98.0, Cargo, Git and a native C compiler; it does not
build Attestor locally. Update an existing Confido checkout to current `main`
before rebuilding it:

```sh
mkdir -p .local/attestation-tools
if [ ! -d .local/attestation-tools/confido/.git ]; then
  git clone --branch main https://github.com/jandigitrust/confido.git \
    .local/attestation-tools/confido
fi
git -C .local/attestation-tools/confido pull --ff-only origin main
cargo build --locked --release \
  --manifest-path .local/attestation-tools/confido/client/Cargo.toml
```

Use `hashbox status RUN_ID` for the VM name and IP. Connect with the private
key matching the profile's `.pub` file and the host key pinned during `run`:

```sh
ssh -i PRIVATE_KEY -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=.local/demo-runs/RUN_ID/VM_NAME.known_hosts \
  hashbox@CVM_IP
```

On the CVM, prepare and launch the image already embedded in the Guix system:

```sh
bundle=/dev/shm/attestor-RUN_ID
python3 /etc/hashbox/prepare-attestor.py --run-id RUN_ID --output "$bundle"
mkdir -m 700 "$bundle/runtime-state"
sh /etc/hashbox/launch-attestor.sh "$bundle/bundle" \
  /run/current-system/profile/bin/crun "$bundle/runtime-state" attestor-RUN_ID
crun --cgroup-manager=disabled --root "$bundle/runtime-state" state attestor-RUN_ID
```

The bundle uses guest tmpfs because the minimal Guix root partition does not
have room to unpack the OCI root filesystem. It disappears on reboot; prepare
and launch it again after a reboot. The launcher writes runtime output to
`$bundle/runtime-state/attestor-RUN_ID.log`. The service listens only on guest
`127.0.0.1:18001`.

Back on the operator machine, run:

```sh
python3 toolchain/attestor/verify-local.py RUN_ID --product Milan
```

`Milan` matches the sample [DCasv5 CVM family](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dcasv5-series);
select the documented processor family of a different CVM size. The verifier
checks the exact Azure VM and image binding, Secure Boot, UEFI db certificate
and embedded OCI digest. It
collects two fresh nonce-bound reports through pinned SSH. The first report
creates an owner-only `reference.json` containing the full ordered IMA log and
SHA-256 PCR 10, then pins its local Git commit and file SHA-256 in a policy.
Confido `main` verifies the second report against that policy and reference.
The run evidence keeps both responses, the policy, reference and result under
ignored `.local/demo-runs/RUN_ID/`. This is local self-enrollment for a demo,
not an independently approved reference or TLS session binding. For an
independent reference, review this image's build and measured boot, approve
the exact reference bytes and scope, publish a signed
[reference registry](https://github.com/teraveri/reference-value-registry)
entry, and pin its issuer, commit and SHA-256 in the verifier policy. A
reference from another image or kernel cannot be substituted.

## License

HashBox Preview is distributed under [GPL-2.0-or-later](LICENSE).
