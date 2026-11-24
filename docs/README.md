# Repository layout

The demo keeps the build, Azure provider and selected application in separate
Python-oriented directories:

| Role | Location | Purpose |
| --- | --- | --- |
| Operator entry | `bin/setup-venv`, `bin/hashbox`, `src/hashbox/cli/` | Local CLI setup, regional quota discovery, run, instance inventory and lifecycle, resume and cleanup. |
| Project and profile | `src/hashbox/project/`, `hashbox.toml` | Project root marker and owner-only Azure profile reader. |
| Build and transfer | `src/hashbox/build/`, `backends/guix/`, `toolchain/` | Bounded source archive, SSH transport, Guix image and Secure Boot VHD derivation. |
| Azure provider | `src/hashbox/providers/azure/`, `infra/providers/azure/` | Admission, resources, builder, conditional REST Gallery publication and CVM instance management. |
| Selected application | `services/oci-hello/`, `toolchain/oci/` | One OCI hello image, guest bundle preparation and `crun` launch. |
| Run state | `src/hashbox/operation/` | Exact local run record and ownership checks. |
| Documentation | `README.md`, `PLAN.md`, `ARM_TEMPLATE_CHANGELOG.md`, `docs/` | Operator guide, project plan, ARM change record and architecture map. |

The Python entry and packages provide the needed boundaries without a
separate contract, platform or schema layer. The active path builds one signed
VHD, publishes one Gallery version and checks the first Secure Boot CVM. More
instances can be created from that version in the same owned group. An earlier
revision completed a live run with guest UEFI db verification.
