"""Small operator CLI for run-owned Secure Boot CVM groups."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from hashbox.project.root import repository_root
from hashbox.providers.azure import demo
from hashbox.source import attestor


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashbox", description="Build and manage Secure Boot Azure CVM instances",
        epilog="Setup: ./bin/setup-venv, then configure examples/dev.toml. See README.md.",
    )
    commands = parser.add_subparsers(dest="command")
    regions = commands.add_parser("regions", help="find CVM quota across this subscription's Azure regions")
    regions.add_argument("--profile", required=True, help="NAME from .local/profiles/NAME.toml")
    regions.add_argument("--json", action="store_true", help="include every scanned region as JSON")
    list_command = commands.add_parser("list", help="count CVMs in locally recorded HashBox groups")
    list_command.add_argument("--json", action="store_true")
    run = commands.add_parser(
        "run", help="create fresh groups and run the full builder-to-CVM path",
        description="Requires .local/profiles/NAME.toml and Azure CLI access to its subscription.",
    )
    run.add_argument("--profile", required=True, help="NAME from .local/profiles/NAME.toml")
    run.add_argument("--region", help="use a region reported ready by 'hashbox regions'; overrides profile location")
    run.add_argument("--group", help="CVM resource group name; default: hbx-demo-RUN_ID-cvm-rg")
    run.add_argument("--name", help="first instance name; default: hbx-demo-RUN_ID_PREFIX")
    run.add_argument("--delete-builder", action="store_true",
                     help="create a fresh builder and delete it after publication")
    run.add_argument("--fresh-builder", action="store_true",
                     help="create a new retained builder instead of reusing a compatible one")
    resume = commands.add_parser("resume", help="continue an existing builder after transport loss")
    resume.add_argument("run_id")
    status = commands.add_parser("status", help="read local state and fresh Azure status")
    status.add_argument("run_id")
    instance = commands.add_parser("instance", help="list, create or delete CVMs in one run-owned group")
    instance_commands = instance.add_subparsers(dest="instance_command")
    instance_list = instance_commands.add_parser("list", help="show current instances and count")
    instance_list.add_argument("run_id")
    instance_list.add_argument("--json", action="store_true")
    instance_create = instance_commands.add_parser("create", help="add one CVM from the saved Gallery version")
    instance_create.add_argument("run_id")
    instance_create.add_argument("--name", help="instance name; default: next hbx-demo-RUN_ID_PREFIX-N")
    instance_delete = instance_commands.add_parser("delete", help="delete one CVM, disk and network resources")
    instance_delete.add_argument("run_id")
    instance_delete.add_argument("name")
    group = commands.add_parser("group", help="manage this run's CVM resource group")
    group_commands = group.add_subparsers(dest="group_command")
    group_delete = group_commands.add_parser("delete", help="delete the whole CVM group and all its instances")
    group_delete.add_argument("run_id")
    cleanup = commands.add_parser("cleanup", help="delete only this run's tagged resource groups")
    cleanup.add_argument("run_id")
    attestor_command = commands.add_parser("attestor", help="check and build the pinned Attestor source")
    attestor_commands = attestor_command.add_subparsers(dest="attestor_command", required=True)
    attestor_commands.add_parser("check", help="compare the pinned commit with upstream main")
    attestor_commands.add_parser("upgrade", help="pin a verified upstream descendant; rebuild afterward")
    attestor_build = attestor_commands.add_parser(
        "build", help="build a linux/amd64 OCI archive from the pinned source"
    )
    attestor_build.add_argument("--fetch-only", action="store_true", help="verify source identity without Docker")
    return parser


def main(argv: Sequence[str] | None = None, *, project_root: Path | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    if not arguments or arguments == ["help"]:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        root = repository_root(project_root or Path.cwd())
        if args.command == "regions":
            report = demo.regions(root, args.profile)
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                shown = [row for row in report["regions"] if row["status"] != "cvm-sku-absent"]
                print(f"Scanned {report['scanned_regions']} regions; {len(shown)} advertise {report['cvm_size']}.")
                print(f"{'Region':<22} {'CVM free/need':<15} {'Builder free/need':<19} {'Total free/need':<17} Result")
                for row in shown:
                    cvm = "-" if row.get("cvm_free") is None else f"{row['cvm_free']}/{row['cvm_cores']}"
                    builder = ("-" if row.get("builder_free") is None or row.get("builder_cores") is None
                               else f"{row['builder_free']}/{row['builder_cores']}")
                    total_need = max(row.get("cvm_cores") or 0, row.get("builder_cores") or 0)
                    total = "-" if row.get("regional_free") is None else f"{row['regional_free']}/{total_need}"
                    result = row["status"] + (f": {row['error']}" if row.get("error") else "")
                    print(f"{row['region']:<22} {cvm:<15} {builder:<19} {total:<17} {result}")
                print(f"Ready: {sum(row['status'] == 'ready' for row in report['regions'])} regions.")
                print(f"Choose a ready region: hashbox run --profile {args.profile} --region REGION")
                print("Builder, staging Blob, Gallery and CVM use that region. Quota does not guarantee capacity.")
            if any(row["status"] == "read-error" for row in report["regions"]):
                print("Some region reads failed; the scan is incomplete.", file=sys.stderr)
                return 1
        elif args.command == "list":
            report = demo.list_runs(root)
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print(f"{'Run':<18} {'Region':<16} {'Instances':<10} {'CVM group':<44} Status")
                for row in report["runs"]:
                    count = "?" if row["instance_count"] is None else str(row["instance_count"])
                    print(f"{row['run_id']:<18} {row['region']:<16} {count:<10} "
                          f"{row['group']:<44} {row['group_status']}")
                print(f"Owned CVM groups: {sum(row['group_status'] == 'owned-present' for row in report['runs'])}; "
                      f"visible instances: {report['reachable_instance_count']}")
                if report["unreachable_run_count"]:
                    print(f"{report['unreachable_run_count']} run(s) could not be read; total may be higher.")
        elif args.command == "run":
            demo.run(root, args.profile, args.region, args.group, args.name,
                     args.delete_builder, args.fresh_builder)
        elif args.command == "resume":
            demo.resume(root, args.run_id)
        elif args.command == "status":
            print(json.dumps(demo.status(root, args.run_id), indent=2, sort_keys=True))
        elif args.command == "instance":
            if args.instance_command == "list":
                report = demo.list_instances(root, args.run_id)
                if args.json:
                    print(json.dumps(report, indent=2, sort_keys=True))
                else:
                    print(f"Group: {report['group']} ({report['group_status']})")
                    print(f"HashBox instances: {report['count']}")
                    for row in report["instances"]:
                        print(f"  {row['name']:<30} {row['power'] or '-':<16} "
                              f"{row['address'] or '-':<16} {row['record_status']}")
                    if report.get("foreign_vm_count"):
                        print(f"Other VMs in group: {report['foreign_vm_count']}")
            elif args.instance_command == "create":
                demo.create_instance(root, args.run_id, args.name)
            elif args.instance_command == "delete":
                demo.delete_instance(root, args.run_id, args.name)
            else:
                parser.print_help()
                return 2
        elif args.command == "group":
            if args.group_command == "delete":
                demo.delete_cvm_group(root, args.run_id)
            else:
                parser.print_help()
                return 2
        elif args.command == "cleanup":
            demo.cleanup(root, args.run_id)
        elif args.command == "attestor":
            if args.attestor_command == "check":
                value = attestor.pin(root)
                print(f"Pinned Attestor {value['version']}: {value['commit']}")
                attestor.advise(root, operation="Attestor build")
            elif args.attestor_command == "upgrade":
                before = attestor.pin(root)
                after = attestor.upgrade(root)
                print(f"Attestor {after['version']}: {after['commit']}")
                if before['commit'] != after['commit']:
                    print("Build the new OCI image with: hashbox attestor build")
                    print("Attestor guest delivery is not yet wired into HashBox runs; existing runs are unchanged.")
            elif args.attestor_command == "build":
                attestor.advise(root, operation="Attestor OCI build")
                print(json.dumps(attestor.build(root, fetch_only=args.fetch_only), indent=2, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
