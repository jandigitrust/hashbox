"""Azure account, region, quota, price and absent-name preflight reads."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import json
import re
import sys
from urllib.parse import quote, urlencode
from urllib.request import urlopen

from hashbox.project.config import AzureProfile
from .cli import AzureCLI
from .errors import DemoError, _require


def _region_skus(azure: AzureCLI, location: str) -> list[dict]:
    filter_value = quote(f"location eq '{location}'", safe="")
    url = (f"https://management.azure.com/subscriptions/{azure.subscription_id}"
           "/providers/Microsoft.Compute/skus?api-version=2021-07-01&$filter=" + filter_value)
    items: list[dict] = []
    for _ in range(8):
        page = azure.json("rest", "--method", "get", "--url", url, timeout=90)
        _require(isinstance(page, dict) and isinstance(page.get("value"), list),
                 f"Compute SKU readback is invalid for {location}")
        items.extend(page["value"])
        url = page.get("nextLink")
        if not url:
            return items
    raise DemoError(f"Compute SKU readback has too many pages for {location}")


def _region_capacity(azure: AzureCLI, profile: AzureProfile, location: str,
                     *, builder_required: bool = True) -> dict:
    """Read exact SKU restrictions and both tiers of VM quota in one region."""
    result = {"region": location, "status": "unknown", "cvm_free": None,
              "builder_free": None, "regional_free": None, "vm_free": None, "cvm_cores": None,
              "builder_cores": None}
    skus = _region_skus(azure, location)

    def exact_sku(name: str) -> dict | None:
        matches = [sku for sku in skus if sku.get("resourceType") == "virtualMachines"
                   and str(sku.get("name", "")).casefold() == name.casefold()
                   and location in [str(value).casefold() for value in sku.get("locations", [])]]
        _require(len(matches) <= 1, f"ambiguous {name} SKU in {location}")
        return matches[0] if matches else None

    cvm = exact_sku(profile.cvm_size)
    builder = exact_sku(profile.builder_size)
    if cvm is None:
        result["status"] = "cvm-sku-absent"
        return result
    cvm_caps = {item.get("name"): item.get("value") for item in cvm.get("capabilities", [])}
    if not cvm_caps.get("ConfidentialComputingType") or "V2" not in cvm_caps.get("HyperVGenerations", "").split(","):
        result["status"] = "cvm-capability-missing"
        return result
    if any(item.get("type") == "Location" for item in cvm.get("restrictions", [])):
        result["status"] = "cvm-location-restricted"
        return result
    result["cvm_cores"] = int(cvm_caps["vCPUs"])
    result["cvm_family"] = cvm.get("family")
    _require(result["cvm_cores"] > 0 and isinstance(result["cvm_family"], str),
             f"CVM SKU cores or family are missing in {location}")

    if builder is not None:
        builder_caps = {item.get("name"): item.get("value") for item in builder.get("capabilities", [])}
        result["builder_cores"] = int(builder_caps["vCPUs"])
        result["builder_family"] = builder.get("family")
        _require(result["builder_cores"] > 0 and isinstance(result["builder_family"], str),
                 f"builder SKU cores or family are missing in {location}")

    usage = azure.json("vm", "list-usage", "--location", location, timeout=90)
    _require(isinstance(usage, list), f"VM quota readback is invalid for {location}")
    quotas = {item.get("name", {}).get("value"): item for item in usage}
    for field, family in (("regional_free", "cores"), ("vm_free", "virtualMachines"),
                          ("cvm_free", result["cvm_family"]),
                          ("builder_free", result.get("builder_family"))):
        item = quotas.get(family)
        if item is not None:
            result[field] = int(item["limit"]) - int(item["currentValue"])

    # The builder is deallocated before the CVM starts, so they do not need
    # their combined vCPU count at the same time.
    regional_need = (max(result["cvm_cores"], result["builder_cores"] or 0)
                     if builder_required else result["cvm_cores"])
    builder_unavailable = builder is None or any(
        item.get("type") == "Location" for item in (builder or {}).get("restrictions", []))
    if builder_required and builder_unavailable:
        result["status"] = "builder-sku-unavailable"
    elif None in ([result["regional_free"], result["vm_free"], result["cvm_free"]] +
                  ([result["builder_free"]] if builder_required else [])):
        result["status"] = "quota-unreported"
    elif result["vm_free"] < 1:
        result["status"] = "vm-count-quota"
    elif result["regional_free"] < regional_need:
        result["status"] = "regional-vcpu-quota"
    elif result["cvm_free"] < result["cvm_cores"]:
        result["status"] = "cvm-family-quota"
    elif builder_required and result["builder_free"] < result["builder_cores"]:
        result["status"] = "builder-family-quota"
    else:
        result["status"] = "ready"
    return result


def available_regions(azure: AzureCLI, profile: AzureProfile) -> dict:
    account = azure.json("account", "show", timeout=60)
    _require(account.get("id", "").casefold() == profile.subscription_id.casefold()
             and account.get("state") == "Enabled", "profile subscription is not active in Azure CLI")
    provider = azure.json("provider", "show", "--namespace", "Microsoft.Compute", timeout=90)
    _require(provider.get("registrationState") == "Registered", "Microsoft.Compute is not registered")
    url = f"https://management.azure.com/subscriptions/{profile.subscription_id}/locations?api-version=2022-12-01"
    response = azure.json("rest", "--method", "get", "--url", url, timeout=90)
    _require(isinstance(response, dict) and isinstance(response.get("value"), list)
             and not response.get("nextLink"), "subscription locations readback is incomplete")
    locations = set()
    for item in response["value"]:
        name = item.get("name")
        metadata = item.get("metadata") or {}
        if (isinstance(name, str) and metadata.get("regionType") == "Physical" and
                not str(metadata.get("geography", "")).casefold().startswith(("stage", "canary"))):
            locations.add(name.casefold())
    locations = sorted(locations)
    _require(bool(locations), "Azure returned no physical customer regions")
    print(f"Scanning {len(locations)} Azure regions for {profile.cvm_size} and {profile.builder_size}...",
          file=sys.stderr, flush=True)
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending = {pool.submit(_region_capacity, azure, profile, location): location for location in locations}
        for index, future in enumerate(as_completed(pending), 1):
            location = pending[future]
            try:
                results.append(future.result())
            except Exception as error:
                results.append({"region": location, "status": "read-error", "error": str(error)[:300]})
            if index % 10 == 0 or index == len(locations):
                print(f"  checked {index}/{len(locations)} regions", file=sys.stderr, flush=True)
    results.sort(key=lambda item: (item["status"] != "ready", item["region"]))
    return {"subscription_id": profile.subscription_id, "cvm_size": profile.cvm_size,
            "builder_size": profile.builder_size, "scanned_regions": len(locations), "regions": results}


def _account_preflight(azure: AzureCLI, profile: AzureProfile,
                       *, builder_required: bool = True) -> AzureProfile:
    account = azure.json("account", "show", timeout=60)
    _require(account.get("id", "").casefold() == profile.subscription_id.casefold(),
             "Azure CLI did not return the profile subscription")
    _require(account.get("state") == "Enabled", "Azure subscription is not enabled")
    for namespace in ("Microsoft.Compute", "Microsoft.Network", "Microsoft.Storage", "Microsoft.Resources"):
        provider = azure.json("provider", "show", "--namespace", namespace, timeout=90)
        _require(provider.get("registrationState") == "Registered", f"Azure provider {namespace} is not registered")
    capacity = _region_capacity(azure, profile, profile.location, builder_required=builder_required)
    _require(capacity["status"] == "ready",
             f"{profile.location} cannot run the requested CVM: {capacity['status']} "
             f"(regional free={capacity.get('regional_free')}, VM slots free={capacity.get('vm_free')}, "
             f"CVM family free={capacity.get('cvm_free')}, "
             f"builder family free={capacity.get('builder_free')}); run 'hashbox regions --profile {profile.name}'")
    if builder_required and profile.builder_image_version == "auto":
        image = azure.json("vm", "image", "show", "--location", profile.location,
                           "--urn", "Canonical:ubuntu-24_04-lts:server:latest", timeout=120)
        exact = image.get("name") if isinstance(image, dict) else None
        _require(isinstance(exact, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", exact) is not None,
                 "Azure did not resolve an exact Ubuntu builder image version")
        profile = replace(profile, builder_image_version=exact)
    return profile


def _retail_vm_hourly(profile: AzureProfile, sku: str) -> float:
    query = " and ".join((
        f"armRegionName eq '{profile.location}'",
        f"armSkuName eq '{sku}'",
        "priceType eq 'Consumption'",
    ))
    url = "https://prices.azure.com/api/retail/prices?" + urlencode({"$filter": query})
    try:
        with urlopen(url, timeout=30) as response:
            items = json.load(response)["Items"]
    except (OSError, KeyError, ValueError) as error:
        raise DemoError("cannot establish current Azure retail VM price") from error
    prices = {float(item["retailPrice"]) for item in items
              if item.get("serviceName") == "Virtual Machines"
              and item.get("unitOfMeasure") == "1 Hour"
              and "Windows" not in item.get("productName", "")
              and "Spot" not in item.get("meterName", "")
              and "Low Priority" not in item.get("meterName", "")}
    _require(len(prices) == 1, f"cannot select one Linux consumption price for {sku}")
    return prices.pop()


def _absent_groups(azure: AzureCLI, record: dict) -> None:
    for role, group in record["groups"].items():
        if role == "builder" and record.get("builder_owner_run_id"):
            continue
        _require(not azure.group_exists(group["name"]), f"new {role} group name already exists")
