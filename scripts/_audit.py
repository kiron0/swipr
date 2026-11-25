"""Read-only advanced storage analysis and capability-aware skill modes."""
from collections import defaultdict
from pathlib import Path
import math
import os
import re
import time

import _core as core

MODES = {"full", "quick", "deep", "safe-cleanup", "developer", "emergency", "targeted",
         "duplicates", "health", "compare", "custom"}
POLICY_KEYS = {"roots", "exclude", "max_entries", "max_depth", "max_seconds",
               "max_hash_bytes", "preserve_offline", "never_permanently_delete"}
PROJECT_RULES = {rule["id"]: (tuple(rule["project_markers"]), tuple(rule["artifact_paths"]), rule["application"])
                 for rule in core.read_rules() if rule.get("project_markers")}
PROJECT_SPECS = [
    (rule_id, markers, tuple(tuple(p.lower() for p in Path(a).parts) if os.name == "nt" else Path(a).parts for a in artifacts), app)
    for rule_id, (markers, artifacts, app) in PROJECT_RULES.items()
]
ARTIFACT_HEADS = {Path(a).parts[0].casefold() for _, artifacts, _ in PROJECT_RULES.values() for a in artifacts}


def policy(value):
    core.require(isinstance(value, dict) and not (set(value) - POLICY_KEYS), "Policy may restrict scan scope only; it cannot grant execution permission")
    for name in ("roots", "exclude"):
        if name in value:
            core.require(isinstance(value[name], list) and all(isinstance(x, str) and x for x in value[name]), "Policy paths must be nonempty strings in lists")
            core.require(name != "roots" or value[name], "A roots restriction cannot be empty")
    for name in ("preserve_offline", "never_permanently_delete"):
        if name in value:
            core.require(isinstance(value[name], bool), "Policy restrictions must be booleans")
    limits = {"max_entries": (1, 100000), "max_depth": (0, 64), "max_seconds": (.01, 120), "max_hash_bytes": (0, 4 * 1024**3)}
    for name, (minimum, maximum) in limits.items():
        if name in value:
            number = value[name]
            core.require(type(number) in ((int, float) if name == "max_seconds" else (int,)) and math.isfinite(number) and minimum <= number <= maximum, "Policy budget is outside supported limits")
    return value


def operation_report(request):
    result, plan = request["operation"], request["plan"]
    core.require("verified_at" in result and "all_verified" in result, "Verify the operation before generating a final cleanup report")
    core.require(isinstance(result["all_verified"], bool) and all(result[k] is None or type(result[k]) is int for k in ("before_free", "after_free", "observed_free_delta")), "Invalid verification or storage measurements")
    core.require(result["plan_id"] == plan["id"], "Report plan and operation do not match")
    entries = plan.get("entries", plan.get("items", []))
    approved = {e.get("id", e.get("candidate_id")) for e in entries}
    if result.get('action') == 'permanent-remove':
        selected = set(result['selected_ids'])
        core.require(selected and selected <= approved and result['plan_digest'] == plan['digest'], 'Removal report does not match the selected reviewed plan')
        approved = selected
    core.require(all(isinstance(x, str) and core.re.fullmatch(r"[a-f0-9]{24}", x) for x in approved), "Invalid report candidate identifiers")
    core.require(isinstance(result["id"], str) and core.re.fullmatch(r"[a-f0-9]{32}", result["id"]), "Invalid report operation identifier")
    attempted = {x["candidate_id"] for x in result["items"]}
    core.require(attempted <= approved, "Operation contains items outside the reported plan")
    core.require(all(x["status"] in {"permanently-removed", "failed-stop"} for x in result["items"]), "Invalid operation status")
    successful = [x for x in result["items"] if x["status"] == "permanently-removed"]
    verified = sum(bool(x.get("verified_absent", False)) for x in successful)
    failed = sum(x["status"] == "failed-stop" for x in result["items"])
    lines = ["# Swipr Cleanup Report", "", "Operation: " + result["id"],
             "Status: " + ("verified" if result["all_verified"] else "partial or verification incomplete"),
             "", f"Approved: {len(approved)}; processed: {len(successful)}; verified: {verified}; failed: {failed}; unattempted: {len(approved - attempted)}.",
             f"Available bytes before: {result['before_free'] if result['before_free'] is not None else 'unknown'}; after: {result['after_free'] if result['after_free'] is not None else 'unknown'}; observed delta: {result['observed_free_delta'] if result['observed_free_delta'] is not None else 'unknown'}.",
             "Observed changes include journal writes and unrelated activity; shared blocks and snapshots can limit physical recovery.", "",
             "| Candidate ID | Status |", "|---|---|"]
    lines += [f"| {x['candidate_id']} | {x['status']} |" for x in result["items"]]
    lines += [f"| {x} | unattempted |" for x in sorted(approved - attempted)]
    lines += ["", "Permanent removal bypasses Trash and Recycle Bin and cannot be undone by Swipr."]
    return {"markdown": "\n".join(lines) + "\n", "shareable": True}


def project_marker(directory, rule_id, markers, cache):
    key = (str(directory), rule_id)
    if key in cache:
        return cache[key]
    marker = None
    for name in markers:
        candidate = directory / name
        try:
            if candidate.is_file() and not core.redirect(candidate.lstat()):
                marker = candidate; break
        except OSError:
            pass
    # Project-local .NET files are detected by metadata, never executed.
    if rule_id == "dotnet-build" and marker is None:
        try:
            with os.scandir(directory) as items:
                for index, item in enumerate(items):
                    if index >= 200:
                        break
                    if item.name.endswith((".csproj", ".fsproj", ".vbproj")) and item.is_file(follow_symlinks=False):
                        marker = directory / item.name; break
        except OSError:
            pass
    cache[key] = marker
    return marker


def project_finding(entry, cache=None):
    path, root = Path(entry["path"]), Path(entry["root"])
    parts = path.parts
    if not any(x.casefold() in ARTIFACT_HEADS for x in parts) or core.protected(path):
        return None
    cache = {} if cache is None else cache
    markers_cache = cache.setdefault("markers", {})
    verified = cache.setdefault("verified", set())
    try:
        parent_str = str(path.parent)
        if parent_str not in verified:
            core.absolute(path.parent)
            verified.add(parent_str)
        info = path.lstat()
        if core.redirect(info) or core.identity(info) != entry["identity"]:
            return None
    except (OSError, core.Refusal):
        return None
    if not core.inside(path, root):
        return None
    root_len = len(root.parts)
    parts_cmp = tuple(x.lower() for x in parts) if os.name == "nt" else parts
    parts_len = len(parts_cmp)
    for offset, directory in enumerate((path.parent, *path.parent.parents)):
        idx = parts_len - 1 - offset
        if idx < root_len:
            break
        for rule_id, markers, art_tuples, app in PROJECT_SPECS:
            if not any(idx + len(ap) <= parts_len and parts_cmp[idx:idx + len(ap)] == ap for ap in art_tuples):
                continue
            marker = project_marker(directory, rule_id, markers, markers_cache)
            if marker is None:
                continue
            try:
                marker_info = core.identity(marker.lstat())
            except OSError:
                continue
            return {"candidate_id": entry["id"], "category": "project-build", "rule_id": rule_id,
                    "classification": "REVIEW", "application": app, "project": str(directory),
                    "marker": str(marker), "marker_identity": marker_info,
                    "mechanism": "Review the tool's supported clean/preview interface with this project stopped",
                    "side_effects": "Rebuild cost, test output loss, or unavailable offline dependencies; not automatically removable"}
    return None


def directory_totals(inventory):
    totals = {}
    seen = defaultdict(set)
    complete = inventory["complete"]
    for entry in inventory["entries"]:
        root, path = Path(entry["root"]), Path(entry["path"])
        if not core.inside(path, root):
            continue
        ident = entry["identity"]
        dedup = ident["links"] > 1 and ident["inode"] != 0
        key = (ident["device"], ident["inode"]) if dedup else None
        logical = entry["logical_bytes"]
        alloc = entry["allocated_bytes"] or 0
        remaining = len(path.parts) - len(root.parts)
        for parent in path.parents:
            if remaining <= 0:
                break
            remaining -= 1
            name = str(parent)
            row = totals.get(name)
            if row is None:
                row = totals[name] = {"path": name, "files": 0, "logical_bytes": 0,
                                      "allocated_bytes_known": 0, "coverage_complete": complete}
            if dedup:
                if key in seen[name]:
                    continue
                seen[name].add(key)
            row["files"] += 1; row["logical_bytes"] += logical
            row["allocated_bytes_known"] += alloc
    return sorted(totals.values(), key=lambda x: x["logical_bytes"], reverse=True)


def compare(request):
    before, after = request["before"], request["after"]
    core.require(before["roots"] == after["roots"] and before.get("exclude", []) == after.get("exclude", []), "Compare snapshots of the same scope and exclusions")
    old = {x["path"]: x for x in before["entries"]}; new = {x["path"]: x for x in after["entries"]}
    changed = [{"id": new[p]["id"], "path": p,
                "logical_delta": new[p]["logical_bytes"] - old[p]["logical_bytes"],
                "category": new[p]["category"]}
               for p in old.keys() & new.keys() if old[p]["identity"] != new[p]["identity"]]
    disks = {(x["root"], x["device"]): x["free"] for x in before["disks"]}
    return {"schema_version": 1, "added": [new[p]["id"] for p in new.keys() - old.keys()],
            "removed": [old[p]["id"] for p in old.keys() - new.keys()], "changed": changed,
            "available_space_deltas": [{"root": x["root"], "observed_delta": x["free"] - disks[(x["root"], x["device"])] if x['free'] is not None and disks[(x['root'], x['device'])] is not None else None}
                                       for x in after["disks"] if (x["root"], x["device"]) in disks],
            "coverage_complete": before["complete"] and after["complete"], "changes_made": False,
            "log_growth": [x for x in changed if x["category"] == "diagnostics" and x["logical_delta"] > 0],
            "regenerated_cache_candidates": [x["id"] for x in changed if "cache" in x["category"]],
            "warning": "Metadata changes do not prove abandonment, performance impact, or deletion eligibility"}


def recommendations(request):
    inventory = request["inventory"]
    rows = []
    cached = request.get("project_artifacts")
    project_index = {x["candidate_id"]: x for x in cached} if cached is not None else None
    started = time.monotonic()
    complete = request.get("project_analysis_complete", True)
    cache = {}
    if not inventory.get("protected_metadata_only"):
        for index, entry in enumerate(inventory["entries"]):
            if project_index is not None:
                project = project_index.get(entry["id"])
            elif index < 100000 and time.monotonic() - started < 10:
                project = project_finding(entry, cache)
            else:
                project = None; complete = False
            kind = project["classification"] if project else entry["classification"]
            category = project["category"] if project else entry["category"]
            if kind == "PROTECTED" and not project:
                continue
            rows.append({"candidate_id": entry["id"], "path": entry["path"], "category": category,
                         "application": project["application"] if project else entry["application"],
                         "classification": kind, "logical_bytes": entry["logical_bytes"],
                         "allocated_bytes": entry["allocated_bytes"], "potential_reclaimable_upper_bound": entry["allocated_bytes"],
                         "estimated_immediate_free_bytes": None,
                         "mechanism": entry["strategy"] if not project else project["mechanism"],
                         "evidence": project or entry["evidence"], "reason": entry["reason"] if not project else "Recognized project marker and exact tool output path",
                         "side_effects": project["side_effects"] if project else entry["side_effects"],
                         "recovery": entry["recovery"] if not project else "Rebuild where dependencies and tooling remain available",
                         "authorization": "not-approved"})
    rows.sort(key=lambda x: (x["classification"] != "SAFE-CANDIDATE", -x["logical_bytes"]))
    return {"schema_version": 1, "inventory_digest": core.digest(inventory), "candidates": rows,
            "project_analysis_complete": complete,
            "changes_made": False, "warning": "Recommendation is not execution authority; native actions require their own exact, reviewed scope"}


def sort_entries(entries, sort_by="size"):
    keys = {"size": lambda e: -e["logical_bytes"], "oldest": lambda e: e["identity"]["mtime_ns"],
            "location": lambda e: e["path"], "type": lambda e: Path(e["path"]).suffix.lower(),
            "application": lambda e: e["application"], "recoverability": lambda e: (e["classification"] != "SAFE-CANDIDATE", e["recovery"])}
    core.require(sort_by in keys, "Unsupported sort order")
    return sorted(entries, key=keys[sort_by])


def enrich_analysis(inventory, request):
    entries = inventory["entries"]
    sort_by = request.get("sort_by", "size")
    directories = directory_totals(inventory)
    projects = []
    started = time.monotonic()
    inspected = 0
    cache = {}
    for entry in entries:
        if inspected >= 100000 or time.monotonic() - started > 10:
            break
        inspected += 1
        finding = project_finding(entry, cache)
        if finding:
            projects.append(finding)
    health = []
    for disk in inventory["disks"]:
        measurement = disk if 'total' in disk else core.disk_metadata(disk['root'])
        if measurement.get('free') is not None and measurement.get('total'):
            ratio = measurement['free'] / measurement['total']
            health.append({"root": disk["root"], "free_bytes": measurement['free'], "free_ratio": ratio,
                           "storage_pressure": "critical" if ratio < .03 else "low-free-space" if ratio < .1 else "normal"})
        else:
            health.append({"root": disk["root"], "storage_pressure": "unknown"})
    now_ns = time.time_ns()
    top = core._bounded_int(request.get("top"), 20, 1, 100, "Invalid top limit")
    return {"ranked_files": sort_entries(entries, sort_by)[:top],
            "directories": directories[:100], "project_artifacts": projects, "health": health,
            "project_analysis_complete": inspected == len(entries),
            "temporary_candidates": [{"candidate_id": e["id"], "age_seconds": max(0, (now_ns - e["identity"]["mtime_ns"]) / 10**9),
                                       "stale_for_review": now_ns - e["identity"]["mtime_ns"] >= 7 * 86400 * 10**9,
                                       "active_use": "unknown", "classification": "REVIEW", "automatic_removal": False}
                                      for e in entries if e["category"] == "application-temporary"],
            "limitations": ["Metadata does not prove a file is inactive", "Clone/snapshot/shared-block savings are unknown",
                            "Storage cleanup is not a universal performance fix"]}


def leftovers(request):
    inventory, applications = request["inventory"], request["applications"]
    core.require(isinstance(applications, dict) and applications.get("source") == "native-installed-applications", "Supply a native application inventory")
    names = "\n".join(str(x.get("name", "")) + " " + str(x.get("id", "")) for x in applications.get("applications", [])).casefold()
    aliases = {"pip": ("python",), "CPython": ("python",), "npm": ("node", "npm"), "Yarn": ("yarn",),
               "Bun": ("bun",), "Cargo": ("rust", "cargo"), "Gradle": ("gradle",), "Xcode": ("xcode",),
               "Firefox": ("firefox",), "Safari": ("safari",), "Homebrew": ("homebrew",),
               "Chromium family": ("chrome", "chromium", "edge", "brave")}
    found_map = {
        app: any(re.search(r"(?<![a-z])" + re.escape(alias), names) for alias in app_aliases)
        for app, app_aliases in aliases.items()
    }
    complete = applications.get("complete", False)
    rows = []
    for entry in inventory["entries"]:
        app = entry["application"]
        if app not in found_map:
            continue
        found = found_map[app]
        rows.append({"candidate_id": entry["id"], "application": app,
                     "association": "present-in-native-inventory" if found else "not-observed-in-native-inventory",
                     "possible_leftover": not found, "classification": "REVIEW", "automatic_removal": False,
                     "inventory_complete": complete,
                     "reason": "A missing executable or incomplete installed inventory never establishes safe deletion"})
    return {"associations": rows, "changes_made": False}


def trash(request):
    core.require(request.get("authorized") is True, "Trash inspection requires selected scope approval")
    scope, _ = resolve_scope(request)
    inventory = core.scan({**scope, "protected_metadata_only": True, "scope_review_approved": True})
    # Contents remain recoverable personal data, irrespective of apparent age/type.
    return {"schema_version": 1, "inventory": inventory,
            "logical_bytes": sum(x["logical_bytes"] for x in inventory["entries"] if x["unique_inode"]),
            "allocated_bytes_known": sum(x["allocated_bytes"] or 0 for x in inventory["entries"] if x["unique_inode"]),
            "classification": "PROTECTED", "emptying_authorized": False, "changes_made": False,
            "warning": "Retention preserves recovery. Moving to Trash usually does not free space on the same filesystem; emptying is irreversible and needs separate approval"}


def profiles(request):
    value = policy(request.get("policy", {}))
    if not request.get("save"):
        return {"policy": value, "execution_authorized": False}
    core.require(request.get("user_approved") is True, "Saving preferences requires user consent")
    store = core.Store(request["state_dir"])
    profile = {"id": core.secrets.token_hex(16), "policy": value, "created_at": core.now(), "execution_authorized": False}
    store.save("profile-" + profile["id"] + ".json", profile)
    return profile


def snapshots(request):
    store = core.Store(request["state_dir"])
    if request.get("snapshot_id"):
        core.require(isinstance(request["snapshot_id"], str), "Invalid snapshot identifier")
        return store.load("snapshot-" + request["snapshot_id"] + ".json")
    core.require(request.get("user_approved") is True, "Saving a private inventory snapshot requires consent")
    snapshot = {"id": core.secrets.token_hex(16), "created_at": core.now(), "inventory": request["inventory"],
                "execution_authorized": False}
    store.save("snapshot-" + snapshot["id"] + ".json", snapshot)
    return snapshot


def resolve_scope(request):
    core.require(not (request.get("policy") and request.get("profile_id")), "Choose policy or profile_id, not both")
    restrictions = policy(request.get("policy") or {})
    if request.get("profile_id"):
        core.require(isinstance(request["profile_id"], str) and request.get("state_dir"), "A saved profile requires state_dir")
        restrictions = policy(core.Store(request["state_dir"]).load("profile-" + request["profile_id"] + ".json")["policy"])
    roots = request.get("roots") if "roots" in request and request["roots"] is not None else restrictions.get("roots")
    core.require(roots, "Explicit roots are required for every mode")
    if restrictions.get("roots"):
        allowed = [Path(os.path.abspath(os.path.expanduser(x))) for x in restrictions["roots"]]
        core.require(all(any(core.inside(Path(os.path.abspath(os.path.expanduser(r))), a) for a in allowed) for r in roots), "Requested root exceeds profile scope")
    scan_request = {k: request[k] for k in ("max_entries", "max_seconds", "max_depth") if k in request and request[k] is not None}
    for key in ("max_entries", "max_seconds", "max_depth"):
        if key in restrictions:
            if key in scan_request:
                value = scan_request[key]
                core.require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value), "Invalid scan budget")
                scan_request[key] = min(value, restrictions[key])
            else:
                scan_request[key] = restrictions[key]
    raw_exclude = request.get("exclude") or []
    core.require(isinstance(raw_exclude, list) and all(isinstance(x, str) and x.strip() for x in raw_exclude), "Exclusions must be nonempty strings")
    scan_request.update(roots=roots, exclude=list(dict.fromkeys(raw_exclude + restrictions.get("exclude", []))))
    return scan_request, restrictions


def audit(request):
    mode = request.get("mode", "quick")
    core.require(mode in MODES, "Unknown audit mode")
    if mode == "compare":
        return compare(request)
    scan_request, restrictions = resolve_scope(request)
    inventory = core.scan(scan_request)
    top = core._bounded_int(request.get("top"), 20, 1, 100, "Invalid top limit")
    analysis_request = {"inventory": inventory, "top": top, "sort_by": request.get("sort_by", "size")}
    if mode == "duplicates" or request.get("duplicates"):
        raw_hash = request.get("max_hash_bytes")
        req_hash = core._bounded_int(raw_hash, 256 * 1024**2, 0, 4 * 1024**3, "Invalid hash byte budget")
        analysis_request.update(duplicates=True, content_read_approved=request.get("content_read_approved", False),
                                max_hash_bytes=min(req_hash, restrictions.get("max_hash_bytes", 4 * 1024**3)))
    analysis = core.analyze(analysis_request)
    return {"schema_version": 1, "mode": mode, "inventory": inventory, "analysis": analysis,
            "proposal": recommendations({"inventory": inventory, "project_artifacts": analysis["project_artifacts"],
                                         "project_analysis_complete": analysis["project_analysis_complete"]}), "changes_made": False,
            "execution_authorized": False,
            "restrictions": {"preserve_offline": restrictions.get("preserve_offline", False),
                             "never_permanently_delete": restrictions.get("never_permanently_delete", False)},
            "next": "Review the exact proposal; this audit grants no execution permission"}
