"""Swipr's offline, standard-library-only filesystem and policy engine.

Recognized findings can enter an exact, digest-bound permanent-removal plan on
every supported OS. Arbitrary deletion and automatic Trash emptying are excluded.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import functools
import hashlib
import hmac
import html
import fnmatch
import getpass
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from collections import defaultdict, deque

VERSION = "0.1.6"
BASE = Path(__file__).resolve().parent.parent
KINDS = {"SAFE-CANDIDATE", "REVIEW", "PROTECTED", "UNSUPPORTED"}
PRUNE = {".git", ".svn", ".hg", ".ssh", ".aws", ".gnupg", ".azure",
         "node_modules", ".venv", "venv", "env", "site-packages", ".swipr", ".disksweep",
         "onedrive", "dropbox", "google drive", "googledrive", "icloud drive",
         "mobile documents", "cloudstorage", "backups", "backup", "time machine"}
PROTECTED_PARTS = PRUNE | {"system32", "winsxs", "windowsapps", "keychains",
                          "credentials", "indexeddb", "local storage", "sessions",
                          "certificates", "volumes", "databases", ".trash", "trash",
                          "$recycle.bin", "system volume information"}
PROTECTED_NAMES = {"cookies", "login data", "bookmarks", "history", "preferences",
                   "web data", "wallet.dat", "id_rsa", "id_ed25519"}
PROTECTED_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx", ".kdbx"}
SYSTEM_ROOTS = ("/etc", "/usr", "/boot", "/var/lib", "/proc", "/sys", "/dev",
                "/System", "/Library", "/bin", "/sbin", "/lib", "/lib64")
SYSTEM_ROOT_PATHS = tuple(Path(x) for x in SYSTEM_ROOTS)
WINDOWS_SYSTEM_PARTS = {"windows", "program files", "program files (x86)", "programdata"}
_RULES_CACHE = {}


class Refusal(ValueError):
    """An operation failed a deterministic safety check."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def platform_id():
    return {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(platform.system(), "unsupported")


def identity(s):
    return {"device": s.st_dev, "inode": s.st_ino, "mode": s.st_mode,
            "size": s.st_size, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns,
            "links": s.st_nlink}


def redirect(s):
    return stat.S_ISLNK(s.st_mode) or bool(getattr(s, "st_file_attributes", 0) & 0x400)


def absolute(path):
    raw = os.fspath(path)
    require(isinstance(raw, (str, bytes)) and bool(raw.strip() if isinstance(raw, str) else raw.strip()), "Path cannot be empty")
    p = Path(os.path.abspath(os.path.expanduser(raw)))
    # Resolve no links: every existing component must be a real directory/file.
    for part in [*reversed(p.parents), p]:
        require(not redirect(part.lstat()), "Symbolic links and reparse points are excluded")
    return p


def inside(path, root):
    child, parent = path.parts, root.parts
    if len(child) < len(parent):
        return False
    if os.name == "nt":
        for a, b in zip(child, parent):
            if a.lower() != b.lower():
                return False
        return True
    return child[:len(parent)] == parent


def protected(path, exclusions=()):
    name_cf = path.name.casefold()
    if name_cf.startswith(".env") or path.suffix.casefold() in PROTECTED_SUFFIXES or name_cf in PROTECTED_NAMES:
        return True
    parts = {x.casefold() for x in path.parts}
    if parts & PROTECTED_PARTS:
        return True
    if exclusions and any(inside(path, x if isinstance(x, Path) else Path(x)) for x in exclusions):
        return True
    if os.name != "nt":
        for sys_root in SYSTEM_ROOT_PATHS:
            if inside(path, sys_root):
                return True
    elif len(path.parts) >= 2 and path.drive and path.parts[1].casefold() in WINDOWS_SYSTEM_PARTS:
        return True
    return False


def read_rules():
    files = sorted((BASE / "rules").glob("*/*.json"))
    key = []
    for file in files:
        s = file.stat()
        key.append((str(file), s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns))
    key = tuple(key)
    if key not in _RULES_CACHE:
        _RULES_CACHE.clear()
        _RULES_CACHE[key] = json.dumps(_load_rules(files))
    return json.loads(_RULES_CACHE[key])


def _load_rules(files):
    rules = []
    seen = set()
    for file in files:
        for rule in json.loads(file.read_text(encoding="utf-8")):
            require(rule["id"] not in seen, "Duplicate rule identifier")
            require(rule["strategy"] in {"audit-only", "remove-exact"}, "Unsupported rule strategy")
            require(rule["classification"] in KINDS and rule["version"] == 1, "Invalid rule")
            require(rule["classification"] == ("SAFE-CANDIDATE" if rule["strategy"] == "remove-exact" else "REVIEW"), "Contradictory rule")
            require(rule["strategy"] != "remove-exact" or rule["id"] == "python-bytecode", "Only verified bytecode is a safe exact-removal rule")
            require(not ({"command", "script", "shell"} & rule.keys()), "Executable rule data is forbidden")
            if rule.get("project_markers"):
                require(rule["strategy"] == "audit-only" and isinstance(rule["project_markers"], list) and isinstance(rule.get("artifact_paths"), list), "Invalid project rule")
                require(all(isinstance(p, str) and p and not Path(p).is_absolute() and ".." not in Path(p).parts for p in rule["project_markers"] + rule["artifact_paths"]), "Unsafe project rule path")
            seen.add(rule["id"])
            rules.append(rule)
    return rules


def mount_points():
    """Linux mountinfo includes same-device bind mounts missed by ismount()."""
    mounts = set()
    if platform_id() == "linux":
        try:
            for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace").splitlines():
                mount = line.split(" - ", 1)[0].split()[4]
                mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), mount)
                mounts.add(Path(mount))
        except (OSError, IndexError):
            pass
    return mounts


def project_for_bytecode(path, root, cache=None):
    if path.parent.name != "__pycache__" or path.suffix != ".pyc":
        return None
    # The CPython cache tag and source file must agree; names alone are not evidence.
    match = re.fullmatch(r"(.+)\.cpython-\d{2,3}(?:\.opt-[12])?\.pyc", path.name)
    if not match:
        return None
    source = path.parent.parent / (match[1] + ".py")
    try:
        if cache is not None:
            verified = cache.setdefault("verified", set())
            parent_key = str(source.parent)
            if parent_key not in verified:
                absolute(source.parent)
                verified.add(parent_key)
            raw = os.fspath(source)
            source_path = Path(os.path.abspath(os.path.expanduser(raw)))
            src_stat = source_path.lstat()
            require(not redirect(src_stat), "Symbolic links and reparse points are excluded")
            source = source_path
        else:
            source = absolute(source)
            src_stat = source.lstat()
        if not stat.S_ISREG(src_stat.st_mode) or protected(source):
            return None
        marker_cache = cache.setdefault("markers", {}) if cache is not None else None
        for parent in [source.parent, *source.parent.parents]:
            if not inside(parent, root):
                break
            p_key = str(parent)
            if marker_cache is not None and p_key in marker_cache:
                cached = marker_cache[p_key]
                if cached is not None:
                    return {"source": str(source), "source_identity": identity(src_stat),
                            "project": p_key, "marker": cached[0], "marker_identity": cached[1]}
                continue
            found = None
            for name in ("pyproject.toml", "setup.py", "setup.cfg"):
                marker = parent / name
                if marker.exists() and not redirect(marker.lstat()) and marker.is_file():
                    found = (str(marker), identity(marker.stat()))
                    break
            if marker_cache is not None:
                marker_cache[p_key] = found
            if found is not None:
                return {"source": str(source), "source_identity": identity(src_stat),
                        "project": p_key, "marker": found[0], "marker_identity": found[1]}
    except (OSError, Refusal):
        return None
    return None


@functools.lru_cache(maxsize=64)
def signature_index(signatures):
    literal, wildcard = defaultdict(list), []
    for order, signature in enumerate(signatures):
        segments = tuple((x, any(c in x for c in "*?[")) for x in signature.casefold().split("/"))
        (wildcard if segments[0][1] else literal[segments[0][0]]).append((order, segments))
    return dict(literal), wildcard


def first_signature(parts, signatures):
    literal, wildcard = signature_index(signatures)
    best = None
    for i, part in enumerate(parts):
        for order, segments in (*literal.get(part, ()), *wildcard):
            if best is not None and order >= best or i + len(segments) > len(parts):
                continue
            if all(fnmatch.fnmatchcase(parts[i + k], x) if glob else parts[i + k] == x
                   for k, (x, glob) in enumerate(segments)):
                best = order
    return best


def _prepare_rules(rules):
    current = platform_id()
    bytecode_idx = None
    bytecode_rule = None
    owners = []
    for idx, rule in enumerate(r for r in rules if current in r["platforms"]):
        if rule["id"] == "python-bytecode":
            bytecode_idx, bytecode_rule = idx, rule
        else:
            for sig in rule["signatures"]:
                owners.append((idx, rule, sig))
    return bytecode_idx, bytecode_rule, owners, tuple(sig for _, _, sig in owners)


def classify(path, root, info, rules, exclusions=(), _prepared=None, _bytecode_cache=None):
    if protected(path, exclusions):
        return None, "PROTECTED", None
    bytecode_idx, bytecode_rule, owners, sigs = _prepare_rules(rules) if _prepared is None else _prepared
    evidence = project_for_bytecode(path, root, _bytecode_cache) if bytecode_rule is not None else None
    if bytecode_rule is not None and evidence and info["links"] == 1 and (bytecode_idx == 0 or not owners):
        return bytecode_rule, "SAFE-CANDIDATE", evidence
    match = None
    if owners:
        parts = [x.casefold() for x in path.parts]
        match = first_signature(parts, sigs)
    if bytecode_rule is not None and evidence and info["links"] == 1 and (match is None or bytecode_idx < owners[match][0]):
        return bytecode_rule, "SAFE-CANDIDATE", evidence
    if match is not None:
        return owners[match][1], "REVIEW", {"signature": owners[match][2], "active_use": "unknown"}
    return None, "PROTECTED", None


def disk_metadata(path):
    """Optional read-only volume measurements; failure never means zero free space."""
    try:
        usage = shutil.disk_usage(path)
        return {'total': usage.total, 'used': usage.used, 'free': usage.free, 'status': 'available'}
    except OSError as error:
        return {'total': None, 'used': None, 'free': None,
                'status': 'permission-denied' if isinstance(error, PermissionError) else 'unavailable'}


def probe(request):
    home = Path.home()
    pid = platform_id()
    cache = Path(os.environ.get("XDG_CACHE_HOME", home / ".cache"))
    roots = {"linux": [cache / "pip", cache / "thumbnails", home / ".npm" / "_cacache",
                        cache / "google-chrome", cache / "chromium", cache / "mozilla"],
             "macos": [home / "Library/Caches/pip", home / "Library/Caches/Homebrew",
                        home / "Library/Developer/Xcode/DerivedData", home / "Library/Caches/Google/Chrome",
                        home / "Library/Caches/com.apple.Safari", home / ".npm/_cacache"],
             "windows": [Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local")) / p
                         for p in ("pip/Cache", "npm-cache/_cacache", "Google/Chrome/User Data", "Microsoft/Edge/User Data")]}
    raw_path = request.get("path")
    selected = Path(os.path.abspath(os.path.expanduser(raw_path))) if raw_path is not None else home
    disk = disk_metadata(selected)
    suggestions = []
    for path in roots.get(pid, []):
        try:
            if path.is_dir():
                suggestions.append(str(path))
        except OSError:
            pass
    mounts = []
    if pid == "linux":
        try:
            for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace").splitlines()[:256]:
                left, right = line.split(" - ", 1)
                fields = left.split()
                mounts.append({"path": fields[4], "filesystem": right.split()[0]})
        except (OSError, IndexError):
            pass
    tools = {name: bool(shutil.which(name)) for name in ("python3", "node", "npm", "pnpm", "yarn", "bun", "pip", "cargo", "rustc", "go", "dotnet", "gradle", "mvn", "docker", "brew", "xcodebuild")}
    return {"version": VERSION, "platform": pid, "os_version": platform.release(),
            "current_user": getpass.getuser(),
            "home": str(home), "disk": disk,
            'installation': {'version': VERSION, 'directory': str(BASE)},
            "access": {"read": os.access(selected, os.R_OK), "write": os.access(selected, os.W_OK), "administrator_requested": False},
            "backup_snapshot_tools": {name: bool(shutil.which(name)) for name in ("tmutil", "diskutil", "btrfs", "zfs", "vssadmin", "wbadmin")},
            "mounts": mounts, "tools": tools,
            "suggested_roots": suggestions,
            "capabilities": {"metadata": True,
                             "content_hashing": os.name == "posix" and os.open in os.supports_dir_fd,
                             "direct_remove": removal_supported(),
                             "permanent_delete": removal_supported(),
                             "permanent_delete_scope": "exact approved current-user local regular files",
                             "active_use_detection": bool(shutil.which("lsof")) if os.name == "posix" else False,
                             "native_maintenance": "agent-guided; no automatic execution"},
            "notes": ["Suggested roots are proposals; scan only user-authorized scope.",
                      "Filesystem type and mounts are best effort; no mount is automatically authorized."]}


def removal_supported():
    if os.name == "nt":
        return True
    return os.name == "posix" and all(f in os.supports_dir_fd for f in (os.open, os.stat, os.unlink))


def _bounded_int(value, default, minimum, maximum, message):
    if value is None:
        return default
    require(not isinstance(value, bool), message)
    if isinstance(value, float):
        require(math.isfinite(value), message)
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise Refusal(message) from None
    return min(max(number, minimum), maximum)


def scan(request):
    metadata_only = request.get("protected_metadata_only", False)
    require(isinstance(metadata_only, bool), "Invalid metadata-only flag")
    require(not metadata_only or request.get("scope_review_approved") is True, "Protected metadata inspection requires explicit scope review")
    raw_roots = request.get("roots")
    require(isinstance(raw_roots, list) and raw_roots and all(isinstance(x, str) and x.strip() for x in raw_roots), "Explicit roots are required")
    roots = [absolute(x) for x in raw_roots]
    require(len(roots) <= 32, "At most 32 roots per scan")
    require(len(set(roots)) == len(roots), "Duplicate roots")
    require(not any(inside(a, b) for a in roots for b in roots if a != b), "Overlapping roots")
    raw_exclude = request.get("exclude", [])
    require(isinstance(raw_exclude, list) and all(isinstance(x, str) and x.strip() for x in raw_exclude), "Exclusions must be nonempty strings")
    exclusions = [os.path.abspath(os.path.expanduser(x)) for x in raw_exclude]
    excluded = [Path(x) for x in exclusions]
    windows = platform_id() == "windows"
    posix = os.name == "posix"
    rules = read_rules()
    prepared_rules = _prepare_rules(rules)
    bytecode_cache = {}
    mounts = mount_points()
    limit = _bounded_int(request.get("max_entries"), 20000, 1, 100000, "Invalid scan entry budget")
    raw_seconds = request.get("max_seconds", 10)
    require(raw_seconds is None or (isinstance(raw_seconds, (int, float)) and not isinstance(raw_seconds, bool)),
            "Scan time budget must be numeric")
    seconds = float(10 if raw_seconds is None else raw_seconds)
    require(math.isfinite(seconds), "Scan time budget must be finite")
    seconds = min(max(seconds, 0.01), 120)
    depth = _bounded_int(request.get("max_depth"), 12, 0, 64, "Invalid scan depth budget")
    started = time.monotonic()
    entries, issues, seen, count = [], [], set(), 0
    devices = {}
    complete = True
    for root in roots:
        require(root.is_dir() and (metadata_only or not protected(root, excluded)), "Scan root is protected or not a directory")
        require(not (excluded and any(inside(root, x) for x in excluded)), "Scan root is excluded")
        rootdev = root.stat().st_dev
        devices[str(root)] = rootdev
        queue = deque([(root, 0)])
        while queue:
            directory, level = queue.popleft()
            if time.monotonic() - started > seconds or count >= limit:
                issues.append({"path": str(directory), "reason": "resource-limit"}); complete = False; break
            try:
                if posix:
                    secure_dir = directory_fd(directory)
                else:
                    # lstat all components on every expansion; never intentionally follow redirections.
                    absolute(directory)
                    require(directory.stat().st_dev == rootdev, "mount-boundary")
                    secure_dir = contextlib.nullcontext(directory)
                hit_limit = False
                with secure_dir as directory_handle:
                    if posix:
                        require(os.fstat(directory_handle).st_dev == rootdev, "mount-boundary")
                    with os.scandir(directory_handle) as iterator:
                        for item in iterator:
                            if count >= limit or time.monotonic() - started > seconds:
                                issues.append({"path": str(directory), "reason": "resource-limit"}); complete = False; hit_limit = True; break
                            count += 1
                            path = directory / item.name
                            try:
                                if excluded and any(inside(path, x) for x in excluded):
                                    issues.append({"path": str(path), "reason": "protected"}); continue
                                # Windows DirEntry.stat caches zero device/inode/link IDs.
                                # lstat() retrieves the complete filesystem identity there.
                                s = path.lstat() if windows else item.stat(follow_symlinks=False)
                                is_dir = stat.S_ISDIR(s.st_mode)
                                if redirect(s) or s.st_dev != rootdev or (mounts and path in mounts) or (is_dir and os.path.ismount(path)):
                                    issues.append({"path": str(path), "reason": "redirection-or-mount"}); continue
                                if is_dir:
                                    if path.name.casefold() in PRUNE or (not metadata_only and protected(path, excluded)):
                                        issues.append({"path": str(path), "reason": "protected"})
                                    elif level < depth:
                                        queue.append((path, level + 1))
                                    else:
                                        issues.append({"path": str(path), "reason": "depth-limit"}); complete = False
                                    continue
                                if not stat.S_ISREG(s.st_mode):
                                    continue
                                info = identity(s)
                                rule, kind, evidence = (None, "PROTECTED", None) if metadata_only else classify(
                                    path, root, info, rules, excluded, _prepared=prepared_rules, _bytecode_cache=bytecode_cache)
                                allocated = getattr(s, "st_blocks", None)
                                allocated = allocated * 512 if allocated is not None else None
                                if s.st_ino != 0:
                                    key = (s.st_dev, s.st_ino)
                                    unique = key not in seen; seen.add(key)
                                else:
                                    unique = True
                                candidate = {"path": str(path), "root": str(root), "identity": info,
                                             "created_ns": getattr(s, "st_birthtime_ns", None),
                                             "logical_bytes": s.st_size, "allocated_bytes": allocated,
                                             "unique_inode": unique, "classification": kind,
                                             "rule_id": rule["id"] if rule else None,
                                             "rule_version": rule["version"] if rule else None,
                                             "application": rule["application"] if rule else "unknown",
                                             "category": rule["category"] if rule else "personal-or-unknown",
                                             "risk": rule["risk"] if rule else "high",
                                             "reason": rule["reason"] if rule else "No verified disposable-artifact rule",
                                             "side_effects": rule["side_effects"] if rule else "Potential loss of user or application data",
                                             "recovery": rule["recovery"] if rule else "Unknown; preserve",
                                             "strategy": rule["strategy"] if rule else "audit-only",
                                             "evidence": evidence, "active_use": "unknown"}
                                candidate["id"] = digest({"path": str(path), "identity": info})[:24]
                                entries.append(candidate)
                            except (OSError, Refusal):
                                issues.append({"path": str(path), "reason": "unreadable-or-changed"}); complete = False
                if hit_limit:
                    break
            except (OSError, Refusal):
                issues.append({"path": str(directory), "reason": "unreadable-or-changed"}); complete = False
    disks = []
    for root in roots:
        measurement = disk_metadata(root)
        disks.append({'root': str(root), 'device': devices[str(root)], 'free': measurement['free'],
                      'total': measurement['total'], 'space_status': measurement['status']})
        if measurement['status'] != 'available':
            issues.append({'path': str(root), 'reason': 'disk-space-' + measurement['status']})
    for issue in issues:
        issue["classification"] = "PROTECTED" if issue["reason"] == "protected" else "UNSUPPORTED"
    return {"schema_version": 1, "version": VERSION, "created_at": now(), "roots": list(map(str, roots)),
            "protected_metadata_only": bool(metadata_only),
            "exclude": exclusions, "complete": complete, "entries_visited": count,
            "entries": entries, "issues": issues, "disks": disks,
            "summary": summarize(entries), "changes_made": False}


def summarize(entries):
    out = {k: {"count": 0, "logical_bytes": 0, "allocated_bytes_known": 0} for k in sorted(KINDS)}
    for entry in entries:
        row = out[entry["classification"]]
        row["count"] += 1
        if entry["unique_inode"]:
            row["logical_bytes"] += entry["logical_bytes"]
            row["allocated_bytes_known"] += entry["allocated_bytes"] or 0
    return out


def safe_hash(entry, budget, read_counter=None, exclusions=()):
    path = absolute(entry["path"])
    require(not protected(path, exclusions), "Protected content cannot be hashed")
    require(entry["identity"]["size"] <= budget, "Hash byte budget exhausted")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with directory_fd(path.parent) as parent_fd:
        fd = os.open(path.name, flags, dir_fd=parent_fd)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and identity(st) == entry["identity"], "File changed before hashing")
            hasher = hashlib.sha256()
            remaining = entry["identity"]["size"]
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                require(chunk, "File changed during hashing")
                if read_counter is not None:
                    read_counter[0] += len(chunk)
                hasher.update(chunk); remaining -= len(chunk)
            require(identity(os.fstat(fd)) == entry["identity"], "File changed during hashing")
            return hasher.hexdigest()
        finally:
            os.close(fd)


def analyze(request):
    inventory = request["inventory"]
    entries = inventory["entries"]
    top = _bounded_int(request.get("top"), 20, 1, 100, "Invalid top limit")
    out = {"schema_version": 1, "summary": summarize(entries),
           "largest": sorted(entries, key=lambda x: x["logical_bytes"], reverse=True)[:top],
           "duplicates": [], "hash_bytes_read": 0, "hash_budget_charged_bytes": 0, "issues": [], "changes_made": False}
    if request.get("duplicates"):
        require(request.get("content_read_approved") is True, "Duplicate hashing requires explicit content-read approval")
        budget = _bounded_int(request.get("max_hash_bytes"), 256 * 1024**2, 0, 4 * 1024**3, "Invalid hash byte budget")
        exclusions = [Path(os.path.abspath(os.path.expanduser(x))) for x in inventory.get("exclude", [])]
        groups = defaultdict(list)
        by_id = {e["id"]: e for e in entries}
        for entry in entries:
            require(entry["root"] in inventory["roots"] and inside(Path(entry["path"]), Path(entry["root"])), "Hash candidate escaped inventory scope")
            if entry["unique_inode"] and entry["logical_bytes"] and not protected(Path(entry["path"]), exclusions):
                groups[entry["logical_bytes"]].append(entry)
        for group in groups.values():
            if len(group) < 2:
                continue
            matches = defaultdict(list)
            for entry in group:
                counter = [0]
                try:
                    remaining = budget - out["hash_budget_charged_bytes"]
                    require(entry["logical_bytes"] <= remaining, "Hash byte budget exhausted")
                    # Charge the allowance even if the post-read identity check fails.
                    out["hash_budget_charged_bytes"] += entry["logical_bytes"]
                    key = safe_hash(entry, remaining, counter, exclusions=exclusions)
                    matches[key].append(entry["id"])
                except (OSError, Refusal):
                    out["issues"].append({"id": entry["id"], "reason": "hash-skipped"})
                finally:
                    out["hash_bytes_read"] += counter[0]
            for hash_, ids in matches.items():
                if len(ids) > 1:
                    reference = min((by_id[x] for x in ids), key=lambda e: e["identity"]["mtime_ns"])
                    out["duplicates"].append({"sha256": hash_, "candidate_ids": ids,
                                              "reference_candidate_id": reference["id"], "reference_basis": "oldest modified copy; heuristic, not proof of origin",
                                              "classification": "PROTECTED", "automatic_removal": False,
                                              "physical_savings": None})
    from _audit import enrich_analysis
    out.update(enrich_analysis(inventory, request))
    if request.get("previous_inventory"):
        from _audit import compare
        out["comparison"] = compare({"before": request["previous_inventory"], "after": inventory})
    return out


class Store:
    """Private local trust anchor, separate from inventories and report files."""
    def __init__(self, path):
        require(os.name == "posix", "Saved profiles and snapshots require POSIX permissions; use session policies on Windows")
        self.path = Path(os.path.abspath(os.path.expanduser(path)))
        existing = self.path
        while not os.path.lexists(existing):
            existing = existing.parent
        absolute(existing)
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        absolute(self.path)
        s = self.path.stat()
        if os.name == "posix":
            require(s.st_uid == os.getuid() and not s.st_mode & 0o077, "State directory must be owned by this user with mode 0700")
        keypath = self.path / "key"
        try:
            self.write_exclusive("key", secrets.token_bytes(32), raw=True)
        except FileExistsError:
            pass
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(keypath, flags)
        try:
            s = os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_size == 32 and s.st_nlink == 1, "Invalid state key")
            if os.name == "posix":
                require(s.st_uid == os.getuid() and not s.st_mode & 0o077, "Insecure state key")
            self.key = os.read(fd, 32)
        finally:
            os.close(fd)

    def write_exclusive(self, name, value, raw=False):
        data = value if raw else canonical(value)
        fd = os.open(self.path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())

    def signed(self, value):
        return {"payload": value, "signature": hmac.new(self.key, canonical(value), hashlib.sha256).hexdigest()}

    def save(self, name, value):
        self.write_exclusive(name, self.signed(value))

    def load(self, name):
        require(re.fullmatch(r"[a-z]+-[a-f0-9]{32}\.json", name), "Invalid state identifier")
        file = absolute(self.path / name)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(file, flags)
        try:
            st = os.fstat(fd)
            require(stat.S_ISREG(st.st_mode) and st.st_size < 32 * 1024**2, "Invalid or oversized state object")
            if os.name == "posix":
                require(st.st_uid == os.getuid() and not st.st_mode & 0o077, "Insecure state object")
            with os.fdopen(fd, "rb") as stream:
                fd = None
                value = json.loads(stream.read(32 * 1024**2))
        finally:
            if fd is not None:
                os.close(fd)
        require(isinstance(value, dict) and "payload" in value and isinstance(value.get("signature"), str), "Invalid state object format")
        expected = self.signed(value["payload"])["signature"]
        require(hmac.compare_digest(expected, value["signature"]), "State object signature mismatch")
        return value["payload"]


@contextlib.contextmanager
def directory_fd(path):
    """Pin every POSIX directory component, refusing symlinks throughout."""
    require(os.name == "posix" and os.open in os.supports_dir_fd, "Secure directory handles are unsupported on this platform")
    path = Path(path)
    require(path.is_absolute(), "Absolute path required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = new
        yield fd
    finally:
        os.close(fd)


def run_bounded(arguments, timeout=10, max_bytes=1024 * 1024):
    proc = None
    try:
        with tempfile.TemporaryFile() as stdout:
            proc = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + timeout
            timed_out = False
            oversized = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    proc.kill(); proc.wait(); break
                try:
                    proc.wait(timeout=min(0.05, remaining))
                    break
                except subprocess.TimeoutExpired:
                    if os.fstat(stdout.fileno()).st_size > max_bytes:
                        oversized = True
                        proc.kill(); proc.wait(); break
            stdout.seek(0)
            data = stdout.read(max_bytes + 1)
            truncated = oversized or len(data) > max_bytes
            return proc.returncode, data[:max_bytes], truncated, timed_out
    except OSError:
        return None, b"", False, False
    finally:
        # Never leave a child running if monitoring failed after launch.
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(OSError):
                proc.kill(); proc.wait()


def docker_audit(request):
    require(request.get("authorized") is True, "Docker socket inspection requires explicit scope authorization")
    require(shutil.which("docker"), "Docker is not installed")
    # Fixed arguments only. Honor the user's Docker context; no daemon mutation.
    commands = [["docker", "system", "df", "--format", "{{json .}}"],
                ["docker", "builder", "du", "--format", "json"]]
    results = []
    for args in commands:
        code, data, truncated, _ = run_bounded(args, timeout=15, max_bytes=1024 * 1024)
        if code is None:
            results.append({"interface": " ".join(args[:3]), "status": "unavailable", "metadata": None})
        else:
            results.append({"interface": " ".join(args[:3]), "status": "ok" if code == 0 else "unsupported-or-unavailable",
                            "truncated": truncated,
                            "metadata": data.decode("utf-8", errors="replace") if code == 0 else None})
    return {"results": results, "changes_made": False, "volumes_protected": True}


def human_report(request):
    if "operation" in request:
        from _audit import operation_report
        return operation_report(request)
    inventory = request["inventory"]
    shareable = request.get("shareable", True)
    def location(entry):
        if shareable:
            return "item-" + entry["id"][:8]
        # Untrusted names must never become Markdown links, images or HTML.
        # quote=False: numeric entities such as &#x27; would be broken by escaping "#".
        value = html.escape(entry["path"].replace("\n", "\\n").replace("\r", "\\r"), quote=False)
        return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", value)
    lines = ["# Swipr Storage Audit", "", "Status: read-only; no cleanup performed.",
             "Scope: " + str(len(inventory["roots"])) + " resolved roots.",
             "Coverage: " + ("complete within configured depth" if inventory["complete"] else "partial — inspect issues and limits"),
             "Skipped or limited locations: " + str(len(inventory["issues"])),
             "", "| Classification | Files | Logical bytes | Known allocated bytes |",
             "|---|---:|---:|---:|"]
    for kind, summary in inventory["summary"].items():
        lines.append(f"| {kind} | {summary['count']} | {summary['logical_bytes']} | {summary['allocated_bytes_known']} |")
    lines += ["", "Sizes count hard-linked inodes once. Shared blocks, clones, compression, snapshots and open files make physical savings uncertain.",
              "Nothing is removed without an exact approved plan.", "", "| Item | Logical bytes | Classification | Mechanism |", "|---|---:|---|---|"]
    if any(disk.get('free') is None for disk in inventory['disks']):
        lines.insert(6, 'Disk space: unknown for some roots; volume measurements were unavailable. File traversal coverage is reported separately.')
    for entry in sorted(inventory["entries"], key=lambda x: x["logical_bytes"], reverse=True)[:30]:
        lines.append(f"| {location(entry)} | {entry['logical_bytes']} | {entry['classification']} | {entry['strategy']} |")
    if request.get('include_next', True):
        lines += ["", "Next: review exact candidates, side effects and recovery. Permanent removal applies only to a fixed, unexpired plan.",
                  "Native browser, package, Docker, OS, and Trash cleanup is guided review only. Unknown data remains protected."]
    return {"markdown": "\n".join(lines) + "\n", "shareable": shareable}
