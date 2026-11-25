# Changelog

## 0.1.6 — 2026-11-26

- Harden request validation: empty or blank roots and exclusions, boolean or
  non-numeric scan budgets, `top` and hash byte budgets, snapshot and profile
  identifiers, candidate ID lists and removal plan fields are refused with a clear
  error instead of raising or being silently coerced. `policy` and `profile_id`
  cannot be combined, and a saved profile requires `state_dir`.
- Read saved state and removal records through a no-follow handle and require a
  regular, owner-only file (and an owner-only records directory on POSIX). `verify`
  rejects items outside the recorded plan, and `history operations` scans more
  directory entries before reaching its 2,000-record limit.
- Protect more data: `System Volume Information`, case-insensitive `.env*` names,
  and hashing now honors scan exclusions and refuses non-regular files. Windows
  system folders are protected only at the drive root, so per-user paths such as
  `AppData\Local\Microsoft\Windows\WER` match their rules.
- Treat more build manifests (`pom.xml`, Gradle, `tsconfig.json`, `global.json` and
  others) as source files, and have the offline-preservation policy also protect
  dependency stores.
- Escape every Markdown table cell against links, HTML and table breaks while
  keeping quotes readable, and place the unknown-disk-space note above the report
  table instead of inside its header.
- Run native and Docker commands through one bounded runner that always stops the
  child on timeout, oversized output or a monitoring failure. Windows PowerShell
  queries return JSON arrays even for a single row, and `activity` matches open
  files by resolved path.
- Count hard-linked files once per directory while counting distinct files
  normally, refuse non-finite JSON output, keep an already-written `--output` file
  from being overwritten by a later error, and replace unencodable console
  characters instead of failing.
- Speed up scanning with breadth-first traversal, one prepared rule index per scan,
  cached bytecode project markers and POSIX directory handles in place of repeated
  per-component checks.
- Skip editor and OS metadata files when packaging, ignore dependency and build
  folders in Markdown link checks, and keep the permission test running without
  `jsonschema` installed.

## 0.1.5 — 2026-11-08

- Make `start --guide` without folders suggest `start` for the bounded current-user
  scan, matching the default workflow, instead of `scan full --root PATH` and doctor.
- Render `find large`, `find directories` and `find duplicates` matches as readable
  tables with root-relative locations instead of raw JSON, and show non-normal
  storage health in scan summaries. JSON output is unchanged.
- Publish the repository as a Claude Code plugin marketplace with
  `.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json`, so
  `/plugin marketplace add kiron0/swipr` and `/plugin install swipr@swipr` work.
  Project validation keeps both manifest versions equal to the skill version.
- Speed up scanning and analysis about tenfold: indexed rule-signature matching,
  component-prefix scope checks, cached rule catalogs, no mount probe for regular
  files, per-directory project-marker caching and a linear duplicate reference lookup.
  A 50,000-file audit dropped from about 50 to 4.5 seconds on the test machine.
- Project build-artifact analysis now covers up to 100,000 entries, matching the full
  scan limit, instead of reporting partial analysis after 20,000.
- Use one cleanup flow on macOS, Linux and Windows: scan, exact digest-bound removal
  plan, one irreversible approval, permanent removal and verification. A new POSIX
  directory-handle backend matches the Windows NTFS-handle backend; only that native
  primitive differs per OS. The full scan now prepares `removal_plan` on every OS.
- Remove the POSIX bytecode quarantine, restore and separate purge workflow, including
  `plan create/show/validate/purge`, `approve`, `clean quarantine/restore/purge`,
  their helper scripts and schemas. Bytecode is now removed through the same exact
  plan and still must be at least 24 hours old.
- Removal checks every selected file before removing any, then reopens and rechecks
  each one before removal, so large plans no longer hold one handle per file.
  Records must be outside the scanned roots and owner-only on POSIX. Free space is
  measured per volume. `history operations` lists removal records on every OS.
- Offer native cleanup review on any OS when no permanent-removal plan is available.

## 0.1.4 — 2026-11-08

- Continue read-only discovery, inventory, analysis and comparison when volume-space
  queries are denied; report unknown measurements without losing collected files.
- Distinguish permission, missing-file and existing-output errors by failed stage,
  retain sanitized Windows error numbers, and report the active installation.
- Measure Windows removal space on target volumes, preserve verified outcomes when
  optional post-removal queries fail, and keep journal-space checks mandatory.
  No permission bypass or automatic retry.

## 0.1.3 — 2026-11-07

- Make `start` and the new `scan full` combine discovery, current-user metadata
  scanning, file/directory rankings, cache findings, health and possible duplicate
  size groups before one review prompt. Explicit scopes and policies take priority.
- Use structured host choices instead of magic reply phrases and per-step questions;
  retain exact-plan approval, workload confirmation and separate irreversible approval.
- Add `start --guide` for onboarding without a scan. Add direct Windows NTFS
  permanent removal of exact checked files after one irreversible review choice,
  with exclusive handles, digest/identity checks, one-use intent and verification.
- Increase the bounded terminal JSON reader to 256 MiB for full inventories;
  disclose scan coverage, proposal truncation and unverified duplicate groups.

## 0.1.2 — 2026-11-07

- Add guided `start` workflows without implicit scans or permissions.
- Add `explain` for exact saved findings, with optional private evidence.
- Give scoped audits contextual review steps, partial-coverage warnings and
  protected-only guidance without implying current execution eligibility.
- Clarify skill capability limits, command routing, and concise response guidance.
- Redesign the README with Hopilo's Unbounded/Onest typography, task-based commands,
  a platform matrix, expandable terminal instructions, and the official skills.sh
  link. Organize the evaluation guide.
- Clarify why skills.sh installations use the GitHub source name.
- Expand ignore rules for private state, local reports, environments, caches, and
  generated files. Remove the unused editable cover and move release-only notes
  outside the installable skill assets.

## 0.1.1 — 2026-11-07

- Add documented commands and subcommands for every workflow through one optional
  adapter, including help, discovery, scans, filtered file discovery, native inspection,
  exact plans, approval, cleanup, verification, reports, history, profiles, and rules.
- Add complete command examples and an advanced usage cookbook.
- Preserve explicit scope and approval gates; reserve private output files before
  operations, refuse overwrites, and bound JSON input.
- Use version-only release titles and document skills.sh listing steps.

## 0.1.0 — 2026-11-07

First published stable release.

- Provide all seven workflow phases and ten natural-language usage modes.
- Add bounded inventories, directory distributions, six file sort orders, exact
  duplicate audits, health findings and before/after comparisons.
- Expand versioned application, browser, temporary, diagnostics and developer rules,
  including project-marker evidence and installed-application association checks.
- Add authorized native volume, filesystem, log, snapshot, application and active-use
  queries, plus protected Trash/Recycle Bin inspection.
- Add restrictive policies, consented signed snapshots, exact approval plans,
  quarantine, non-overwriting restoration and operation journals.
- Add a separate irreversible approval workflow for permanent removal of exact
  verified private bytecode quarantine; preserve source, personal data and system state.
- Keep the README focused on installation and usage; document feature coverage,
  supported backends and native user-guided maintenance separately.
- Include schemas, behavioral cases, adversarial fixtures and multi-platform CI.
