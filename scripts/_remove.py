"""Explicit permanent removal on every supported OS, bound to a displayed digest and exact IDs."""
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import time

import _audit as audit
import _core as core

if os.name == 'nt':
    import _windows_file as files
else:
    import _posix_file as files


SOURCE_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.rs', '.go', '.c', '.h', '.cpp', '.cs', '.java',
                   '.kt', '.swift', '.php', '.rb', '.sh', '.ps1', '.bat', '.cmd', '.toml', '.yaml', '.yml', '.lock'}
SOURCE_NAMES = {'package.json', 'package-lock.json', 'composer.json', 'composer.lock', 'go.mod', 'go.sum',
                'cargo.lock', 'requirements.txt', 'dockerfile', 'makefile',
                'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'setup.cfg',
                'directory.build.props', 'global.json', 'pytest.ini', 'tsconfig.json'}


def eligible(entry, roots, exclusions, personal=False, _rules=None, _prepared=None):
    path, root = core.absolute(entry['path']), core.absolute(entry['root'])
    core.require(str(root) in roots and core.inside(path, root) and path != root, 'File escaped the reviewed scope')
    core.require(not core.protected(path, exclusions), 'Protected data cannot enter permanent removal')
    core.require(path.suffix.casefold() not in SOURCE_SUFFIXES and path.name.casefold() not in SOURCE_NAMES,
                 'Project source, manifests and scripts are protected')
    info = entry['identity']
    core.require(stat.S_ISREG(info['mode']) and info['links'] == 1, 'Select regular single-link files only')
    core.require(entry['id'] == core.digest({'path': str(path), 'identity': info})[:24], 'Invalid candidate identity')
    rules = core.read_rules() if _rules is None else _rules
    rule, kind, evidence = core.classify(path, root, info, rules, exclusions, _prepared=_prepared)
    core.require(rule is not None or personal is True, 'Select a recognized finding, or explicitly select a personal file before planning it')
    if rule:
        core.require(rule['id'] == entry['rule_id'] and evidence == entry['evidence'], 'Rule or evidence changed')
        core.require(rule['id'] != 'python-bytecode' or time.time_ns() - info['mtime_ns'] >= 86400 * 10**9,
                     'Bytecode is recent; leave it untouched')
    return path


def create_plan(request):
    policy = audit.policy(request.get('policy') or {})
    core.require(not policy.get('never_permanently_delete'), 'Policy forbids permanent removal')
    inventory = request['inventory']
    core.require(not inventory.get('protected_metadata_only'), 'Protected metadata cannot become a removal plan')
    selected = request['candidate_ids']
    core.require(isinstance(selected, list) and selected and len(selected) <= 1000
                 and all(isinstance(v, str) for v in selected) and len(selected) == len(set(selected)),
                 'Select 1–1000 distinct files')
    index = {entry['id']: entry for entry in inventory['entries']}
    core.require(all(value in index for value in selected), 'Unknown file selection')
    exclusions = [os.path.abspath(os.path.expanduser(x))
                  for x in dict.fromkeys(inventory.get('exclude', []) + policy.get('exclude', []))]
    excluded_paths = [Path(x) for x in exclusions]
    if policy.get('roots'):
        allowed = [core.absolute(root) for root in policy['roots']]
        core.require(all(any(core.inside(core.absolute(index[value]['path']), root) for root in allowed) for value in selected), 'Selection exceeds policy scope')
    rules = core.read_rules()
    prepared = core._prepare_rules(rules)
    entries = []
    skipped = []
    for value in selected:
        entry = dict(index[value])
        try:
            eligible(entry, inventory['roots'], excluded_paths, request.get('include_personal', False), _rules=rules, _prepared=prepared)
            core.require(not policy.get('preserve_offline') or ('cache' not in entry['category'] and entry['category'] != 'dependency-store'),
                         'Offline-preservation policy protects cached downloads and dependency stores')
            with files.OpenFile(entry) as opened:
                entry['handle_identity'] = opened.snapshot()
        except (OSError, core.Refusal):
            if not request.get('skip_unavailable'):
                raise
            skipped.append(value); continue
        entries.append(entry)
    core.require(entries, 'No eligible unlocked local files are available for removal')
    plan = {'schema_version': 1, 'id': secrets.token_hex(16), 'version': core.VERSION,
            'action': 'permanent-remove', 'created_at': core.now(), 'expires_at': time.time() + 900,
            'roots': inventory['roots'], 'exclude': exclusions, 'entries': entries,
            'include_personal': request.get('include_personal') is True,
            'skipped_ids': skipped,
            'rule_catalog_digest': core.digest(rules),
            'logical_bytes': sum(entry['logical_bytes'] for entry in entries),
            'warning': 'PERMANENT DELETION: selected files bypass Trash and Recycle Bin and cannot be restored by Swipr. Submit approval only for the exact checked files.'}
    plan['digest'] = core.digest(plan)
    return plan


def _save(file, value):
    with os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True); stream.flush(); os.fsync(stream.fileno())


def _absent(path):
    try:
        Path(path).lstat()
        return False
    except FileNotFoundError:
        return True


def execute(request):
    core.require(request.get('user_approved') is True and request.get('acknowledge_irreversible') is True,
                 'Submit explicit approval of permanent deletion before executing')
    plan = request['plan']
    core.require(isinstance(plan, dict), 'Invalid removal plan')
    payload = {key: value for key, value in plan.items() if key != 'digest'}
    core.require(plan.get('action') == 'permanent-remove' and request.get('plan_digest') == plan.get('digest') == core.digest(payload), 'Plan differs from the digest shown before approval')
    expires = plan.get('expires_at')
    now_ts = time.time()
    core.require(type(expires) in (int, float) and math.isfinite(expires) and now_ts < expires <= now_ts + 901, 'Removal plan expired or has invalid expiry; review a fresh plan')
    rules = core.read_rules()
    core.require(plan.get('rule_catalog_digest') == core.digest(rules), 'Rules changed; review a fresh plan')
    selected = request['candidate_ids']
    index = {entry['id']: entry for entry in plan['entries']}
    core.require(isinstance(selected, list) and selected and len(selected) <= 1000
                 and all(isinstance(v, str) for v in selected) and len(selected) == len(set(selected))
                 and all(value in index for value in selected), 'Approve only exact distinct IDs in the reviewed plan')
    core.require(isinstance(plan.get('id'), str) and re.fullmatch(r'[a-f0-9]{32}', plan['id']), 'Invalid plan identifier')
    state = Path(os.path.abspath(os.path.expanduser(request['state_dir'])))
    core.require(not any(core.inside(state, Path(root)) or core.inside(Path(root), state) for root in plan['roots']),
                 'Removal records must be outside the scanned roots')
    parent = state
    while not os.path.lexists(parent):
        parent = parent.parent
    core.absolute(parent); state.mkdir(mode=0o700, parents=True, exist_ok=True); core.absolute(state)
    if os.name == 'posix':
        owner = state.stat()
        core.require(owner.st_uid == os.getuid() and not owner.st_mode & 0o077, 'Removal records directory must be owned by this user with mode 0700')
    if os.path.lexists(state / ('remove-used-' + plan['id'] + '.json')):
        raise FileExistsError('Removal plan already consumed; inspect records before another review')
    core.require(not any(core.inside(core.absolute(index[value]['path']), state) for value in selected), 'Removal cannot target its own operation records')
    journal_space = shutil.disk_usage(state).free
    core.require(journal_space > 65536 + len(core.canonical(plan)) * 3, 'Insufficient space to journal removal')
    volumes = {}
    for value in selected:
        volumes.setdefault(index[value]['identity']['device'], str(Path(index[value]['path']).parent))
    volume_roots = sorted(volumes.values())
    before_space = {root: core.disk_metadata(root)['free'] for root in volume_roots}
    operation = {'id': secrets.token_hex(16), 'action': 'permanent-remove', 'plan_id': plan['id'], 'plan_digest': plan['digest'],
                 'created_at': core.now(), 'selected_ids': selected, 'plan': plan, 'irreversible': True}
    # One-use, flushed intent precedes any delete disposition. A crash never grants a retry.
    _save(state / ('remove-used-' + plan['id'] + '.json'), operation)
    prepared = core._prepare_rules(rules)
    excluded_paths = [Path(os.path.abspath(os.path.expanduser(x))) for x in plan['exclude']]
    items = []
    for value in selected:
        entry = index[value]
        eligible(entry, plan['roots'], excluded_paths, plan['include_personal'], _rules=rules, _prepared=prepared)
        with files.OpenFile(entry) as opened:
            core.require(opened.snapshot() == entry['handle_identity'], 'File changed since the removal plan')
    for value in selected:
        entry = index[value]
        item = {'candidate_id': entry['id'], 'status': 'failed-stop', 'verified_absent': False}
        try:
            core.require(time.time() < plan['expires_at'], 'Plan expired during removal')
            with files.OpenFile(entry) as opened:
                core.require(opened.snapshot() == entry['handle_identity'], 'File changed before removal')
                _save(state / ('remove-attempt-' + operation['id'] + '-' + entry['id'] + '.json'), {'operation_id': operation['id'], 'entry': entry})
                files.mark_for_removal(opened)
                item['deletion_requested'] = True
            core.require(_absent(entry['path']), 'Path remains or regenerated; do not retry removal')
            item.update(status='permanently-removed', verified_absent=True)
        except (OSError, core.Refusal):
            item['reason'] = 'Removal stopped; inspect records before any new approval'
        items.append(item)
        if item['status'] == 'failed-stop':
            break
    volume_space = []
    for root in volume_roots:
        before, after = before_space[root], core.disk_metadata(root)['free']
        volume_space.append({'root': root, 'before_free': before, 'after_free': after,
                             'observed_free_delta': after - before if before is not None and after is not None else None})
    measured = volume_space[0] if len(volume_space) == 1 else {'before_free': None, 'after_free': None, 'observed_free_delta': None}
    result = {**{key: value for key, value in operation.items() if key != 'plan'}, 'items': items,
              'before_free': measured['before_free'], 'after_free': measured['after_free'],
              'observed_free_delta': measured['observed_free_delta'], 'volume_space': volume_space,
              'all_verified': len(items) == len(selected) and all(item['verified_absent'] for item in items),
              'changes_made': any(item.get('deletion_requested') for item in items), 'verified_at': core.now(),
              'warning': 'Permanent removal has no Swipr undo. Free-space changes can include unrelated activity.'}
    _save(state / ('remove-result-' + operation['id'] + '.json'), result)
    return result


def _read_record(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        core.require(stat.S_ISREG(st.st_mode) and st.st_size <= 32 * 1024**2, 'Operation record is invalid or too large')
        if os.name == 'posix':
            core.require(st.st_uid == os.getuid() and not st.st_mode & 0o077, 'Operation record permissions are insecure')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            return json.loads(stream.read(32 * 1024**2))
    finally:
        if fd is not None:
            os.close(fd)


def verify(request):
    identifier = request['operation_id']
    core.require(isinstance(identifier, str) and re.fullmatch(r'[a-f0-9]{32}', identifier), 'Invalid operation identifier')
    state = core.absolute(request['state_dir'])
    if os.name == 'posix':
        owner = state.stat()
        core.require(owner.st_uid == os.getuid() and not owner.st_mode & 0o077, 'Removal records directory must be owned by this user with mode 0700')
    result_file = core.absolute(state / ('remove-result-' + identifier + '.json'))
    result = _read_record(result_file)
    core.require(isinstance(result, dict) and isinstance(result.get('plan_id'), str)
                 and re.fullmatch(r'[a-f0-9]{32}', result['plan_id']), 'Invalid plan identifier in operation record')
    intent_file = core.absolute(state / ('remove-used-' + result['plan_id'] + '.json'))
    intent = _read_record(intent_file)
    core.require(intent['id'] == identifier and intent['plan_digest'] == result['plan_digest'], 'Operation records disagree')
    plan_payload = {key: value for key, value in intent['plan'].items() if key != 'digest'}
    core.require(core.digest(plan_payload) == intent['plan']['digest'] == result['plan_digest'], 'Recorded plan digest changed')
    index = {entry['id']: entry for entry in intent['plan']['entries']}
    for item in result['items']:
        core.require(item['candidate_id'] in index, 'Operation item outside recorded plan')
        entry = index[item['candidate_id']]
        try:
            core.absolute(Path(entry['path']).parent)
            item['verified_absent'] = item['status'] == 'permanently-removed' and _absent(entry['path'])
        except (OSError, core.Refusal):
            item['verified_absent'] = False
    result['all_verified'] = len(result['items']) == len(intent['selected_ids']) and all(item['verified_absent'] for item in result['items'])
    result['verified_at'] = core.now()
    return result


def operations(request):
    state = core.absolute(request['state_dir'])
    if os.name == 'posix':
        owner = state.stat()
        core.require(owner.st_uid == os.getuid() and not owner.st_mode & 0o077, 'Removal records directory must be owned by this user with mode 0700')
    results, intents = {}, {}
    matched = 0
    with os.scandir(state) as items:
        for index, item in enumerate(items):
            if index >= 200000 or matched >= 2000:
                break
            match = re.fullmatch(r'remove-(result|used)-([a-f0-9]{32})\.json', item.name)
            if not match or not item.is_file(follow_symlinks=False):
                continue
            matched += 1
            value = _read_record(core.absolute(state / item.name))
            (results if match[1] == 'result' else intents)[value['id']] = value
    records = []
    for identifier, intent in sorted(intents.items(), key=lambda pair: pair[1]['created_at'], reverse=True)[:100]:
        result = results.get(identifier)
        status = ('interrupted-or-pending' if result is None else 'complete' if result['all_verified'] else 'partial')
        records.append({'id': identifier, 'record': 'remove', 'status': status, 'plan_id': intent['plan_id']})
    return {'operations': records, 'changes_made': False, 'limit': 100}
