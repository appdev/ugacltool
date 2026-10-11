"""Read-only MD discovery. Only an explicit, fresh selection pins write intent."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

import disk_safety as safety
from patch_btrfs_ugos import ValidationError


def canonical_md(value):
    return str(uuid.UUID(value.replace(':', '').replace('-', '')))


def export_fields(text):
    result = {}
    for line in text.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key in result:
            raise ValidationError('Duplicate MD metadata field')
        result[key] = value
    if not result.get('MD_UUID'):
        return None
    result['MD_UUID'] = canonical_md(result['MD_UUID'])
    return result


def examine(path):
    if not re.fullmatch(r'/dev/[A-Za-z0-9_.+-]+', path):
        raise ValidationError('Unsupported partition path')
    value = subprocess.run(['mdadm', '--examine', '--export', path],
                           capture_output=True, text=True, timeout=15)
    return export_fields(value.stdout) if value.returncode == 0 else None


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def discover(disks=None, critical=None, reader=None, native_md=None):
    """No assembly, activation, mounting or state write during discovery."""
    disks = safety.inventory() if disks is None else disks
    critical = safety.system_serials(disks) if critical is None else set(critical)
    reader = examine if reader is None else reader
    native_md = native_arrays() if native_md is None else set(native_md)
    if not critical:
        raise ValidationError('System disk protection cannot be established')
    top = [d for d in disks if d.get('type') == 'disk']
    identities = []
    for disk in top:
        identities.append(safety.identity({'serial': (disk.get('serial') or '').strip(),
            'model': (disk.get('model') or '').strip(), 'size': disk.get('size')}))
    if len({d['serial'] for d in identities}) != len(identities):
        raise ValidationError('Duplicate physical serials; discovery refused')
    if not critical <= {d['serial'] for d in identities}:
        raise ValidationError('System disk is absent from inventory')
    groups = {}
    for disk, identity in zip(top, identities):
        for child in disk.get('children', []):
            if child.get('type') != 'part':
                continue
            fields = reader(child['name'])
            if not fields:
                continue
            record = dict(identity, partition=child['name'], partition_identity=child['maj:min'])
            groups.setdefault(fields['MD_UUID'], []).append((record, fields))
    found = []
    for md_uuid, entries in sorted(groups.items()):
        members = sorted((r for r, _ in entries), key=lambda r: r['serial'])
        metadata = [m for _, m in entries]
        expected = {m.get('MD_DEVICES') for m in metadata}
        levels = {m.get('MD_LEVEL') for m in metadata}
        reason = None
        if len(expected) != 1 or None in expected or not next(iter(expected)).isdigit():
            reason = '无法确认完整阵列成员数量'
        elif int(next(iter(expected))) != len(members):
            reason = '阵列缺盘或存在额外成员'
        elif len({m['serial'] for m in members}) != len(members):
            reason = '同一硬盘重复归属该阵列'
        elif len(levels) != 1 or next(iter(levels)) not in ('linear', 'raid1', 'raid6'):
            reason = '尚未支持的阵列结构'
        elif {m['serial'] for m in members} & critical:
            reason = '包含正在使用的系统硬盘'
        elif md_uuid in native_md:
            reason = '已经属于飞牛原生存储空间'
        snapshot = {'md_uuid': md_uuid, 'level': sorted(levels, key=str), 'members': members}
        # Freeze other disks too: replacement/addition requires a new selection.
        snapshot['protected'] = [dict(i, role='system' if i['serial'] in critical else 'other')
                                 for i in identities if i['serial'] not in {m['serial'] for m in members}]
        snapshot['protected'].sort(key=lambda d: d['serial'])
        snapshot['eligible'] = reason is None
        snapshot['reason'] = reason
        snapshot['selection'] = fingerprint(snapshot)
        found.append(snapshot)
    return found


def public_candidate(candidate):
    return {'selection': candidate['selection'], 'eligible': candidate['eligible'],
            'reason': candidate['reason'], 'level': candidate['level'][0],
            'members': [{k: d[k] for k in ('serial', 'model', 'size')} for d in candidate['members']]}


def native_arrays():
    """Recognize already-native MD backings without publishing VG names."""
    result = subprocess.run(['pvs', '--reportformat', 'json', '-o', 'pv_name,vg_name'],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValidationError('LVM inventory failed')
    native = set()
    for pv in json.loads(result.stdout)['report'][0]['pv']:
        if not pv['vg_name'].strip().startswith('trim_'):
            continue
        value = os.stat(pv['pv_name'].strip())
        node = (Path('/sys/dev/block') / ('%d:%d' % (os.major(value.st_rdev), os.minor(value.st_rdev)))).resolve(strict=True)
        if (node / 'md/uuid').is_file():
            native.add(canonical_md((node / 'md/uuid').read_text().strip()))
    return native


def recheck_selection(selected, candidates=None):
    if selected.get('selection') != fingerprint({k: v for k, v in selected.items() if k != 'selection'}):
        raise ValidationError('Selection snapshot was modified')
    candidates = discover() if candidates is None else candidates
    matches = [c for c in candidates if c['selection'] == selected['selection']]
    if len(matches) != 1 or not matches[0]['eligible'] or matches[0] != selected:
        raise ValidationError('阵列身份或容量已变化，请重新选择')
    # Device paths are derived from observed partitions, never the HTTP payload.
    for member in selected['members']:
        value = os.stat(member['partition'])
        if (not stat.S_ISBLK(value.st_mode)
                or '%d:%d' % (os.major(value.st_rdev), os.minor(value.st_rdev)) != member['partition_identity']):
            raise ValidationError('Selected partition device was replaced')
    return selected
