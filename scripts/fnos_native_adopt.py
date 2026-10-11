#!/usr/bin/env python3
"""Journaled metadata-only adoption of already converted, pinned UGREEN pools.

No formatting, array creation/reshape, recursive permission changes, data moves,
or superblock restoration. Preserve the existing fnOS volume and native rows.
Prepare is read-only except root-private evidence files and LVM metadata backups.
Apply requires compatibility mounts stopped and all disks/topology revalidated.
"""
import argparse
import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import platform
import stat
import subprocess
import sys
import uuid

import fnos_storage as storage
import disk_safety
from patch_btrfs_ugos import ValidationError


TESTED_NATIVE = {
    'kernel': '6.18.18.c1107-trim',
    'native_driver': '38dd9779b959350034273c5dac5ec36120975296bd16125378b5f8ec9f10d4d6',
    'storage_handler': '005d016e08162fa60cad85df3cd12617f8750d8c76f2aa044af66ae18d71cef6',
}


def check_native_version():
    actual = {'kernel': platform.release(),
              'native_driver': hashlib.sha256(Path('/usr/trim/lib/libndev.so').read_bytes()).hexdigest(),
              'storage_handler': hashlib.sha256(Path('/usr/trim/bin/handlers/storage.hdl').read_bytes()).hexdigest()}
    if actual != TESTED_NATIVE:
        raise ValidationError('fnOS native implementation differs from the isolated tested version')
    return actual


def save(path, value):
    temporary = path.parent / (path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sql(query):
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At',
                             '-v', 'ON_ERROR_STOP=1', '-d', 'trim'],
                            input=query, text=True, capture_output=True)
    if result.returncode:
        raise ValidationError('Native storage database operation failed')
    return result.stdout.strip()


def rows():
    value = sql("SELECT COALESCE(json_agg(row_to_json(m)), '[]'::json) FROM "
                "(SELECT id,uuid,state,pool_type FROM public.mount ORDER BY id,uuid) m;")
    return json.loads(value)


def lv_record(source):
    value = storage.view.run('lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                             '-o', 'vg_name,lv_name,lv_uuid,lv_size', source)
    records = json.loads(value)['report'][0]['lv']
    if len(records) != 1:
        raise ValidationError('Expected exactly one LV')
    return records[0]


def disk_records(md, policy, pool_id):
    return disk_safety.array_members(md, policy, pool_id)


def check_pool(pool, expected_disks=None, offline=False, policy=None):
    if policy is None:
        raise ValidationError('Explicit protected/target disk policy is required')
    fd, node, md, _ = storage.check_source(pool)
    try:
        actual = disk_records(md, policy, pool['id'])
        # Partition kernel names may change; serial and capacity own identity.
        identity = lambda items: sorted((d['serial'], d['model'], d['size']) for d in items)
        if expected_disks is not None and identity(actual) != identity(expected_disks):
            raise ValidationError('Array member serial/capacity changed')
        if offline and (storage.view.mounts(storage.view.dev_id(fd)) or list((node / 'holders').iterdir())):
            raise ValidationError('Array is in use; ordinary stop/unmount is required')
        if {p.name for p in (md / 'holders').iterdir()} != {node.name}:
            raise ValidationError('Array has a foreign holder')
        if len(json.loads(storage.view.run('lvs', '--reportformat', 'json', pool['vg']))['report'][0]['lv']) != 1:
            raise ValidationError('VG has unexpected additional logical volumes')
        return actual
    finally:
        os.close(fd)


def prepare(config_path, directory):
    check_native_version()
    config = storage.validate_config(storage.private_json(config_path))
    policy = disk_safety.check_config(config)
    if any(p.get('native_adoption') or p.get('mode') != 'rw' for p in config['pools']):
        raise ValidationError('Only previously validated RW UGREEN origins can be adopted')
    baseline = rows()
    occupied = {r['id'] for r in baseline} | {1}
    records = []
    for pool in config['pools']:
        disks = check_pool(pool, policy=policy)
        point = Path(pool['mount'])
        storage.check_mount(storage.mount_record(point), pool['source'], 'rw')
        # Never overwrite an original directory with fnOS reserved directories.
        if any((point / name).exists() for name in [str(config['uid']), '@team', 'thumb']):
            raise ValidationError('Original root has a native reserved-directory collision')
        number = 2
        while number in occupied:
            number += 1
        occupied.add(number)
        if Path('/vol%d' % number).exists():
            raise ValidationError('Proposed native mount path already exists')
        native_vg = 'trim_' + str(uuid.uuid4()).replace('-', '_')
        try:
            marker = os.getxattr(point, 'user.is_trimacl').hex()
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                raise
            marker = None
        records.append({'pool': copy.deepcopy(pool), 'disks': disks,
                        'vg': native_vg, 'lv': '0', 'uuid': native_vg + '-0',
                        'storage_id': number, 'phase': 'prepared', 'root_marker_before': marker})
    directory.mkdir(mode=0o700)
    journal = {'version': 2, 'state': 'prepared', 'config_path': str(config_path),
               'config_before': config, 'database_before': baseline, 'pools': records}
    save(directory / 'journal.json', journal)
    for entry in records:
        storage.view.run('vgcfgbackup', '-f', str(directory / (entry['pool']['id'] + '.vgbackup')),
                         entry['pool']['vg'])
    journal['backups_ready'] = True
    save(directory / 'journal.json', journal)
    return journal


def renamed_pool(entry):
    pool = copy.deepcopy(entry['pool'])
    pool.update(vg=entry['vg'], lv='0', source='/dev/' + entry['vg'] + '/0')
    pool['native_adoption'] = {'original_vg': entry['pool']['vg'],
                              'original_lv': entry['pool']['lv'],
                              'uuid': entry['uuid'], 'storage_id': entry['storage_id']}
    return pool


def validate_journal(journal):
    if journal.get('version') != 2:
        raise ValidationError('Public adoption requires a new version 2 journal; do not reuse private legacy journals')
    original = storage.validate_config(journal['config_before'])
    policy = disk_safety.policy_for(original)
    if len(journal['pools']) != len(original['pools']):
        raise ValidationError('Journal origin count differs')
    ids, names = set(), set()
    for entry, pool in zip(journal['pools'], original['pools']):
        if (entry['pool'] != pool or pool.get('native_adoption')
                or entry['uuid'] != entry['vg'] + '-0' or entry['lv'] != '0'
                or entry['storage_id'] in ids or entry['vg'] in names
                or len(entry['disks']) != pool['members']):
            raise ValidationError('Journal origin/target provenance differs')
        data = copy.deepcopy(original); data['pools'] = [renamed_pool(entry)]
        storage.validate_config(data)
        physical = lambda entries: sorted(tuple(disk_safety.identity(d)[k] for k in ('serial', 'model', 'size')) for d in entries)
        if physical(entry['disks']) != physical(policy['pools'][pool['id']]):
            raise ValidationError('Journal physical identities differ from frozen target policy')
        ids.add(entry['storage_id']); names.add(entry['vg'])
    if any(row['id'] in ids or row['uuid'] in {e['uuid'] for e in journal['pools']}
           for row in journal['database_before']):
        raise ValidationError('Journal would replace a pre-existing native storage record')
    return journal


def finish_rename(entry, policy):
    """Resume only the pinned LV at one of the journal's exact intermediate names."""
    original = entry['pool']
    all_lvs = json.loads(storage.view.run('lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                                         '-o', 'vg_name,lv_name,lv_uuid,lv_size'))['report'][0]['lv']
    found = [lv for lv in all_lvs if lv['lv_uuid'] == original['lv_uuid']]
    if len(found) != 1:
        raise ValidationError('Pinned LV is missing or duplicated during rename')
    actual = found[0]
    if (actual['vg_name'] not in (original['vg'], entry['vg'])
            or actual['lv_name'] not in (original['lv'], '0')
            or int(float(actual['lv_size'])) != original['size']):
        raise ValidationError('Interrupted rename has an unexpected identity')
    if (actual['vg_name'], actual['lv_name']) == (entry['vg'], '0'):
        return
    temporary = copy.deepcopy(original)
    temporary.update(vg=actual['vg_name'], lv=actual['lv_name'],
                     source='/dev/' + actual['vg_name'] + '/' + actual['lv_name'])
    check_pool(temporary, entry['disks'], offline=True, policy=policy)
    occupied = [lv for lv in all_lvs if lv['vg_name'] == entry['vg'] and lv['lv_uuid'] != original['lv_uuid']]
    if occupied:
        raise ValidationError('Generated native VG name is occupied')
    if actual['lv_name'] != '0':
        storage.view.run('lvrename', actual['vg_name'], actual['lv_name'], '0')
    if actual['vg_name'] != entry['vg']:
        storage.view.run('vgrename', actual['vg_name'], entry['vg'])


def register(entry, baseline):
    current = rows()
    # Existing volumes and rows must be preserved exactly.
    for row in baseline:
        if row not in current:
            raise ValidationError('Pre-existing native storage record changed')
    matches = [r for r in current if r['id'] == entry['storage_id'] or r['uuid'] == entry['uuid']]
    expected = {'id': entry['storage_id'], 'uuid': entry['uuid'], 'state': 0, 'pool_type': 0}
    if matches:
        if matches != [expected]:
            raise ValidationError('Native storage ID/UUID collision')
        return
    number, identifier = entry['storage_id'], entry['uuid']
    if type(number) is not int or number < 2 or not re.fullmatch(r'trim_[0-9a-f_]+-0', identifier):
        raise ValidationError('Invalid native database target')
    # The guard and insert share a locked transaction, not two racing queries.
    query = "BEGIN;LOCK TABLE public.mount IN EXCLUSIVE MODE;DO $$BEGIN "
    query += "IF EXISTS(SELECT 1 FROM public.mount WHERE id=%d OR uuid='%s') THEN RAISE EXCEPTION 'occupied';END IF;" % (number, identifier)
    query += "INSERT INTO public.mount(id,uuid,comment,warn_frsize,stripe_cache_size,pool_type) VALUES(%d,'%s','UGREEN %s',10,4096,0);" % (number, identifier, entry['pool']['id'])
    query += 'END$$;COMMIT;'
    sql(query)


def publish_home(staging, home):
    """Publish only a newly created home, never overwrite a racing native home."""
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staging), -100, os.fsencode(home), 1):
        raise ValidationError('Native personal home publication failed; staging directory retained')


def apply(directory):
    check_native_version()
    journal = validate_journal(storage.private_json(directory / 'journal.json'))
    policy = disk_safety.check_config(journal['config_before'])
    if not journal.get('backups_ready'):
        raise ValidationError('Original LVM metadata backups were not completed')
    config_path, after = current_configuration(journal)
    for entry in journal['pools']:
        backup = directory / (entry['pool']['id'] + '.vgbackup')
        fd = os.open(backup, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o077 or info.st_size > 1024**2:
                raise ValidationError('Unsafe LVM metadata backup')
            if entry['pool']['lv_uuid'].encode() not in os.read(fd, 1024**2):
                raise ValidationError('LVM metadata backup identity differs')
        finally:
            os.close(fd)
    for entry in journal['pools']:
        old, new = entry['pool'], renamed_pool(entry)
        if entry['phase'] in ('prepared', 'reverted'):
            check_pool(old, entry['disks'], offline=True, policy=policy)
            # Write intent before each metadata operation for explicit recovery.
            entry['phase'] = 'renaming'; save(directory / 'journal.json', journal)
            finish_rename(entry, policy)
            entry['phase'] = 'renamed'; save(directory / 'journal.json', journal)
        elif entry['phase'] == 'renaming':
            finish_rename(entry, policy)
            entry['phase'] = 'renamed'; save(directory / 'journal.json', journal)
        check_pool(new, entry['disks'], policy=policy)
        register(entry, journal['database_before'])
        entry['phase'] = 'registered'; save(directory / 'journal.json', journal)
        point = Path('/vol%d' % entry['storage_id'])
        if storage.mount_record(point):
            storage.check_mount(storage.mount_record(point), new['source'], 'rw')
        else:
            point.mkdir(mode=0o700, exist_ok=True)
            if point.is_symlink() or any(point.iterdir()):
                raise ValidationError('Native mount path is not an empty real directory')
            # Existing UGOS roots can reject mkdir under native ACL processing.
            # Initialize only the new personal home under the original POSIX
            # policy, then enable native ACLs before publishing account access.
            storage.view.run('mount', '-t', 'btrfs', '-o', 'rw,notrimacl', new['source'], str(point))
            storage.check_mount(storage.mount_record(point), new['source'], 'rw')
        home = point / str(after['uid'])
        if not home.exists():
            if 'trimacl' in storage.mount_record(point)['super_options']:
                raise ValidationError('Unmount through fnOS before initializing the new personal home')
            # Direct mkdir of a numeric home can be rejected on imported roots.
            # Create a private, owned empty directory first and publish it with
            # RENAME_NOREPLACE. Journal the name before creating anything.
            if not entry.get('home_staging'):
                entry['home_staging'] = 'ugacl-native-home-' + uuid.uuid4().hex
                save(directory / 'journal.json', journal)
            name = entry['home_staging']
            if not re.fullmatch(r'ugacl-native-home-[0-9a-f]{32}', name):
                raise ValidationError('Invalid personal home staging name')
            staging = point / name
            staging.mkdir(mode=0o700, exist_ok=True)
            if (staging.is_symlink() or not staging.is_dir() or any(staging.iterdir())
                    or staging.stat().st_uid not in (0, after['uid'])
                    or stat.S_IMODE(staging.stat().st_mode) != 0o700):
                raise ValidationError('Personal home staging directory differs')
            os.chown(staging, after['uid'], after['gid'])
            publish_home(staging, home)
        if home.is_symlink() or not home.is_dir() or home.stat().st_uid != after['uid']:
            raise ValidationError('Native personal root conflicts with original data')
        if 'trimacl' not in storage.mount_record(point)['super_options']:
            storage.view.run('mount', '-o', 'remount,rw,trimacl', str(point))
        if 'trimacl' not in storage.mount_record(point)['super_options']:
            raise ValidationError('Native ACL mounting did not become active')
        storage.view.run('/usr/trim/bin/trimacl', '-m', 'e', str(home))
        # fnOS checks this root-only marker for native ACL v2 storage. Existing
        # file POSIX modes/owners and ACLs are preserved, with no recursive scan.
        entry['root_marker_set'] = True
        save(directory / 'journal.json', journal)  # Marker intent survives interruption.
        os.setxattr(point, 'user.is_trimacl', b'1')
        entry['phase'] = 'mounted'; save(directory / 'journal.json', journal)
    save(config_path, after)
    journal['state'] = 'adopted'; save(directory / 'journal.json', journal)
    return journal


def current_configuration(journal):
    path = Path(journal['config_path'])
    after = copy.deepcopy(journal['config_before'])
    after['pools'] = [renamed_pool(e) for e in journal['pools']]
    storage.validate_config(after)
    if storage.private_json(path) not in (journal['config_before'], after):
        raise ValidationError('Configuration or disk policy changed after preparation')
    return path, after


def rollback(directory):
    check_native_version()
    journal = validate_journal(storage.private_json(directory / 'journal.json'))
    policy = disk_safety.check_config(journal['config_before'])
    current_configuration(journal)
    for entry in reversed(journal['pools']):
        if entry['phase'] in ('prepared', 'reverted'):
            continue
        if entry['phase'] == 'renaming':
            finish_rename(entry, policy)
        new = renamed_pool(entry)
        if entry['phase'] != 'reverting':
            check_pool(new, entry['disks'], policy=policy)
            if storage.mount_record('/vol%d' % entry['storage_id']):
                raise ValidationError('Stop compatibility aliases, then unmount this volume through fnOS before rollback')
            check_pool(new, entry['disks'], offline=True, policy=policy)
            if entry.get('root_marker_set'):
                # The volume was unmounted through fnOS; use a task-private
                # temporary mount solely to restore the one root marker.
                temporary = directory / (entry['pool']['id'] + '-marker-root')
                temporary.mkdir(mode=0o700, exist_ok=True)
                if temporary.is_symlink() or any(temporary.iterdir()):
                    raise ValidationError('Marker rollback target is not empty')
                storage.view.run('mount', '-t', 'btrfs', '-o', 'rw', new['source'], str(temporary))
                try:
                    storage.check_mount(storage.mount_record(temporary), new['source'], 'rw')
                    previous = entry.get('root_marker_before')
                    restore_marker(temporary, previous)
                finally:
                    storage.view.run('umount', str(temporary))
                entry['root_marker_set'] = False
            entry['phase'] = 'reverting'; save(directory / 'journal.json', journal)
        all_lvs = json.loads(storage.view.run('lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
                                             '-o', 'vg_name,lv_name,lv_uuid,lv_size'))['report'][0]['lv']
        matches = [lv for lv in all_lvs if lv['lv_uuid'] == entry['pool']['lv_uuid']]
        if len(matches) != 1:
            raise ValidationError('Rollback LV identity missing/duplicated')
        current = matches[0]
        if (current['vg_name'] not in (entry['vg'], entry['pool']['vg'])
                or current['lv_name'] not in ('0', entry['pool']['lv'])
                or int(float(current['lv_size'])) != entry['pool']['size']):
            raise ValidationError('Rollback names/capacity differ')
        pinned = copy.deepcopy(entry['pool'])
        pinned.update(vg=current['vg_name'], lv=current['lv_name'],
                      source='/dev/' + current['vg_name'] + '/' + current['lv_name'])
        check_pool(pinned, entry['disks'], offline=True, policy=policy)
        if current['vg_name'] != entry['pool']['vg']:
            storage.view.run('vgrename', current['vg_name'], entry['pool']['vg'])
        if current['lv_name'] != entry['pool']['lv']:
            storage.view.run('lvrename', entry['pool']['vg'], current['lv_name'], entry['pool']['lv'])
        # Remove only this task's exact storage registration, never user data.
        matches = [row for row in rows() if row['id'] == entry['storage_id'] or row['uuid'] == entry['uuid']]
        expected = {'id': entry['storage_id'], 'uuid': entry['uuid'], 'state': 0, 'pool_type': 0}
        if matches and matches != [expected]:
            raise ValidationError('Rollback database row differs; leave it untouched')
        sql("BEGIN;LOCK TABLE public.mount IN EXCLUSIVE MODE;DELETE FROM public.mount "
            "WHERE id=%d AND uuid='%s' AND state=0 AND pool_type=0;COMMIT;" % (entry['storage_id'], entry['uuid']))
        check_pool(entry['pool'], entry['disks'], policy=policy)
        entry['phase'] = 'reverted'; save(directory / 'journal.json', journal)
    save(Path(journal['config_path']), journal['config_before'])
    for row in journal['database_before']:
        if row not in rows():
            raise ValidationError('Pre-existing database rows differ after rollback')
    journal['state'] = 'rolled_back'; save(directory / 'journal.json', journal)
    return journal


def restore_marker(point, previous):
    previous_bytes = None if previous is None else bytes.fromhex(previous)
    try:
        actual = os.getxattr(point, 'user.is_trimacl')
    except OSError as exc:
        if exc.errno != errno.ENODATA:
            raise
        actual = None
    if actual == previous_bytes:
        return  # The journaled write had not occurred, or rollback finished.
    if actual != b'1':
        raise ValidationError('Root marker changed; do not overwrite it')
    if previous_bytes is None:
        os.removexattr(point, 'user.is_trimacl')
    else:
        os.setxattr(point, 'user.is_trimacl', previous_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'apply', 'rollback', 'status'])
    parser.add_argument('--config', type=Path, default=Path('/etc/ugacltool/storage.json'))
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        storage.view.require_host()
        if args.action == 'prepare':
            result = prepare(args.config, args.directory)
        else:
            # Root-only journal ownership and a nonblocking lock prevent overlap.
            if args.directory.is_symlink() or args.directory.stat().st_uid or args.directory.stat().st_mode & 0o077:
                raise ValidationError('Unsafe adoption directory')
            fd = os.open(args.directory / 'lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                operation = {'apply': apply, 'rollback': rollback}.get(args.action)
                result = operation(args.directory) if operation else validate_journal(storage.private_json(args.directory / 'journal.json'))
            finally:
                os.close(fd)
        print(json.dumps({'state': result['state'], 'pools': [
            {'id': e['pool']['id'], 'storage_id': e['storage_id'], 'uuid': e['uuid'], 'phase': e['phase']}
            for e in result['pools']]}))
        return 0
    except (ValidationError, OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
