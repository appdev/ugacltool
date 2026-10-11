#!/usr/bin/env python3
"""Explicit, pinned offline UGOS -> fnOS superblock conversion.

Requires successful SAME-origin/kernel isolated COW evidence. Saves original
mirrors before enabling runtime writes; changes only UGACL bit and CRC32C.
Never mounts, formats, repairs, disables quotas or rewinds filesystem writes.
After the first RW mount, old superblocks MUST NOT be restored as rollback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

import btrfs_readonly_view as view
import fnos_storage as storage
from patch_btrfs_ugos import (scan, patch_superblock, parse_superblock,
                             ValidationError, MIRRORS, SUPER_SIZE, _pwrite_all)


def headers_hash(blocks):
    return hashlib.sha256(b''.join(blocks[x] for x in sorted(blocks))).hexdigest()


def check_evidence(pool, blocks, evidence, kernel, code_hash, policy):
    fields = ('fsid', 'device_uuid', 'size', 'md_uuid', 'lv_uuid')
    if (evidence.get('disk_safety') != policy
            or evidence.get('pool') != pool['id'] or evidence.get('kernel') != kernel
            or evidence.get('origin') != {key: pool[key] for key in fields}
            or evidence.get('original_superblocks_sha256') != headers_hash(blocks)
            or evidence.get('patch_core_sha256') != code_hash):
        raise ValidationError('Isolation evidence does not match this origin/kernel/code')
    gates = ('offline_check_passed', 'persistent_reactivation_readback',
             'original_superblocks_unchanged', 'snapshot_removed')
    if (any(evidence.get(key) is not True for key in gates)
            or evidence.get('original_writes') is not False
            or evidence.get('offline_check', {}).get('rc') != 0
            or evidence.get('write_probe', {}).get('write_fsync_read_rename_links_xattr') is not True):
        raise ValidationError('Required isolation/integrity gates did not pass')


def save_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def acceptable_resume(current, original, patched):
    # A partial bounded pwrite may leave a mix of old/new checksum bytes.
    # No byte outside the exact conversion diff may have changed.
    return len(current) == len(original) and all(
        actual in (old, new) for actual, old, new in zip(current, original, patched))


def write_mirrors(fd, blocks, root, state):
    for offset in sorted(blocks, reverse=True):
        patch = patch_superblock(blocks[offset], offset)
        if not acceptable_resume(os.pread(fd, SUPER_SIZE, offset), blocks[offset], patch):
            raise ValidationError('Origin changed before mirror write')
        _pwrite_all(fd, patch, offset); os.fsync(fd)
        if os.pread(fd, SUPER_SIZE, offset) != patch:
            raise ValidationError('Written mirror readback differs')
        if offset not in state['written']:
            state['written'].append(offset)
        view.save_state(root, state)


def reject_pending_log(blocks):
    if any(struct.unpack_from('<Q',block,0x60)[0] for block in blocks.values()):
        raise ValidationError('Pending Btrfs log: recovery/replay is outside conversion scope')


def convert(config, pool_id, evidence_file, state_directory, resume=False):
    view.require_host()
    policy = storage.disk_safety.check_config(config)
    pool = next(p for p in config['pools'] if p['id'] == pool_id)
    if pool.get('mode', 'ro') != 'ro':
        raise ValidationError('Conversion is only for an offline original RO configuration')
    root = Path(state_directory).absolute()
    if resume:
        value=root.lstat()
        if not stat.S_ISDIR(value.st_mode) or value.st_uid or value.st_mode & 0o077:
            raise ValidationError('Resume directory must be private and root-owned')
        state = storage.private_json(root/'state.json')
        if state.get('version') != 2 or state.get('disk_safety') != policy:
            raise ValidationError('Public resume requires its version 2 journal and unchanged disk policy')
        if state['pool'] != pool or state['phase'] not in ('prepared', 'writing', 'failed'):
            raise ValidationError('Resume state is not a pending conversion for this pool')
        backup_fd=os.open(root/'original-superblocks.bin',os.O_RDONLY|os.O_NOFOLLOW)
        try:
            value=os.fstat(backup_fd)
            if not stat.S_ISREG(value.st_mode) or value.st_uid or value.st_mode & 0o077:
                raise ValidationError('Unsafe superblock backup')
            data=os.read(backup_fd,4*SUPER_SIZE)
        finally:os.close(backup_fd)
        expected=[x for x in MIRRORS if x+SUPER_SIZE<=pool['size']]
        if state['mirrors']!=expected or len(data)!=len(expected)*SUPER_SIZE:
            raise ValidationError('Incomplete/invalid mirror backup')
        if hashlib.sha256(data).hexdigest() != state['original_superblocks_sha256']:
            raise ValidationError('Superblock backup changed')
        blocks = {offset: data[i*SUPER_SIZE:(i+1)*SUPER_SIZE]
                  for i,offset in enumerate(state['mirrors'])}
        # Source may contain mixed old/new mirrors; establish its topology with
        # lvs/sysfs and raw headers, never choose a stale generation.
        fd, _ = view.open_device(pool['source'])
        try:
            node = (Path('/sys/dev/block')/view.dev_id(fd)).resolve(strict=True)
            children = list((node/'slaves').iterdir())
            if len(children) != 1 or not (node/'dm').is_dir():
                raise ValidationError('Resume requires exactly one MD-backed LV')
            md = children[0].resolve(strict=True)
        except BaseException:
            os.close(fd)
            raise
    else:
        fd, node, md, blocks = storage.check_source(pool)
        try:
            storage.disk_safety.array_members(md, policy, pool['id'])
            view.guard_device(fd)
            evidence = storage.private_json(evidence_file)
            code_hash = hashlib.sha256((Path(__file__).parent/'patch_btrfs_ugos.py').read_bytes()).hexdigest()
            check_evidence(pool, blocks, evidence, view.run('uname','-r'), code_hash, policy)
            reject_pending_log(blocks)
            root.mkdir(mode=0o700, exist_ok=False)
            save_file(root/'original-superblocks.bin', b''.join(blocks[x] for x in sorted(blocks)))
            state = {'version':2, 'pool':pool, 'disk_safety':policy, 'mirrors':sorted(blocks),
                     'original_superblocks_sha256':headers_hash(blocks),
                     'phase':'prepared', 'written':[],
                     'rollback_limit':'Do not restore old headers after filesystem RW use'}
            view.save_state(root,state)
        except BaseException:
            os.close(fd)
            raise
    runtime_touched = False
    try:
        storage.disk_safety.array_members(md, policy, pool['id'])
        reject_pending_log(blocks)
        if (md/'md/uuid').read_text().strip() != pool['md_uuid']:
            raise ValidationError('Backing MD differs')
        if view.mounts(view.dev_id(fd)) or list((node/'holders').iterdir()):
            raise ValidationError('Origin mounted or held; conversion refused')
        if {x.name for x in (md/'holders').iterdir()} != {node.name}:
            raise ValidationError('Foreign MD holder; conversion refused')
        if view.run('lvs','--noheadings','-o','lv_uuid',pool['source']).strip() != pool['lv_uuid']:
            raise ValidationError('LV UUID changed')
        if any(row.split()[2]!='linear' for row in view.run('dmsetup','table',(node/'dm/name').read_text().strip()).splitlines()):
            raise ValidationError('Not a linear LV')
        if (int((md/'md/raid_disks').read_text()) != pool['members']
                or len(list((md/'slaves').iterdir())) != pool['members']):
            raise ValidationError('MD members changed')
        for name, expected in [('degraded','0'),('sync_action','idle')]:
            path = md/'md'/name
            if path.exists() and path.read_text().strip()!=expected:
                raise ValidationError('MD is not healthy/idle')
        for offset,block in blocks.items():
            info=parse_superblock(block,offset)
            if info['fsid']!=pool['fsid'] or info['device_uuid']!=pool['device_uuid']:
                raise ValidationError('Backup identity differs')
            patch=patch_superblock(block,offset)
            if not acceptable_resume(os.pread(fd,SUPER_SIZE,offset),block,patch):
                raise ValidationError('Origin changed beyond pending compatibility patch')
        if view.source_size(fd)!=pool['size']:
            raise ValidationError('Origin size differs')
        os.close(fd);fd=None
        # No persistent LV permission metadata changes, array recreation or force.
        runtime_touched = True
        node=storage.activate_rw(pool,node,md)
        storage.disk_safety.array_members(md, policy, pool['id'])
        fd=os.open(Path(pool['source']).resolve(strict=True),os.O_RDWR|os.O_NOFOLLOW|os.O_EXCL)
        if view.readonly(fd):
            raise ValidationError('Origin remained readonly')
        if view.mounts(view.dev_id(fd)) or list((node/'holders').iterdir()):
            raise ValidationError('Origin became used before patch')
        state['phase']='writing';view.save_state(root,state)
        # Secondary copies first, primary last. Each mirror is independently
        # backed up, fsynced and read back before the journal advances.
        write_mirrors(fd,blocks,root,state)
        infos, after=scan(fd)
        if any(info['ugacl'] for info in infos):
            raise ValidationError('Compatibility flag still set')
        state.update(phase='converted', converted_superblocks_sha256=headers_hash(after))
        view.save_state(root,state)
        return {'pool':pool_id,'converted':True,'backup':str(root),
                'original_data_migrated':False,'patched_bytes':len(blocks)*SUPER_SIZE,
                'filesystem_mounted':False,'restoring_old_headers_after_rw_is_unsafe':True}
    except BaseException:
        state['phase']='failed';view.save_state(root,state)
        # Contain failures at the final origin. No automatic rewind. The MD
        # runtime state may need a separately verified transition back to RO.
        if runtime_touched:
            try:view.run('blockdev','--setro',pool['source'])
            except Exception:pass
        raise
    finally:
        if fd is not None:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('--pool',required=True)
    parser.add_argument('--evidence',required=True)
    parser.add_argument('--state-directory',required=True)
    parser.add_argument('--convert-to-fnos',action='store_true')
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args()
    try:
        if not args.convert_to_fnos:
            raise ValidationError('Explicit --convert-to-fnos required; this changes original headers')
        result=convert(storage.validate_config(storage.private_json(args.config)),args.pool,
                       args.evidence,args.state_directory,args.resume)
        print(json.dumps(result));return 0
    except (ValidationError,OSError,ValueError,StopIteration) as exc:
        print(json.dumps({'error':str(exc),'recovery':'Keep backup; do not mount partial mirrors RW or restore old SB after RW use'}),file=sys.stderr)
        return 2


if __name__=='__main__':sys.exit(main())
