#!/usr/bin/env python3
"""Pinned, guarded startup mounting and personal-folder binds for fnOS.

Does not format, repair, import pools into private databases, or convert origins.
Config/state are root-private. All stops use ordinary unmounts, never force/lazy.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import uuid

import btrfs_readonly_view as view
import disk_safety
from patch_btrfs_ugos import (scan, parse_superblock, MIRRORS, SUPER_SIZE,
                             ValidationError, SUPPORTED_INCOMPAT)


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid or s.st_mode & 0o077:
            raise ValidationError('Configuration/state must be private and root-owned')
        if s.st_size >= 1024*1024:
            raise ValidationError('Configuration/state is oversized')
        return json.loads(os.read(fd, 1024 * 1024))
    finally:
        os.close(fd)


def validate_config(config):
    if config.get('version') != 1 or not config.get('pools'):
        raise ValidationError('Unknown/empty configuration')
    if any(type(config.get(k)) is not int or config[k] <= 0 for k in ('uid', 'gid')):
        raise ValidationError('Explicit non-root UID and GID are required')
    ids = set()
    for pool in config['pools']:
        name = pool['id']
        if not re.fullmatch(r'pool[1-9][0-9]*', name) or name in ids:
            raise ValidationError('Invalid/duplicate pool ID')
        ids.add(name)
        for key in ('vg', 'lv'):
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', pool[key]):
                raise ValidationError('Invalid LVM identity')
        adoption = pool.get('native_adoption')
        if adoption:
            if (not isinstance(adoption, dict)
                    or not re.fullmatch(r'trim_[0-9a-f]{8}(?:_[0-9a-f]{4}){3}_[0-9a-f]{12}', pool['vg'])
                    or pool['lv'] != '0' or pool.get('mode') != 'rw'
                    or not re.fullmatch(r'ug_[A-Za-z0-9_.+-]+', adoption.get('original_vg', ''))
                    or adoption.get('original_lv') != 'volume1'
                    or adoption.get('uuid') != pool['vg'] + '-0'
                    or type(adoption.get('storage_id')) is not int
                    or adoption['storage_id'] < 2):
                raise ValidationError('Invalid pinned native adoption identity')
        elif not pool['vg'].startswith('ug_'):
            raise ValidationError('Refuse native/non-UGOS VG without adoption provenance')
        if pool['source'] != '/dev/' + pool['vg'] + '/' + pool['lv']:
            raise ValidationError('Source is not the pinned LV path')
        if pool['mount'] != '/mnt/ugreen/' + name:
            raise ValidationError('Unexpected mount path')
        for key in ('fsid', 'device_uuid', 'md_uuid'):
            if str(uuid.UUID(pool[key])) != pool[key]:
                raise ValidationError('Invalid UUID')
        if not isinstance(pool['size'], int) or pool['size'] < 128 * 1024**2:
            raise ValidationError('Invalid device size')
        if (pool.get('mode', 'ro') not in ('ro', 'rw')
                or type(pool['members']) is not int or pool['members'] < 1):
            raise ValidationError('Invalid mode/member count')
        if not re.fullmatch(r'[A-Za-z0-9]{6}(?:-[A-Za-z0-9]{4}){5}-[A-Za-z0-9]{6}', pool['lv_uuid']):
            raise ValidationError('Invalid LV UUID')
    base = config.get('personal_base')
    if base and base != '/vol1/' + str(config['uid']) + '/UGREEN':
        raise ValidationError('Unexpected personal folder')
    if config.get('personal_permissions','bind') not in ('bind','owner'):
        raise ValidationError('Unknown personal permission mapping')
    if config.get('personal_permissions')=='owner' and (config['uid']<=0 or config['gid']<=0):
        raise ValidationError('Owner mapping requires a non-root account')
    if 'disk_safety' in config:
        disk_safety.validate_policy(config['disk_safety'])
    return config


def mount_record(path):
    # Match an actual mountpoint, not findmnt's containing-filesystem fallback.
    p = Path(path)
    if p.is_symlink():
        raise ValidationError('Mountpoint must not be a symlink')
    records = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        def unescape(value):
            return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)
        if unescape(fields[4]) == str(path):
            split = fields.index('-')
            records.append({'identity': fields[2], 'root': unescape(fields[3]),
                            'options': fields[5].split(','),
                            'fstype': fields[split+1], 'source': unescape(fields[split+2]),
                            'super_options': fields[split+3].split(',')})
    if len(records) > 1:
        raise ValidationError('Stacked mounts are not supported')
    return records[0] if records else None


def check_mount(record, device, mode):
    if not record:
        raise ValidationError('Missing mount')
    identity = os.stat(device).st_rdev
    actual = os.stat(record['source']).st_rdev
    if (actual != identity or record['fstype'] != 'btrfs'
            or mode not in record['options'] or record['root'] != '/'):
        raise ValidationError('Foreign mount/device/options; leave it untouched')


def owner_mapping_args(pool, config):
    return ('bindfs','--force-user='+str(config['uid']),
            '--force-group='+str(config['gid']),'--perms=0600:u+X',
            '--create-for-user='+str(config['uid']),
            '--create-for-group='+str(config['gid']),
            '--create-with-perms=u=rwX:go=', '--chmod-ignore',
            '--chown-ignore','--chgrp-ignore','--xattr-ro',
            '-o','subtype=bindfs,default_permissions,nosuid,nodev,noexec'+
            (',ro' if pool.get('mode','ro')=='ro' else ''),
            pool['mount'],config['personal_base']+'/'+pool['id'])


def check_personal(record, pool, config, device, kind=None):
    kind=kind or config.get('personal_permissions','bind')
    mode=pool.get('mode','ro')
    if kind=='bind':
        return check_mount(record,device,mode)
    if (not record or record['fstype']!='fuse.bindfs'
            or record['source']!=pool['mount'] or record['root']!='/'
            or not {mode,'nosuid','nodev','noexec'}<=set(record['options'])
            or not {'default_permissions','allow_other','user_id=0','group_id=0'}<=set(record['super_options'])):
        raise ValidationError('Personal owner mapping differs; leave it untouched')
    actual=Path(config['personal_base']+'/'+pool['id']).stat()
    if actual.st_uid!=config['uid'] or actual.st_mode & 0o077:
        raise ValidationError('Personal mapping ownership/access differs')


def check_source(pool):
    fd, _ = view.open_device(pool['source'])
    try:
        if pool.get('mode', 'ro') == 'rw':
            # A live Btrfs commit writes its mirrors sequentially. Check each
            # checksum/identity/feature set; do not require equal generations
            # across a changing mounted RW volume.
            blocks={x:os.pread(fd,SUPER_SIZE,x) for x in MIRRORS if x+SUPER_SIZE<=view.source_size(fd)}
            infos=[parse_superblock(block,x) for x,block in blocks.items()]
        else:
            infos, blocks = scan(fd)
        info = infos[0]
        if (view.source_size(fd) != pool['size'] or
                any(item[k] != pool[k] for item in infos for k in ('fsid', 'device_uuid'))):
            raise ValidationError('Filesystem identity/size differs from pinned origin')
        flags = int(info['incompat_flags'], 16)
        if pool.get('mode', 'ro') == 'ro':
            for item in infos:
                view.validate_patch_scope(item)
        elif any(item['ugacl'] or int(item['incompat_flags'],16) & ~SUPPORTED_INCOMPAT
                 or item['num_devices']!=1 or item['super_flags'] & ~1
                 or item['compat_flags'] or item['compat_ro_flags'] & ~3
                 or item['device_total_bytes']!=pool['size']
                 or item['total_bytes']!=pool['size'] for item in infos):
            raise ValidationError('RW requires a separately validated converted origin')
        identity = view.dev_id(fd)
        node = (Path('/sys/dev/block') / identity).resolve(strict=True)
        children = list((node / 'slaves').iterdir())
        if len(children) != 1 or not (node / 'dm').is_dir():
            raise ValidationError('Expected a single MD-backed linear LV')
        md = children[0].resolve(strict=True)
        if not (md / 'md').is_dir():
            raise ValidationError('Unexpected LVM backing')
        if (md / 'md/uuid').read_text().strip() != pool['md_uuid']:
            raise ValidationError('MD UUID differs')
        count = int((md / 'md/raid_disks').read_text())
        if count != pool['members'] or len(list((md / 'slaves').iterdir())) != count:
            raise ValidationError('Incomplete/changed MD member set')
        degraded, action = md / 'md/degraded', md / 'md/sync_action'
        if ((degraded.exists() and degraded.read_text().strip() != '0') or
                (action.exists() and action.read_text().strip() != 'idle')):
            raise ValidationError('MD degraded or recovery/reshape in progress')
        name = (node / 'dm/name').read_text().strip()
        table = view.run('dmsetup', 'table', name)
        if any(row.split()[2] != 'linear' for row in table.splitlines()):
            raise ValidationError('Only linear LVM supported')
        actual = view.run('lvs', '--noheadings', '-o', 'lv_uuid', pool['source'])
        if actual.strip() != pool['lv_uuid']:
            raise ValidationError('LV UUID differs')
        return fd, node, md, blocks
    except BaseException:
        os.close(fd)
        raise


def prepare_ro(pool):
    fd, node, md, _ = check_source(pool)
    try:
        if view.mounts(view.dev_id(fd)) or list((node / 'holders').iterdir()):
            raise ValidationError('Origin in use; cannot change runtime state')
        if {x.name for x in (md / 'holders').iterdir()} != {node.name}:
            raise ValidationError('Unexpected MD holders')
        path = '/dev/' + md.name
        # Do not keep our own LV FD open across lvchange -an: that would make
        # an otherwise unused LV busy during boot's RW -> RO transition.
        os.close(fd);fd=None
        if (md / 'md/array_state').read_text().strip() != 'readonly':
            view.run('blockdev', '--setro', pool['source'])
            view.run('lvchange', '--activate', 'n', pool['vg']+'/'+pool['lv'])
            view.run('mdadm', '--readonly', path)
            override = 'activation { read_only_volume_list = ["%s/%s"] }' % (pool['vg'], pool['lv'])
            view.run('lvchange', '--activate', 'y', '--activationmode', 'complete',
                     '--config', override, pool['vg']+'/'+pool['lv'])
        view.run('blockdev', '--setro', pool['source'])
    finally:
        if fd is not None:os.close(fd)
    fd, _, _, _ = check_source(pool)
    try:
        view.guard_device(fd)
    finally:
        os.close(fd)


def activate_rw(pool, node, md):
    """Clear the command-local LVM RO override without changing VG metadata.

    The caller must close its LV FD first. Reactivation can change the DM
    minor, so establish the fresh topology before allowing any writes.
    """
    view.run('lvchange','--activate','n',pool['vg']+'/'+pool['lv'])
    if (md/'md/array_state').read_text().strip() in ('readonly','read-auto'):
        view.run('mdadm','--readwrite','/dev/'+md.name)
    view.run('lvchange','--activate','y','--activationmode','complete',
             '--config','activation { read_only_volume_list = [] }',
             pool['vg']+'/'+pool['lv'])
    view.run('blockdev','--setrw',pool['source'])
    fd,_=view.open_device(pool['source'])
    try:
        fresh=(Path('/sys/dev/block')/view.dev_id(fd)).resolve(strict=True)
        children=list((fresh/'slaves').iterdir())
        if (len(children)!=1 or children[0].resolve(strict=True)!=md
                or (md/'md/uuid').read_text().strip()!=pool['md_uuid']
                or view.run('lvs','--noheadings','-o','lv_uuid',pool['source']).strip()!=pool['lv_uuid']
                or view.source_size(fd)!=pool['size']
                or view.readonly(fd) or view.mounts(view.dev_id(fd))
                or list((fresh/'holders').iterdir())
                or {p.name for p in (md/'holders').iterdir()}!={fresh.name}):
            raise ValidationError('Reactivated origin identity/state differs')
        table=view.run('dmsetup','table',(fresh/'dm/name').read_text().strip())
        if not table.strip() or any(row.split()[2]!='linear' for row in table.splitlines()):
            raise ValidationError('Reactivated LV is not linear')
        return fresh
    finally:os.close(fd)


def prepare_rw(pool):
    fd,node,md,_=check_source(pool)
    try:
        if view.mounts(view.dev_id(fd)) or list((node/'holders').iterdir()):
            raise ValidationError('Converted origin is in use; refuse RW activation')
        if {p.name for p in (md/'holders').iterdir()}!={node.name}:
            raise ValidationError('Converted MD has foreign holders')
        os.close(fd);fd=None
        activate_rw(pool,node,md)
    finally:
        if fd is not None:os.close(fd)
    fd,_,_,_=check_source(pool)
    os.close(fd)


def unmount_personal(path, refresh_bridge):
    try:
        view.run('umount',path)
        return
    except ValidationError as exc:
        if not refresh_bridge or 'target is busy' not in str(exc):raise
    bridge=mount_record('/fs')
    if (not bridge or bridge['fstype']!='trimafs' or bridge['source']!='trimafs'
            or bridge['root']!='/'
            or set(bridge['super_options']) not in ({'rw','trimacl','ino_mode=32'}, {'rw','ino_mode=32'})):
        raise ValidationError('Unknown fnOS bridge; refuse refresh')
    # A normally unmountable trimafs can retain lower mount references with no
    # userspace FD. Rebuild only its virtual namespace; live handles cause its
    # own ordinary unmount to fail. Never force/lazy-unmount any filesystem.
    view.run('umount','/fs')
    try:
        for attempt in range(20):
            try:
                view.run('umount',path)
                return
            except ValidationError as exc:
                if 'target is busy' not in str(exc) or attempt==19:raise
                time.sleep(.1)
    finally:
        if mount_record('/fs') is not None:
            raise ValidationError('Foreign bridge appeared; do not overwrite it')
        options = ('trimacl,' if 'trimacl' in bridge['super_options'] else '') + 'ino_mode=32'
        view.run('mount','-t','trimafs','-o',options,'trimafs','/fs')


def pool_state(root, pool):
    path = root / (pool['id'] + '.json')
    if path.exists():
        value = private_json(path)
        if value.get('boot') == Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            return value
    return None


def save_pool(root, pool, state):
    target = root / (pool['id'] + '.json')
    temp = root / (pool['id'] + '-' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, target)
    fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verified_view(directory, pool):
    _, state = view.load_state(directory)
    if state['phase'] != 'active' or state['fsid'] != pool['fsid'] or state['size'] != pool['size']:
        raise ValidationError('View state differs')
    if (view.run('dmsetup', 'info', '-c', '--noheadings', '-o', 'uuid', state['name']) != state['uuid']
            or view.run('dmsetup', 'table', state['name']) != state['table']):
        raise ValidationError('View ownership/table differs')
    fd, _ = view.open_device(state['device'])
    try:
        if not view.readonly(fd) or scan(fd)[0][0]['fsid'] != pool['fsid']:
            raise ValidationError('View is not pinned readonly filesystem')
    finally:
        os.close(fd)
    return state


def ensure_array(root, pool):
    matches=[p.parent.parent for p in Path('/sys/block').glob('md*/md/uuid')
             if p.read_text().strip()==pool['md_uuid']]
    if len(matches)>1:
        raise ValidationError('Duplicate pinned MD UUID')
    if matches:
        return
    target='/dev/md/ugacltool-'+pool['id']
    if Path(target).exists():
        raise ValidationError('Assembly target is already occupied')
    value=pool['md_uuid'].replace('-','')
    md_uuid=':'.join(value[i:i+8] for i in range(0,32,8))
    config=root/('assemble-'+uuid.uuid4().hex+'.conf')
    text='DEVICE partitions\nAUTO -all\nHOMEHOST <ignore>\nARRAY %s UUID=%s\n' % (target,md_uuid)
    fd=os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(text);stream.flush();os.fsync(stream.fileno())
    # Existing metadata only, exact UUID, no force/run/create/degraded override.
    # Subsequent check_source requires the full healthy member set before RW.
    view.run('mdadm','--assemble','--scan','--readonly','--config',str(config))


def start_pool(root, pool, config):
    policy = disk_safety.check_config(config)
    mode = pool.get('mode', 'ro')
    ensure_array(root,pool)
    if not Path(pool['source']).exists():
        # A failed offline activation may leave an otherwise valid LV inactive.
        # Recover only the pinned LV, then validate the entire backing topology.
        target=pool['vg']+'/'+pool['lv']
        if view.run('lvs','--noheadings','-o','lv_uuid',target).strip()!=pool['lv_uuid']:
            raise ValidationError('Inactive LV UUID differs')
        # Activate readonly first, even for a future RW mount. Physical member
        # checks must precede any transition into writable operation.
        override='activation { read_only_volume_list = ["%s"] }' % target
        view.run('lvchange','--activate','y','--activationmode','complete',
                 '--config',override,target)
    fd, _, md, _ = check_source(pool)
    try:
        disk_safety.array_members(md, policy, pool['id'])
    finally:
        os.close(fd)
    previous = pool_state(root, pool)
    record = mount_record(pool['mount'])
    directory = None
    if mode == 'ro' and record:
        fd, _, _, _ = check_source(pool)
        try:
            if not view.readonly(fd):
                raise ValidationError('Readonly mount requires a readonly origin')
        finally:
            os.close(fd)
    if mode == 'ro':
        if record:
            directory = (previous or {}).get('view_directory') or pool.get('readonly_state')
            if not directory:
                raise ValidationError('Mounted view has no owned state')
            state = verified_view(directory, pool)
        else:
            if previous and previous.get('view_directory'):
                directory = previous['view_directory']
                state = verified_view(directory, pool)
            else:
                prepare_ro(pool)
                directory = str(root / (pool['id']+'-view-'+uuid.uuid4().hex))
                state = view.create(pool['source'], directory, True)
        device = state['device']
    else:
        device = pool['source']
        if pool.get('native_adoption'):
            native = '/vol' + str(pool['native_adoption']['storage_id'])
            deadline = time.monotonic() + 45
            while not mount_record(native) and time.monotonic() < deadline:
                time.sleep(.5)
            check_mount(mount_record(native), device, 'rw')
        elif not record:
            prepare_rw(pool)
        fd, _, _, _ = check_source(pool)
        try:
            if view.readonly(fd):
                raise ValidationError('RW origin must be prepared by validated conversion')
        finally:
            os.close(fd)
    state = {'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'device': device, 'mode': mode, 'view_directory': directory,
             'personal_kind':config.get('personal_permissions','bind')}
    save_pool(root, pool, state)  # Keep ownership before any mount/bind failure.
    if record:
        check_mount(record, device, mode)
    else:
        point = Path(pool['mount'])
        point.mkdir(mode=0o700, parents=True, exist_ok=True)
        if point.is_symlink() or any(point.iterdir()):
            raise ValidationError('Mountpoint must be an empty real directory')
        options = ('ro,rescue=nologreplay' if mode == 'ro' else 'rw')+',nosuid,nodev,noexec'
        if pool.get('native_adoption'):
            view.run('mount', '--bind', native, str(point))
        else:
            view.run('mount', '-t', 'btrfs', '-o', options, device, str(point))
        check_mount(mount_record(point), device, mode)
    if config.get('personal_base'):
        base = Path(config['personal_base'])
        existed=base.exists()
        base.mkdir(mode=0o700, exist_ok=True)
        if base.is_symlink() or base.parent.stat().st_uid != config['uid']:
            raise ValidationError('Personal folder ownership differs')
        if existed and base.stat().st_uid!=config['uid']:
            raise ValidationError('Existing personal entry belongs to another owner')
        if not existed:os.chown(base, config['uid'], config['gid'])
        target = base / pool['id']
        target.mkdir(mode=0o700, exist_ok=True)
        bound = mount_record(target)
        if bound:
            check_personal(bound,pool,config,device)
        else:
            if target.is_symlink() or any(target.iterdir()):
                raise ValidationError('Bind target is not an empty real directory')
            if config.get('personal_permissions')=='owner':
                view.run(*owner_mapping_args(pool,config))
            else:
                view.run('mount', '--bind', pool['mount'], str(target))
            check_personal(mount_record(target),pool,config,device)
    if pool.get('native_adoption'):
        native_personal(pool, config)
    return {'pool': pool['id'], 'mode': mode, 'mounted': True}


def native_personal(pool, config, stop=False):
    """Expose original top-level directories in native personal storage.

    Individual ordinary bind mounts avoid a recursive alias of the volume
    root. Entries retain their original metadata; no file data is copied.
    No names or contents are written to state/logs. Non-directories remain
    available through the existing complete compatibility view.
    """
    volume = Path('/vol' + str(pool['native_adoption']['storage_id']))
    check_mount(mount_record(volume), pool['source'], 'rw')
    home = volume / str(config['uid'])
    if not home.is_dir() or home.is_symlink() or home.stat().st_uid != config['uid']:
        raise ValidationError('Native personal storage must be created by fnOS first')
    target = home / 'UGREEN'
    if not target.exists() and not stop:
        target.mkdir(mode=0o700)
        os.chown(target, config['uid'], config['gid'])
    if not target.exists():
        return
    if target.is_symlink() or not target.is_dir() or target.stat().st_uid != config['uid']:
        raise ValidationError('Native personal alias target ownership differs')
    ignored = {str(config['uid']), 'thumb', '@team'}
    count = 0
    for source in volume.iterdir():
        if source.name in ignored or source.is_symlink() or not source.is_dir():
            continue
        alias = target / source.name
        record = mount_record(alias)
        if record:
            if (record['fstype'] != 'btrfs' or record['identity'] != mount_record(volume)['identity']
                    or os.stat(record['source']).st_rdev != os.stat(pool['source']).st_rdev
                    or record['root'] != '/' + source.name or 'rw' not in record['options']):
                raise ValidationError('Native personal entry has a foreign mount')
            if stop:
                unmount_personal(str(alias), config.get('refresh_bridge_on_stop', False))
        elif not stop:
            alias.mkdir(mode=0o700, exist_ok=True)
            if alias.is_symlink() or any(alias.iterdir()):
                raise ValidationError('Native personal bind target must be empty')
            view.run('mount', '--bind', str(source), str(alias))
            check = mount_record(alias)
            if not check or check['identity'] != mount_record(volume)['identity'] or check['root'] != '/' + source.name:
                raise ValidationError('Native personal bind identity differs')
        count += 1
    return count


def stop_pool(root, pool, config):
    state = pool_state(root, pool)
    if not state or state.get('phase') == 'stopped':
        if mount_record(pool['mount']):
            raise ValidationError('No current-boot ownership state; refuse stop')
        return
    device = state['device']
    if pool.get('native_adoption'):
        native_personal(pool, config, stop=True)
    if state['mode'] == 'ro':
        verified_view(state['view_directory'], pool)
    else:
        fd, _, _, _ = check_source(pool); os.close(fd)
    paths = [pool['mount']]
    if config.get('personal_base'):
        paths.insert(0, config['personal_base']+'/'+pool['id'])
    for path in paths:
        record = mount_record(path)
        if record:
            if config.get('personal_base') and path.startswith(config['personal_base']+'/'):
                check_personal(record,pool,config,device,state.get('personal_kind','bind'))
                unmount_personal(path,config.get('refresh_bridge_on_stop',False))
            else:
                check_mount(record, device, state['mode'])
                view.run('umount', path)
    if state['mode'] == 'ro':
        view.remove(state['view_directory'])
    save_pool(root, pool, {'boot': state['boot'], 'phase': 'stopped'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/ugacltool/storage.json')
    parser.add_argument('--state', default='/var/lib/ugacltool')
    parser.add_argument('command', choices=('start', 'stop', 'status', 'share-guard'))
    parser.add_argument('pool', nargs='?')
    args = parser.parse_args()
    try:
        view.require_host()
        config = validate_config(private_json(args.config))
        if args.command != 'stop':
            # Validate before creating state or assembling/activating anything.
            disk_safety.check_config(config)
        root = Path(args.state)
        root.mkdir(mode=0o700, exist_ok=True)
        if root.is_symlink() or root.stat().st_uid or root.stat().st_mode & 0o077:
            raise ValidationError('Unsafe state directory')
        fd = os.open(root/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = []
            for pool in config['pools']:
                if args.pool and pool['id'] != args.pool:
                    continue
                if args.command == 'start':
                    result.append(start_pool(root, pool, config))
                elif args.command == 'stop':
                    stop_pool(root, pool, config)
                else:
                    state = pool_state(root, pool)
                    if not state or not state.get('device'):
                        raise ValidationError('Pool is not started')
                    if state['mode'] == 'ro':
                        verified_view(state['view_directory'], pool)
                    fd2, _, md, _ = check_source(pool)
                    try:
                        disk_safety.array_members(md, disk_safety.policy_for(config), pool['id'])
                    finally:
                        os.close(fd2)
                    record = mount_record(pool['mount'])
                    if not record:
                        raise ValidationError('Missing pool mount')
                    check_mount(record, state['device'], state['mode'])
                    if config.get('personal_base'):
                        check_personal(mount_record(config['personal_base']+'/'+pool['id']),
                                       pool,config,state['device'],state.get('personal_kind','bind'))
                    result.append({'pool': pool['id'], 'mode': state['mode'], 'mounted': True})
            if not result and args.command not in ('stop',):
                raise ValidationError('Unknown pool')
            print(json.dumps(result))
        finally:
            os.close(fd)
        return 0
    except (ValidationError, OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
