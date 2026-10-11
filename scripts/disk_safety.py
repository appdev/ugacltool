#!/usr/bin/env python3
"""Explicit physical identities for protected disks and each target array.

No discovery result becomes permission to write. Operators supply serial,
model and exact whole-disk bytes; system roots are independently checked.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from patch_btrfs_ugos import ValidationError


ROLES = {'system', 'old-system', 'test', 'other'}
CRITICAL_MOUNTS = {'/', '/usr', '/boot', '/boot/efi', '/home', '/vol1'}


def identity(value):
    if not isinstance(value, dict):
        raise ValidationError('Disk identity must be an object')
    for field in ('serial', 'model'):
        text = value.get(field)
        if (not isinstance(text, str) or not text or text != text.strip()
                or len(text) > 256 or any(ord(c) < 32 for c in text)
                or '<' in text or '>' in text or text.startswith('__')):
            raise ValidationError('Disk serial/model is missing or is a placeholder')
    if type(value.get('size')) is not int or value['size'] <= 0:
        raise ValidationError('Exact whole-disk size must be a positive integer')
    return {key: value[key] for key in ('serial', 'model', 'size')}


def validate_policy(policy, pool_ids=None):
    if not isinstance(policy, dict) or type(policy.get('version')) is not int or policy['version'] != 1:
        raise ValidationError('Explicit disk_safety version 1 is required')
    protected = policy.get('protected_disks')
    if not isinstance(protected, list) or not protected:
        raise ValidationError('A nonempty protected disk list is required')
    protected_ids = {}
    for disk in protected:
        value = identity(disk)
        if disk.get('role') not in ROLES or value['serial'] in protected_ids:
            raise ValidationError('Invalid or duplicate protected disk')
        protected_ids[value['serial']] = disk
    if not any(d['role'] == 'system' for d in protected):
        raise ValidationError('At least one system disk must be explicitly protected')
    pools = policy.get('pools')
    if not isinstance(pools, dict) or not pools:
        raise ValidationError('Explicit target array member identities are required')
    if pool_ids is not None and set(pools) != set(pool_ids):
        raise ValidationError('Disk policy and configured pool set differ')
    targets = set()
    for name, members in pools.items():
        if not re.fullmatch(r'pool[1-9][0-9]*', name) or not isinstance(members, list) or not members:
            raise ValidationError('Invalid or empty target member list')
        for member in members:
            value = identity(member)
            serial = value['serial']
            if serial in protected_ids or serial in targets:
                raise ValidationError('Target disk is protected or assigned more than once')
            targets.add(serial)
    if 'test_disk' in policy:
        test = identity(policy['test_disk'])
        item = protected_ids.get(test['serial'])
        if not item or item['role'] != 'test' or identity(item) != test:
            raise ValidationError('Test backing must exactly match a protected test disk')
    return policy


def policy_for(config):
    policy = validate_policy(config.get('disk_safety'), [p['id'] for p in config['pools']])
    for pool in config['pools']:
        if len(policy['pools'][pool['id']]) != pool['members']:
            raise ValidationError('Configured physical member count differs')
    return policy


def inventory():
    result = subprocess.run(['lsblk', '--json', '--bytes', '--paths', '-o',
                             'NAME,TYPE,SIZE,SERIAL,MODEL,MAJ:MIN'],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise ValidationError('Physical disk inventory failed')
    return json.loads(result.stdout)['blockdevices']


def select_disk(disks, expected):
    expected = identity(expected)
    matches = [d for d in disks if (d.get('serial') or '').strip() == expected['serial']]
    if len(matches) != 1:
        raise ValidationError('Configured physical disk serial is missing or ambiguous')
    disk = matches[0]
    if (disk.get('type') != 'disk' or type(disk.get('size')) is not int
            or disk['size'] != expected['size']
            or (disk.get('model') or '').strip() != expected['model']):
        raise ValidationError('Physical disk type/model/exact size differs')
    return disk


def block_device_id(source):
    if not source.startswith('/dev/') or '..' in Path(source).parts:
        raise ValidationError('Btrfs system source is not a device path')
    info = os.stat(source)
    if not stat.S_ISBLK(info.st_mode):
        raise ValidationError('Btrfs system source is not a block device')
    return '%d:%d' % (os.major(info.st_rdev), os.minor(info.st_rdev))


def mounted_btrfs_members(source, btrfs_sysfs):
    """Btrfs mountinfo uses an anonymous dev_t; protect every real member."""
    source_dev = block_device_id(source)
    matches = []
    for filesystem in btrfs_sysfs.iterdir():
        directory = filesystem/'devices'
        if not directory.is_dir():
            continue
        members = []
        for device in directory.iterdir():
            try:
                members.append((device/'dev').read_text().strip())
            except FileNotFoundError:
                members.append(None)
        if source_dev in members:
            matches.append(members)
    if (len(matches) != 1 or not matches[0]
            or any(not isinstance(dev, str) or not re.fullmatch(r'[1-9][0-9]*:[0-9]+', dev)
                   for dev in matches[0]) or len(set(matches[0])) != len(matches[0])):
        raise ValidationError('Complete Btrfs system members cannot be established')
    return set(matches[0])


def system_serials(disks, sysfs=Path('/sys/dev/block'), mounts=Path('/proc/self/mountinfo'),
                   btrfs_sysfs=Path('/sys/fs/btrfs')):
    """Trace root/boot/home/native space1 through partitions and DM/MD slaves."""
    roots = set()
    for line in mounts.read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise ValidationError('Malformed system mount inventory')
        if fields[4] in CRITICAL_MOUNTS:
            if '-' not in fields or len(fields) < fields.index('-') + 4:
                raise ValidationError('Malformed system mount filesystem')
            separator = fields.index('-')
            if fields[separator+1] == 'btrfs':
                # The kernel supplies mount source and sysfs membership. Never
                # assume the first source disk is the whole Btrfs filesystem.
                roots.update(mounted_btrfs_members(fields[separator+2], btrfs_sysfs))
            elif not re.fullmatch(r'[1-9][0-9]*:[0-9]+', fields[2]):
                raise ValidationError('System mount does not resolve to supported block storage')
            else:
                roots.add(fields[2])
    if not roots:
        raise ValidationError('Cannot identify system storage')
    serials, visiting = set(), set()

    def visit(node):
        node = node.resolve(strict=True)
        if (node / 'partition').exists():
            node = node.parent
        if node in visiting:
            raise ValidationError('System storage topology contains a cycle')
        visiting.add(node)
        children = list((node / 'slaves').iterdir()) if (node / 'slaves').is_dir() else []
        if children:
            for child in children:
                visit(child)
        else:
            matches = [d for d in disks if d.get('name') == '/dev/' + node.name and d.get('type') == 'disk']
            if len(matches) != 1 or not (matches[0].get('serial') or '').strip():
                raise ValidationError('System physical disk identity cannot be established')
            serials.add(matches[0]['serial'].strip())
        visiting.remove(node)

    for value in roots:
        visit(sysfs / value)
    return serials


def check_inventory(policy, disks=None, critical_serials=None):
    validate_policy(policy)
    disks = inventory() if disks is None else disks
    for disk in policy['protected_disks']:
        select_disk(disks, disk)
    for members in policy['pools'].values():
        for disk in members:
            select_disk(disks, disk)
    critical = system_serials(disks) if critical_serials is None else set(critical_serials)
    system = {d['serial'] for d in policy['protected_disks'] if d['role'] == 'system'}
    if not critical or not critical <= system:
        raise ValidationError('Current system disks are absent from explicit system protection')
    return disks


def check_config(config):
    policy = policy_for(config)
    check_inventory(policy)
    return policy


def array_members(md, policy, pool_id):
    """Bind actual MD slaves to the explicitly allowed whole physical disks."""
    disks = check_inventory(policy)
    found = []
    for member in (md / 'slaves').iterdir():
        node = member.resolve(strict=True)
        disk = node.parent if (node / 'partition').exists() else node
        matches = [d for d in disks if d.get('name') == '/dev/' + disk.name]
        if len(matches) != 1:
            raise ValidationError('Array member physical device is not unique')
        item = matches[0]
        value = identity({'serial': (item.get('serial') or '').strip(),
                          'model': (item.get('model') or '').strip(), 'size': item.get('size')})
        select_disk(disks, value)
        found.append(dict(value, partition=node.name))
    key = lambda entries: sorted((d['serial'], d['model'], d['size']) for d in entries)
    if key(found) != key(policy['pools'][pool_id]):
        raise ValidationError('Actual MD member serial/model/size differs from explicit target policy')
    return sorted(found, key=lambda d: d['serial'])
