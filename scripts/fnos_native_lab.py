#!/usr/bin/env python3
"""Read-only physical-device guards for an isolated fnOS native-adoption lab.

Never formats, partitions, mounts or changes permissions on a physical device.
Only newly created file overlays are writable. No commit/merge operation exists.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import struct
import subprocess

import disk_safety
import fnos_storage as storage


class LabError(RuntimeError):
    pass


BLKGETSIZE64 = 0x80081272


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        # Never include arbitrary device contents or customer paths in errors.
        raise LabError('Diagnostic command failed: ' + args[0])
    return result.stdout


def disk_inventory():
    return json.loads(command('lsblk', '--bytes', '--json', '--paths',
                             '-o', 'NAME,TYPE,SIZE,SERIAL,MODEL,MAJ:MIN,MOUNTPOINTS'))['blockdevices']


def select_disk(disks, expected):
    try:
        expected = disk_safety.identity(expected)
    except storage.ValidationError as exc:
        raise LabError(str(exc)) from exc
    matches = [d for d in disks if (d.get('serial') or '').strip() == expected['serial']]
    if len(matches) != 1:
        raise LabError('Target serial missing or ambiguous')
    disk = matches[0]
    if (disk.get('type') != 'disk' or disk.get('size') != expected['size']
            or (disk.get('model') or '').strip() != expected['model']):
        raise LabError('Target disk type, model or exact size mismatch')
    return disk


def descend(disk):
    yield disk
    for child in disk.get('children', []):
        yield from descend(child)


def check_unused(disk, sysfs=Path('/sys/dev/block')):
    for node in descend(disk):
        if any(node.get('mountpoints') or []):
            raise LabError('Target disk or descendant is mounted')
        if node is not disk and node.get('type') != 'part':
            raise LabError('Target has a mapped/array descendant')
        root = (sysfs / node['maj:min']).resolve(strict=True)
        if list((root / 'holders').iterdir()):
            raise LabError('Target disk or partition has holders')


def pin_disk(expected):
    disk = select_disk(disk_inventory(), expected)
    check_unused(disk)
    # Exclusive read-only open also rejects an already claimed block device.
    path = Path(disk['name']).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_EXCL | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISBLK(info.st_mode):
            raise LabError('Pinned source is not a block device')
        identity = '%d:%d' % (os.major(info.st_rdev), os.minor(info.st_rdev))
        size = struct.unpack('Q', fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0]
        if identity != disk['maj:min'] or size != expected['size']:
            raise LabError('Device identity changed during open')
        # Re-query serial/size after opening; no device-name-only assumptions.
        again = select_disk(disk_inventory(), expected)
        check_unused(again)
        if again['maj:min'] != identity:
            raise LabError('Target device changed during verification')
        return fd, dict(expected, device=str(path), identity=identity)
    except BaseException:
        os.close(fd)
        raise


def recheck(fd, pinned):
    disk = select_disk(disk_inventory(), pinned)
    check_unused(disk)
    info = os.fstat(fd)
    identity = '%d:%d' % (os.major(info.st_rdev), os.minor(info.st_rdev))
    size = struct.unpack('Q', fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0]
    if disk['maj:min'] != pinned['identity'] or identity != pinned['identity'] or size != pinned['size']:
        raise LabError('Pinned device identity changed')
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise LabError('Physical backing descriptor is not read-only')


def backing_nodes(fd, overlay):
    """Use QEMU fdset1 with -add-fd, never reopen an nvme path in QEMU."""
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise LabError('Refuse a writable physical descriptor')
    if not Path(overlay).is_file() or Path(overlay).is_symlink():
        raise LabError('Overlay must be an independent regular file')
    return [
        {'driver': 'host_device', 'node-name': 'ssd-physical',
         'filename': '/dev/fdset/1', 'read-only': True},
        {'driver': 'raw', 'node-name': 'ssd-readonly',
         'file': 'ssd-physical', 'read-only': True},
        {'driver': 'file', 'node-name': 'ssd-overlay-file',
         'filename': str(Path(overlay).resolve()), 'read-only': False},
        {'driver': 'qcow2', 'node-name': 'ssd-overlay',
         'file': 'ssd-overlay-file', 'backing': 'ssd-readonly'}]


def create_overlay(directory, expected):
    directory = Path(directory).absolute()
    if directory.is_symlink() or not directory.is_dir():
        raise LabError('Expected an existing dedicated lab directory')
    overlay = directory / 'ssd-overlay.qcow2'
    if overlay.exists() or overlay.is_symlink():
        raise LabError('Overlay already exists; preserve previous run')
    fd, pinned = pin_disk(expected)
    try:
        recheck(fd, pinned)
        # New empty QCOW2 has no embedded physical path. Explicit block nodes
        # supply a pinned read-only backing only while the isolated guest runs.
        command('qemu-img', 'create', '-f', 'qcow2', str(overlay), str(pinned['size']))
        overlay.chmod(0o600)
        recheck(fd, pinned)
        manifest = dict(pinned, overlay=str(overlay), physical_writes=False,
                        passthrough=False, state='overlay_prepared')
        manifest_path = directory / 'ssd-identity.json'
        with manifest_path.open('x') as dest:
            os.chmod(manifest_path, 0o600)
            json.dump(manifest, dest, indent=2)
            dest.flush()
            os.fsync(dest.fileno())
        return manifest
    finally:
        os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True,
                        help='Root-private storage configuration with explicit disk_safety.test_disk')
    parser.add_argument('--prepare-overlay', type=Path)
    args = parser.parse_args()
    config = storage.validate_config(storage.private_json(args.config))
    policy = disk_safety.check_config(config)
    if 'test_disk' not in policy:
        raise LabError('An explicitly protected test_disk is required')
    expected = policy['test_disk']
    if args.prepare_overlay:
        result = create_overlay(args.prepare_overlay, expected)
    else:
        fd, result = pin_disk(expected)
        os.close(fd)
    print(json.dumps(result, indent=2))
