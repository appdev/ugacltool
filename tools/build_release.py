#!/usr/bin/env python3
"""Build only the public source allowlist; never include runtime config/logs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


ROOT = Path(__file__).resolve().parents[1]
FILES = (
    '.gitignore',
    'README.md',
    'scripts/patch_btrfs_ugos.py',
    'scripts/btrfs_readonly_view.py',
    'scripts/convert_fnos.py',
    'scripts/fnos_storage.py',
    'scripts/fnos_native_adopt.py',
    'scripts/fnos_native_lab.py',
    'scripts/disk_safety.py',
    'tools/check_config.py',
    'tools/validate_real_cow.py',
    'tools/build_release.py',
    'tests/test_btrfs_ugos.py',
    'tests/test_policy_assessment.py',
    'tests/test_readonly_view.py',
    'tests/test_fnos_conversion.py',
    'tests/test_fnos_storage.py',
    'tests/test_fnos_native_adopt.py',
    'tests/test_native_lab.py',
    'tests/test_real_cow_guards.py',
    'tests/test_disk_safety.py',
    'examples/storage.json.example',
    'examples/ugacltool-storage.service.example',
    'scripts/fnos_discover.py',
    'scripts/fnos_oneclick.py',
    'scripts/fnos_oneclick_server.py',
    'scripts/fnos_app_lifecycle.py',
    'tools/build_fpk.py',
    'tests/test_oneclick.py',
    'tests/create_oneclick_fixtures.py',
    'web/index.html',
    'web/app.js',
    'web/style.css',
    'packaging/manifest',
    'packaging/config/privilege',
    'packaging/config/resource',
    'packaging/ui/config',
    'packaging/cmd/main',
    'packaging/cmd/install_init',
    'packaging/cmd/stop_for_update',
    'packaging/cmd/secure_install',
)


def check_template(config):
    policy = config['disk_safety']
    entries = policy['protected_disks'] + [policy['test_disk']]
    entries += [d for members in policy['pools'].values() for d in members]
    for disk in entries:
        if disk['size'] != 0 or any(not re.fullmatch(r'__[A-Z0-9_]+__', disk[k]) for k in ('serial', 'model')):
            raise ValueError('Refuse to publish a filled hardware-identity template')
    for pool in config['pools']:
        if pool['size'] != 0 or any(not re.fullmatch(r'__[A-Z0-9_]+__', pool[k])
                                  for k in ('fsid', 'device_uuid', 'md_uuid', 'lv_uuid')):
            raise ValueError('Refuse to publish a filled source-identity template')
        if (pool['vg'] != 'ug_EXAMPLE_' + pool['id'] or pool['lv'] != 'volume1'
                or pool['source'] != '/dev/' + pool['vg'] + '/volume1'):
            raise ValueError('Refuse to publish a filled source-name template')


def build(output):
    contents = {}
    for name in FILES:
        path = ROOT / name
        if any(p.is_symlink() for p in (path, *path.parents) if p == ROOT or ROOT in p.parents):
            raise ValueError('Refuse symlink in public source tree')
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('Public source must be an independent regular file')
        contents[name] = path.read_bytes()
    check_template(json.loads(contents['examples/storage.json.example']))
    manifest = {'format': 1, 'sha256': {name: hashlib.sha256(data).hexdigest()
                                      for name, data in contents.items()}}
    contents['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves a previous release or unrelated file.
    with output.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in contents.items():
                archive.writestr('ugacltool/' + name, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != {'ugacltool/' + n for n in contents}:
            raise ValueError('Release archive readback failed')
        for name, data in contents.items():
            if archive.read('ugacltool/' + name) != data:
                raise ValueError('Release archive content differs')
    return {'file_count': len(contents), 'archive_sha256': hashlib.sha256(output.read_bytes()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output)))
