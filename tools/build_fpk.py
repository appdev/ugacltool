#!/usr/bin/env python3
"""Build an exact source allowlist with official fnpack, no runtime state."""
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('disk_safety.py', 'patch_btrfs_ugos.py', 'btrfs_readonly_view.py',
           'convert_fnos.py', 'fnos_storage.py', 'fnos_native_adopt.py',
           'fnos_discover.py', 'fnos_oneclick.py', 'fnos_oneclick_server.py',
           'fnos_app_lifecycle.py')


def icon(size):
    """Deterministic original icon, requiring no image library or external asset."""
    def chunk(kind, data):
        return struct.pack('>I', len(data))+kind+data+struct.pack('>I', zlib.crc32(kind+data)&0xffffffff)
    rows=[]
    for y in range(size):
        row=bytearray(b'\0')
        for x in range(size):
            color=(25,43,57)
            if size*.22<=x<size*.72 and any(size*(.23+i*.21)<=y<size*(.34+i*.21) for i in range(3)):
                color=(233,243,237)
            if (x-size*.75)**2+(y-size*.75)**2<(size*.11)**2:
                color=(62,201,125)
            row.extend(color)
        rows.append(bytes(row))
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(b''.join(rows),9))+chunk(b'IEND',b'')


def copy_source(name, destination, executable=False):
    source = ROOT/name
    if (any(p.is_symlink() for p in (source,*source.parents) if p==ROOT or ROOT in p.parents)
            or not source.is_file() or source.stat().st_nlink != 1):
        raise ValueError('Package source must be an independent regular file')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(source.read_bytes())
    destination.chmod(0o755 if executable else 0o644)


def build(output, fnpack):
    output = Path(output).absolute()
    # A fresh build directory prevents accidental inclusion or replacement.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    package=output/'ugacltool';package.mkdir()
    for name in SOURCES:
        copy_source('scripts/'+name, package/'app/scripts'/name)
    copy_source('tools/validate_real_cow.py',package/'app/tools/validate_real_cow.py')
    for name in ('index.html','app.js','style.css'):
        copy_source('web/'+name,package/'app/web'/name)
    for name in ('manifest','config/privilege','config/resource'):
        copy_source('packaging/'+name,package/name)
    copy_source('packaging/ui/config',package/'app/ui/config')
    for name in ('main','install_init'):
        copy_source('packaging/cmd/'+name,package/'cmd'/name,True)
    for name in ('upgrade_init','uninstall_init'):
        copy_source('packaging/cmd/stop_for_update',package/'cmd'/name,True)
    for name in ('install_callback','upgrade_callback'):
        copy_source('packaging/cmd/secure_install',package/'cmd'/name,True)
    for name in ('uninstall_callback','config_init','config_callback'):
        target=package/'cmd'/name;target.write_text('#!/bin/sh\nexit 0\n');target.chmod(0o755)
    (package/'wizard').mkdir()
    for size, name in ((64,'ICON.PNG'),(256,'ICON_256.PNG')):
        (package/name).write_bytes(icon(size))
        (package/'app/ui/images').mkdir(exist_ok=True)
        (package/'app/ui/images'/('icon_%d.png'%size)).write_bytes(icon(size))
    subprocess.run([str(Path(fnpack).resolve(strict=True)),'build','--directory',str(package)],cwd=output,check=True)
    artifact=output/'ugacltool.fpk'
    if not artifact.is_file():raise ValueError('fnpack did not create the expected artifact')
    return {'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'path':str(artifact)}


if __name__=='__main__':
    import json
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--fnpack',type=Path,required=True)
    a=p.parse_args();print(json.dumps(build(a.output,a.fnpack)))
