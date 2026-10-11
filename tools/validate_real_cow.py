#!/usr/bin/env python3
"""fnOS integration on independent COW snapshots of pinned, offline RO origins.

Writes only task-owned new COW files and new probe files inside their snapshots.
Never merges, patches or enables writes on an origin. Keeps all artifacts.
Business filenames/content/digests stay in memory and are not included in reports.
"""
import hashlib
import argparse
import json
import os
import pwd
import shutil
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import btrfs_readonly_view as view
import fnos_storage as storage
from patch_btrfs_ugos import patch_superblock, scan


def snapshot_table(size, origin, cow):
    for identity in (origin, cow):
        if not __import__('re').fullmatch(r'\d+:\d+', identity):
            raise view.ValidationError('Invalid snapshot block identity')
    if size % 512:
        raise view.ValidationError('Unaligned origin')
    return '0 %d snapshot %s %s P 128' % (size//512, origin, cow)


def release(state):
    name, device = state['name'], '/dev/mapper/'+state['name']
    if view.run('dmsetup', 'info', '-c', '--noheadings', '-o', 'uuid', name) != state['uuid']:
        raise view.ValidationError('Snapshot UUID differs; leave intact')
    if view.run('dmsetup', 'table', name) != state['table']:
        raise view.ValidationError('Snapshot table differs; leave intact')
    fd, _ = view.open_device(device)
    try:
        if view.mounts(view.dev_id(fd)):
            raise view.ValidationError('Snapshot still mounted; leave intact')
        node=(Path('/sys/dev/block')/view.dev_id(fd)).resolve()
        if list((node/'holders').iterdir()):
            raise view.ValidationError('Snapshot has holders; leave intact')
    finally: os.close(fd)
    view.run('dmsetup','remove','--noudevsync',name)
    value=json.loads(view.run('losetup','--json','--list','--output','NAME,BACK-FILE',state['loop']))['loopdevices']
    if len(value)!=1 or Path(value[0]['back-file']).resolve()!=Path(state['cow']).resolve():
        raise view.ValidationError('COW loop backing differs')
    view.run('losetup','--detach',state['loop'])


def activate(state, pool):
    state['loop']=view.run('losetup','--find','--show',state['cow'])
    origin, cow = view.open_device(pool['source'])[0], view.open_device(state['loop'])[0]
    try:
        state['table']=snapshot_table(pool['size'],view.dev_id(origin),view.dev_id(cow))
    finally: os.close(origin);os.close(cow)
    state['device']='/dev/mapper/'+state['name']
    view.save_state(Path(state['root']),state)
    view.run('dmsetup','create',state['name'],'--uuid',state['uuid'],
             '--noudevsync','--table',state['table'])
    view.run('dmsetup','mknodes',state['name'])


def share_guard(directory):
    state=storage.private_json(Path(directory)/'state.json')
    if (view.run('dmsetup','info','-c','--noheadings','-o','uuid',state['name'])!=state['uuid']
            or view.run('dmsetup','table',state['name'])!=state['table']):
        raise view.ValidationError('Foreign isolated share mapping')
    fd,_=view.open_device(state['device'])
    try:
        if scan(fd)[0][0]['fsid']!=state['fsid']:raise view.ValidationError('FSID differs')
    finally:os.close(fd)
    target = '/vol1/' + str(state['uid']) + '/UGREEN_ISOLATED'
    storage.check_mount(storage.mount_record(target),state['device'],'rw')


def check_native_layout(point, uid):
    entries = list(point.iterdir())
    if (any(p.name in {str(uid), '@team', 'thumb'} for p in entries)
            or any(p.is_symlink() or not p.is_dir() for p in entries)):
        raise view.ValidationError('原目录布局不支持自动接管，原盘未进行兼容写入')
    return len(entries)


def require_cow_space(parent):
    # Keep headroom on the state filesystem instead of consuming all free
    # system space with the independent 2 GiB test file.
    if shutil.disk_usage(parent).free < 3 * 1024**3:
        raise view.ValidationError('隔离验证需要至少 3 GiB 可用空间（含系统预留空间）')


def validate(pool, destination, config, pause_for_share=False, native_ready=False):
    policy = storage.disk_safety.check_config(config)
    if pool not in config['pools'] or pool.get('mode', 'ro') != 'ro':
        raise view.ValidationError('COW validation requires a configured readonly origin')
    uid, gid = config['uid'], config['gid']
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid <= 0:
        raise view.ValidationError('Explicit non-root probe account required')
    account = pwd.getpwuid(uid)
    if account.pw_gid != gid:
        raise view.ValidationError('Probe account primary GID differs from configuration')
    target = Path('/vol1/' + str(uid) + '/UGREEN_ISOLATED')
    fd,_,md,baseline=storage.check_source(pool)
    try:
        storage.disk_safety.array_members(md, policy, pool['id'])
        view.guard_device(fd)
    finally: os.close(fd)
    root=Path(destination).absolute();require_cow_space(root.parent)
    root.mkdir(mode=0o700,exist_ok=False)
    cow=root/'cow.raw'; cow_fd=os.open(cow,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try: os.posix_fallocate(cow_fd,0,2*1024**3);os.fsync(cow_fd)
    finally: os.close(cow_fd)
    token=uuid.uuid4().hex
    state={'root':str(root),'name':'ugacltest-'+token,'uuid':'UGACLTEST-'+token,'cow':str(cow),'fsid':pool['fsid'],
           'uid':uid,'gid':gid,'disk_safety':policy}
    report={'pool':pool['id'],'original_writes':False,'synthetic_write_bytes':16*1024**2,
            'kernel':view.run('uname','-r'),
            'origin':{key:pool[key] for key in ('fsid','device_uuid','size','md_uuid','lv_uuid')},
            'original_superblocks_sha256':hashlib.sha256(b''.join(baseline[x] for x in sorted(baseline))).hexdigest(),
            'patch_core_sha256':hashlib.sha256((Path(__file__).resolve().parents[1]/'scripts/patch_btrfs_ugos.py').read_bytes()).hexdigest()}
    parent=Path('/mnt/ugacltool-tests')
    existed=parent.exists()
    parent.mkdir(mode=0o700,exist_ok=True)
    if parent.is_symlink(): raise view.ValidationError('Unsafe test mount parent')
    if existed and (parent.stat().st_uid != uid or parent.stat().st_gid != gid):
        raise view.ValidationError('Existing test mount parent belongs to another account')
    if not existed: os.chown(parent,uid,gid)
    point=parent/token;point.mkdir(mode=0o700)
    report['disk_safety']=policy
    mounted=False
    bound=False
    try:
        activate(state,pool)
        fd=os.open(Path(state['device']).resolve(strict=True),os.O_RDWR|os.O_NOFOLLOW)
        try:
            infos,blocks=scan(fd)
            if blocks != baseline: raise view.ValidationError('COW headers differ from origin baseline')
            for offset,block in blocks.items():
                patched=patch_superblock(block,offset)
                if os.pwrite(fd,patched,offset)!=len(patched):
                    raise view.ValidationError('Incomplete COW header write')
            os.fsync(fd)
            if scan(fd)[0][0]['ugacl']: raise view.ValidationError('COW compatibility patch did not apply')
        finally: os.close(fd)
        view.run('mount','-t','btrfs','-o','rw,nodiscard,nosuid,nodev,noexec',state['device'],str(point));mounted=True
        if native_ready:
            count = check_native_layout(point, uid)
            report['native_layout_checked'] = True
            report['native_top_directory_count'] = count
        if pause_for_share:
            view.run('setfacl','-m','u:%d:rwx,d:u:%d:rwx' % (uid,uid),str(point))
        new=point/('ugacltool-write-probe-'+token);new.mkdir(mode=0o700);os.chown(new,uid,gid)
        program='''import os,json,hashlib
from pathlib import Path
p=Path(%r)
data=bytes(range(256))*65536
fd=os.open(p/'probe.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try: os.write(fd,data);os.fsync(fd)
finally:os.close(fd)
os.setxattr(p/'probe.bin','user.ugacltool',b'isolated-synthetic-only')
if (p/'renamed.bin').exists(): raise RuntimeError('Synthetic rename target already exists')
os.rename(p/'probe.bin',p/'renamed.bin')
os.link(p/'renamed.bin',p/'hardlink.bin')
os.symlink('renamed.bin',p/'symlink.bin')
fd=os.open(p,os.O_RDONLY);os.fsync(fd);os.close(fd)
if (p/'renamed.bin').read_bytes()!=data: raise RuntimeError('Synthetic readback failed')
if (p/'hardlink.bin').stat().st_ino!=(p/'renamed.bin').stat().st_ino: raise RuntimeError('Hardlink mismatch')
if (p/'symlink.bin').read_bytes()!=data: raise RuntimeError('Symlink readback failed')
print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),'write_fsync_read_rename_links_xattr':True}))
''' % str(new)
        result=json.loads(view.run('runuser','-u',account.pw_name,'--','python3','-c',program))
        view.run('btrfs','filesystem','sync',str(point))
        report['write_probe']=result
        if pause_for_share:
            target.mkdir(mode=0o700,exist_ok=False)
            os.chown(target,uid,gid)
            view.run('mount','--bind',str(point),str(target));bound=True
            (root/'share-ready.json').write_text(json.dumps({'probe_directory':new.name,'fsid':pool['fsid']}));os.chmod(root/'share-ready.json',0o600)
            print(json.dumps({'share_ready':True,'pool':pool['id']}),flush=True)
            deadline=time.monotonic()+240
            while not (root/'share-done').exists():
                if time.monotonic()>deadline:raise RuntimeError('Isolated share validation timed out')
                time.sleep(.25)
            share_guard(root)
            view.run('umount',str(target));bound=False
            view.run('btrfs','filesystem','sync',str(point))
            report['share_pause_completed']=True
        report['device_stats']=view.run('btrfs','device','stats',str(point))
        if not all(line.rsplit(None,1)[-1]=='0' for line in report['device_stats'].splitlines()):
            raise view.ValidationError('COW device error counters are nonzero')
        report['cow_status']=view.run('dmsetup','status',state['name'])
        if 'Invalid' in report['cow_status'] or 'Overflow' in report['cow_status']:
            raise RuntimeError('COW overflow/invalid')
        view.run('umount',str(point));mounted=False
        check=subprocess.run(['btrfs','check','--readonly',state['device']],capture_output=True,text=True,timeout=240)
        report['offline_check']={'rc':check.returncode,'stdout':check.stdout,'stderr':check.stderr}
        report['offline_check_passed']=check.returncode==0
        # Native-origin paths/content are not copied into the report.
        report['offline_check']['stdout']=report['offline_check']['stdout'][:12000]
        report['offline_check']['stderr']=report['offline_check']['stderr'][:12000]
        release(state)
        activate(state,pool)  # Prove persistence after completely recreating DM/loop.
        view.run('mount','-t','btrfs','-o','ro,rescue=nologreplay,nosuid,nodev,noexec',state['device'],str(point));mounted=True
        if hashlib.sha256((new/'renamed.bin').read_bytes()).hexdigest()!=result['sha256']:
            raise view.ValidationError('Persistent COW readback failed')
        if os.getxattr(new/'renamed.bin','user.ugacltool')!=b'isolated-synthetic-only':
            raise view.ValidationError('Persistent COW xattr differs')
        report['persistent_reactivation_readback']=True
        view.run('umount',str(point));mounted=False
    finally:
        if bound:
            share_guard(root)
            view.run('umount',str(target))
        if mounted:
            storage.check_mount(storage.mount_record(point),state['device'],'rw' if 'rw' in storage.mount_record(point)['options'] else 'ro')
            view.run('umount',str(point))
        release(state)
        fd,_,_,after=storage.check_source(pool)
        try:
            if after!=baseline: raise view.ValidationError('Original headers changed during isolation')
            view.guard_device(fd)
        finally:os.close(fd)
        report['original_superblocks_unchanged']=True
        report['snapshot_removed']=True
        report['cow_retained']=True
        (root/'report.json').write_text(json.dumps(report,indent=2));os.chmod(root/'report.json',0o600)
    return report


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='share-guard':
        share_guard(sys.argv[2]);sys.exit(0)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('--pool',required=True)
    parser.add_argument('--directory',required=True)
    parser.add_argument('--pause-for-share',action='store_true')
    parser.add_argument('--native-ready',action='store_true')
    args=parser.parse_args()
    view.require_host()
    cfg=storage.validate_config(storage.private_json(args.config))
    pool=next(p for p in cfg['pools'] if p['id']==args.pool)
    result=validate(pool,args.directory,cfg,args.pause_for_share,args.native_ready)
    print(json.dumps({k:v for k,v in result.items() if k not in ('offline_check','device_stats')}))
