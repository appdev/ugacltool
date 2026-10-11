"""New virtual-file fixtures only; reject physical NAS and existing signatures."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from patch_btrfs_ugos import MIRRORS, SUPER_SIZE, UGACL, crc32c, parse_superblock

SIZE = 4*1024**3
ROOT = Path('/root/ugacl-oneclick-fixtures')


def run(*args, input=None):
    result=subprocess.run(args,input=input,capture_output=True,text=True,timeout=180)
    if result.returncode:raise RuntimeError('Synthetic fixture command failed: '+args[0])
    return result.stdout.strip()


def inventory():
    return json.loads(run('lsblk','--json','--bytes','--paths','-o','NAME,TYPE,SIZE,SERIAL,MODEL,FSTYPE,MOUNTPOINTS'))['blockdevices']


def blank(number):
    expected='UGACLONECLICKARRAY'+str(number)
    matches=[d for d in inventory() if d.get('serial')==expected]
    if len(matches)!=1:raise RuntimeError('Synthetic serial missing or duplicate')
    d=matches[0]
    if (d['type']!='disk' or d['size']!=SIZE or d.get('model','').strip()!='UGACL-TEST-ARRAY'
            or d.get('fstype') or d.get('children') or any(d.get('mountpoints') or [])
            or list((Path('/sys/class/block')/Path(d['name']).name/'holders').iterdir())):
        raise RuntimeError('Synthetic virtual disk is not blank and unused')
    if json.loads(run('wipefs','--no-act','--json',d['name'])).get('signatures'):
        raise RuntimeError('Synthetic signature already exists')
    return d['name']


def main():
    product=Path('/sys/class/dmi/id/product_name').read_text()
    if not any(k in product for k in ('QEMU','Standard PC')):raise RuntimeError('Only a QEMU guest can create fixtures')
    disks=[d for d in inventory() if d['type']=='disk']
    expected={'UGACLTESTSYSTEM'}|{'UGACLONECLICKARRAY'+str(i) for i in range(1,7)}
    if len(disks)!=7 or {d.get('serial') for d in disks}!=expected:raise RuntimeError('Unexpected guest disk')
    system=next(d for d in disks if d['serial']=='UGACLTESTSYSTEM')
    if system['size']!=64*1024**3 or system.get('model','').strip()!='UGACL-TEST-OS':raise RuntimeError('Invalid virtual system identity')
    devices=[blank(i) for i in range(1,7)]
    ROOT.mkdir(mode=0o700,exist_ok=False)
    for i,device in enumerate(devices,1):
        if blank(i)!=device:raise RuntimeError('Virtual device changed')
        run('sfdisk',device,input='label: gpt\nstart=2048,size=129024,type=linux\nstart=131072,type=linux-raid\n')
    run('udevadm','settle')
    records=[]
    for number,(level,members) in enumerate([('linear',devices[:1]),('1',devices[1:2]),('6',devices[2:])],1):
        md='/dev/md/oneclick-lab%d'%number;vg='ug_oneclick_lab%d'%number
        run('mdadm','--create',md,'--metadata=1.2','--level='+level,'--raid-devices='+str(len(members)),
            '--force','--run','--name=oneclick-lab%d'%number,*[d+'2' for d in members])
        run('udevadm','settle');run('pvcreate',md);run('vgcreate',vg,md);run('lvcreate','-l','100%FREE','-n','volume1',vg)
        source='/dev/'+vg+'/volume1';run('mkfs.btrfs',source)
        point=ROOT/('pool%d'%number);point.mkdir();run('mount','-t','btrfs',source,str(point))
        directory=point/'original';directory.mkdir(mode=0o700)
        data=('retained synthetic array %d\n'%number).encode()*4096
        file=directory/'retained.bin'
        with file.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.chown(file,999,999);os.chmod(file,0o600);os.chown(directory,999,999)
        os.setxattr(file,'user.oneclick',b'preserve-original')
        run('btrfs','filesystem','sync',str(point));run('umount',str(point))
        fd=os.open(Path(source).resolve(strict=True),os.O_RDWR|os.O_NOFOLLOW)
        try:
            size=os.lseek(fd,0,os.SEEK_END)
            for offset in MIRRORS:
                if offset+SUPER_SIZE>size:continue
                block=os.pread(fd,SUPER_SIZE,offset);info=parse_superblock(block,offset)
                patched=bytearray(block);struct.pack_into('<Q',patched,0xBC,int(info['incompat_flags'],16)|UGACL)
                struct.pack_into('<I',patched,0,crc32c(patched[32:]))
                if os.pwrite(fd,patched,offset)!=SUPER_SIZE:raise RuntimeError('Incomplete synthetic marker write')
            os.fsync(fd)
        finally:os.close(fd)
        records.append({'vg':vg,'source':source,'sha256':hashlib.sha256(data).hexdigest(),
                        'size':len(data),'original_uid':999,'original_gid':999,'original_mode':0o600})
    with (ROOT/'baseline.json').open('x') as f:json.dump(records,f,indent=2)
    print(json.dumps({'fixtures':len(records),'physical_devices':0,'format_targets':'new virtual files only'}))


if __name__=='__main__':main()
