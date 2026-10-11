"""Durable one-array adoption orchestration; no formatting or data migration."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import threading
import uuid

import disk_safety
import fnos_discover as discovery
import fnos_native_adopt as adoption
import fnos_storage as storage
from patch_btrfs_ugos import ValidationError


STAGES = ('prepare', 'cow', 'convert', 'mount', 'native_prepare', 'release',
          'native_apply', 'maintain', 'verify')
LABELS = {'prepare': '核验并只读打开阵列', 'cow': '隔离验证原数据与读写',
          'convert': '转换文件系统兼容标记', 'mount': '核验转换后的原卷',
          'native_prepare': '备份原生接管信息', 'release': '释放临时访问',
          'native_apply': '登记飞牛原生存储空间', 'maintain': '配置开机维护',
          'verify': '验证原生读写'}


def private_directory(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValidationError('Unsafe state path')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValidationError('State directory must be private and owned by the runtime user')
    return path


def read_owned(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 2**20:
            raise ValidationError('Unsafe job record')
        return json.loads(os.read(fd, 2**20))
    finally:
        os.close(fd)


class Jobs:
    def __init__(self, root, adapter):
        self.root = private_directory(root)
        self.adapter = adapter
        self.lock = threading.Lock()

    def path(self, job_id):
        if not isinstance(job_id, str) or not re.fullmatch('[0-9a-f]{32}', job_id):
            raise ValidationError('Invalid job ID')
        path = self.root / job_id
        if path.is_symlink():
            raise ValidationError('Unsafe job directory')
        return path

    def read(self, job_id, uid):
        record = read_owned(self.path(job_id) / 'job.json')
        if record.get('id') != job_id or record.get('owner_uid') != uid:
            raise ValidationError('Job belongs to another account')
        return record

    def list(self, uid):
        result = []
        for path in sorted(self.root.iterdir()):
            if re.fullmatch('[0-9a-f]{32}', path.name) and path.is_dir() and not path.is_symlink():
                record = read_owned(path / 'job.json')
                if record.get('owner_uid') == uid:
                    result.append(self.public(record))
        return result

    @staticmethod
    def public(record):
        return {k: record[k] for k in ('id', 'state', 'stage', 'completed', 'message', 'storage_id') if k in record}

    def create(self, selected, uid):
        if type(uid) is not int or uid <= 0 or not selected.get('eligible'):
            raise ValidationError('管理员与可接管阵列必须明确')
        self.adapter.validate_selection(selected)
        job_id = uuid.uuid4().hex
        path = self.path(job_id)
        path.mkdir(mode=0o700)
        record = {'version': 1, 'id': job_id, 'owner_uid': uid, 'selection': copy.deepcopy(selected),
                  'implementation': self.adapter.identity(),
                  'state': 'queued', 'stage': None, 'completed': [], 'message': '等待核验'}
        adoption.save(path / 'job.json', record)
        return record

    def run(self, job_id, uid):
        if not self.lock.acquire(blocking=False):
            raise ValidationError('已有接管任务运行，请等待它完成')
        lock_fd = None
        try:
            lock_fd = os.open(self.root / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = self.read(job_id, uid)
            if record['state'] == 'done':
                return record
            if record.get('implementation') != self.adapter.identity():
                raise ValidationError('恢复任务必须使用原来验证的代码版本')
            if record.get('version') != 1 or any(s not in STAGES for s in record['completed']):
                raise ValidationError('Job record is not recognized')
            if record['completed'] != list(STAGES[:len(record['completed'])]):
                raise ValidationError('Job stages were changed or skipped')
            path = self.path(job_id)
            for stage in STAGES[len(record['completed']):]:
                record.update(state='running', stage=stage, message=LABELS[stage])
                adoption.save(path / 'job.json', record)  # Intent before operation.
                try:
                    self.adapter.execute(stage, path, record)
                except Exception as exc:
                    # Commands can include private paths. Never expose raw stderr.
                    record.update(state='attention', message='此阶段已停止，保留记录，可按原任务检查并继续',
                                  error_type=type(exc).__name__)
                    adoption.save(path / 'job.json', record)
                    raise
                record['completed'].append(stage)
                adoption.save(path / 'job.json', record)
            record.update(state='done', message='已成为飞牛原生存储空间')
            adoption.save(path / 'job.json', record)
            return record
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            self.lock.release()


class LinuxAdapter:
    """Real actions are separate from UI and unavailable to the demo adapter."""
    def __init__(self):
        self.loaded_identity = self.source_identity()

    @staticmethod
    def source_identity():
        root = Path(__file__).resolve().parents[1]
        names = ['scripts/' + n for n in ('fnos_storage.py', 'fnos_native_adopt.py',
            'disk_safety.py', 'patch_btrfs_ugos.py', 'btrfs_readonly_view.py',
            'convert_fnos.py', 'fnos_oneclick.py', 'fnos_discover.py')]
        names.append('tools/validate_real_cow.py')
        return {n: hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names}

    def identity(self):
        if self.source_identity() != self.loaded_identity:
            raise ValidationError('Running implementation changed; restart before continuing')
        return copy.deepcopy(self.loaded_identity)

    def validate_selection(self, selected):
        storage.view.require_host()
        adoption.check_native_version()
        discovery.recheck_selection(selected)

    def execute(self, stage, path, record):
        self.identity()
        method = getattr(self, 'stage_' + stage)
        if stage == 'prepare':
            return method(path, record)
        config = storage.validate_config(storage.private_json(path / 'config.json'))
        self.check_scope(config, record)
        disk_safety.check_config(config)
        adoption.check_native_version()
        return method(path, record, config)

    @staticmethod
    def check_scope(config, record):
        if len(config['pools']) != 1 or config['uid'] != record['owner_uid']:
            raise ValidationError('Job account or pool scope differs')
        pool = config['pools'][0]
        policy = config['disk_safety']
        members = [{k:m[k] for k in ('serial','model','size')} for m in record['selection']['members']]
        if (pool['md_uuid'] != record['selection']['md_uuid']
                or policy['protected_disks'] != record['selection']['protected']
                or policy['pools'] != {pool['id']:members}):
            raise ValidationError('Job configuration differs from selected physical identities')

    def stage_prepare(self, path, record):
        existing = path / 'config.json'
        if existing.exists():
            cfg = storage.validate_config(storage.private_json(existing))
            self.check_scope(cfg, record)
            disk_safety.check_config(cfg)
            adoption.check_native_version()
            return
        self.validate_selection(record['selection'])
        selected = record['selection']
        md_nodes = [p.parent.parent for p in Path('/sys/block').glob('md*/md/uuid')
                    if discovery.canonical_md(p.read_text().strip()) == selected['md_uuid']]
        if len(md_nodes) > 1:
            raise ValidationError('Multiple MD devices match the selection')
        if not md_nodes:
            target = '/dev/md/ugacl-oneclick-' + record['id']
            if Path(target).exists():
                raise ValidationError('Assembly destination already exists')
            storage.view.run('mdadm', '--assemble', '--readonly', target,
                             *[m['partition'] for m in selected['members']])
            storage.view.run('udevadm', 'settle')
            md_nodes = [p.parent.parent for p in Path('/sys/block').glob('md*/md/uuid')
                        if discovery.canonical_md(p.read_text().strip()) == selected['md_uuid']]
        if len(md_nodes) != 1:
            raise ValidationError('Readonly MD assembly is incomplete')
        md = md_nodes[0]; device = '/dev/' + md.name
        pvs = json.loads(storage.view.run('pvs', '--reportformat', 'json', '-o', 'pv_name,vg_name'))['report'][0]['pv']
        same = [p for p in pvs if os.stat(p['pv_name'].strip()).st_rdev == os.stat(device).st_rdev]
        if len(same) != 1 or not re.fullmatch(r'ug_[A-Za-z0-9_.+-]+', same[0]['vg_name'].strip()):
            raise ValidationError('Selected array is not an original UGREEN VG')
        vg = same[0]['vg_name'].strip()
        if len([p for p in pvs if p['vg_name'].strip() == vg]) != 1:
            raise ValidationError('Extra PVs in the selected VG')
        lvs = json.loads(storage.view.run('lvs', '--reportformat', 'json', '--units', 'b', '--nosuffix',
            '-o', 'vg_name,lv_name,lv_uuid,lv_size,segtype', vg))['report'][0]['lv']
        if len(lvs) != 1 or lvs[0]['lv_name'].strip() != 'volume1' or lvs[0]['segtype'].strip() != 'linear':
            raise ValidationError('Expected one original linear volume1 LV')
        lv = lvs[0]; source = '/dev/' + vg + '/volume1'
        if not Path(source).exists():
            override = 'activation { read_only_volume_list = ["%s/volume1"] }' % vg
            storage.view.run('lvchange', '--activate', 'y', '--activationmode', 'complete', '--config', override, vg+'/volume1')
        account = pwd.getpwuid(record['owner_uid'])
        pool_id = self.pool_id(path.parent)
        fd, _ = storage.view.open_device(source)
        try:
            infos, _ = storage.view.scan(fd)
            info = infos[0]
        finally:
            os.close(fd)
        pool = {'id': pool_id, 'vg': vg, 'lv': 'volume1', 'source': source,
                'mount': '/mnt/ugreen/' + pool_id, 'fsid': info['fsid'], 'device_uuid': info['device_uuid'],
                'md_uuid': selected['md_uuid'], 'lv_uuid': lv['lv_uuid'].strip(),
                'size': int(lv['lv_size']), 'members': len(selected['members']), 'mode': 'ro'}
        policy = {'version': 1, 'protected_disks': selected['protected'],
                  'pools': {pool_id: [{k: m[k] for k in ('serial', 'model', 'size')} for m in selected['members']]}}
        cfg = {'version': 1, 'uid': account.pw_uid, 'gid': account.pw_gid, 'pools': [pool], 'disk_safety': policy}
        storage.validate_config(cfg); disk_safety.check_config(cfg)
        disk_safety.array_members(md, policy, pool_id)
        storage.prepare_ro(pool)
        adoption.save(existing, cfg)

    @staticmethod
    def pool_id(jobs):
        occupied = set()
        for path in jobs.glob('*/config.json'):
            occupied.update(p['id'] for p in storage.private_json(path)['pools'])
        for i in range(1, 10000):
            name = 'pool%d' % i
            if name not in occupied and not Path('/mnt/ugreen', name).exists():
                return name
        raise ValidationError('No free compatibility namespace')

    def stage_cow(self, path, record, cfg):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
        import validate_real_cow
        destination = path / 'cow'
        if (destination / 'report.json').exists():
            report = storage.private_json(destination / 'report.json')
        else:
            if destination.exists():
                raise ValidationError('Interrupted COW requires inspection before retry')
            report = validate_real_cow.validate(cfg['pools'][0], destination, cfg, native_ready=True)
        if report.get('native_layout_checked') is not True:
            raise ValidationError('Native layout isolation proof is missing')

    def stage_convert(self, path, record, cfg):
        import convert_fnos
        conversion = path / 'conversion'
        state_path = conversion / 'state.json'
        if state_path.exists():
            state = storage.private_json(state_path)
            if state.get('disk_safety') != cfg['disk_safety'] or state.get('pool') != cfg['pools'][0]:
                raise ValidationError('Conversion journal differs from frozen job configuration')
            if state.get('phase') == 'converted':
                return
        convert_fnos.convert(cfg, cfg['pools'][0]['id'], path/'cow/report.json', conversion, resume=state_path.exists())

    def stage_mount(self, path, record, cfg):
        cfg = copy.deepcopy(cfg); cfg['pools'][0]['mode'] = 'rw'
        adoption.save(path/'config.json', cfg)
        storage.start_pool(private_directory(path/'mount-state'), cfg['pools'][0], cfg)

    def stage_native_prepare(self, path, record, cfg):
        journal = path/'native/journal.json'
        if journal.exists():
            value = adoption.validate_journal(storage.private_json(journal))
            if not value.get('backups_ready'):
                raise ValidationError('Interrupted native metadata backup requires inspection')
            return
        adoption.prepare(path/'config.json', path/'native')

    def stage_release(self, path, record, cfg):
        pool = cfg['pools'][0]
        if storage.mount_record(pool['mount']):
            storage.stop_pool(path/'mount-state', pool, cfg)
        fd, _, _, _ = storage.check_source(pool)
        try:
            if storage.view.mounts(storage.view.dev_id(fd)):
                raise ValidationError('Source remains mounted')
        finally:
            os.close(fd)

    def stage_native_apply(self, path, record, cfg):
        journal = adoption.apply(path/'native')
        record['storage_id'] = journal['pools'][0]['storage_id']

    def stage_maintain(self, path, record, cfg):
        if not cfg['pools'][0].get('native_adoption'):
            raise ValidationError('Native identity must be present before service installation')
        digest = discovery.fingerprint(record['implementation'])
        code = private_directory('/usr/local/lib/ugacltool-oneclick') / digest
        private_directory(code)
        source = Path(__file__).resolve().parent
        for name in ('fnos_storage.py', 'disk_safety.py', 'btrfs_readonly_view.py', 'patch_btrfs_ugos.py'):
            data = (source/name).read_bytes()
            if hashlib.sha256(data).hexdigest() != record['implementation']['scripts/'+name]:
                raise ValidationError('Boot maintenance source changed during task')
            target = code/name
            if target.exists():
                info = target.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o077
                        or target.read_bytes() != data):
                    raise ValidationError('Pinned maintenance installation differs')
            else:
                fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
        self.validate_unit_path(path)
        name = 'ugacltool-native-' + record['id'] + '.service'
        unit = ('[Unit]\nDescription=UGREEN native storage maintenance\nAfter=local-fs.target\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStart=/usr/bin/python3 %s/fnos_storage.py --config %s/config.json --state %s/boot-state start\n'
                'ExecStop=/usr/bin/python3 %s/fnos_storage.py --config %s/config.json --state %s/boot-state stop\n'
                '[Install]\nWantedBy=multi-user.target\n') % (code,path,path,code,path,path)
        target = Path('/etc/systemd/system') / name
        if target.exists():
            if target.is_symlink() or target.stat().st_uid or target.read_text() != unit:
                raise ValidationError('Existing service is not owned by this task')
        else:
            fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(unit); stream.flush(); os.fsync(stream.fileno())
        storage.view.run('systemctl', 'daemon-reload')
        storage.view.run('systemctl', 'enable', '--now', name)
        if storage.view.run('systemctl', 'is-active', name) != 'active':
            raise ValidationError('Native maintenance service did not start')

    @staticmethod
    def validate_unit_path(path):
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) or '..' in path.parts:
            raise ValidationError('Unsafe service path')

    def stage_verify(self, path, record, cfg):
        pool = cfg['pools'][0]
        volume = Path('/vol%d' % pool['native_adoption']['storage_id'])
        storage.check_mount(storage.mount_record(volume), pool['source'], 'rw')
        storage.native_personal(pool, cfg)
        account = pwd.getpwuid(cfg['uid'])
        if account.pw_gid != cfg['gid']:
            raise ValidationError('Native account primary group changed')
        probe = volume/str(cfg['uid'])/'UGREEN'/('.ugacltool-check-'+record['id'])
        program = '''import ctypes,os,stat
from pathlib import Path
p=Path(%r); data=bytes(range(256))*256
if not p.exists():p.mkdir(mode=0o700)
if p.is_symlink() or not p.is_dir() or p.stat().st_uid!=os.getuid():raise RuntimeError('Probe owner differs')
if {x.name for x in p.iterdir()}-{'probe.bin','verified.bin'}:raise RuntimeError('Probe has foreign entries')
for name in ('probe.bin','verified.bin'):
 q=p/name
 if q.exists():
  st=q.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_size!=len(data):raise RuntimeError('Probe identity differs')
  if q.read_bytes()!=data:raise RuntimeError('Probe content differs')
if not (p/'verified.bin').exists():
 if not (p/'probe.bin').exists():
  fd=os.open(p/'probe.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   offset=0
   while offset<len(data):
    count=os.write(fd,data[offset:])
    if count<=0:raise RuntimeError('Short probe write')
    offset+=count
   os.fsync(fd)
  finally:os.close(fd)
 libc=ctypes.CDLL(None,use_errno=True)
 if libc.renameat2(-100,os.fsencode(p/'probe.bin'),-100,os.fsencode(p/'verified.bin'),1):raise OSError(ctypes.get_errno(),'No-replace rename failed')
fd=os.open(p,os.O_RDONLY);os.fsync(fd);os.close(fd)
if (p/'verified.bin').read_bytes()!=data:raise RuntimeError('Native readback differs')
print('verified')
''' % str(probe)
        if storage.view.run('runuser', '-u', account.pw_name, '--', 'python3', '-c', program) != 'verified':
            raise ValidationError('Ordinary native account write verification failed')
