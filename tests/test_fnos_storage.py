import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fnos_storage as storage


def config():
    return {'version': 1, 'uid': 1000, 'gid': 1001,
            'disk_safety': {'version': 1,
                'protected_disks': [{'serial': 'SYNTH-SYSTEM', 'model': 'SYNTH-SYS',
                                     'size': 64 * 1024**3, 'role': 'system'}],
                'pools': {'pool1': [{'serial': 'SYNTH-ARRAY', 'model': 'SYNTH-HDD',
                                     'size': 400000000000}]}},
            'personal_base': '/vol1/1000/UGREEN', 'pools': [{
                'id': 'pool1', 'vg': 'ug_fixture', 'lv': 'volume1',
                'lv_uuid': 'AAAAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGGGG',
                'source': '/dev/ug_fixture/volume1', 'mount': '/mnt/ugreen/pool1',
                'fsid': '11111111-1111-1111-1111-111111111111',
                'device_uuid': '22222222-2222-2222-2222-222222222222',
                'md_uuid': '33333333-3333-3333-3333-333333333333',
                'size': 300 * 1024**3, 'members': 1}]}


class StartupTests(unittest.TestCase):
    def test_owner_mapping_is_private_and_preserves_source_metadata(self):
        cfg=config();cfg['personal_permissions']='owner';pool=cfg['pools'][0];pool['mode']='rw'
        storage.validate_config(cfg)
        args=storage.owner_mapping_args(pool,cfg)
        self.assertIn('--perms=0600:u+X',args)
        self.assertIn('--chmod-ignore',args);self.assertIn('--xattr-ro',args)
        self.assertNotIn('--resolve-symlinks',args)
        record={'fstype':'fuse.bindfs','source':pool['mount'],'root':'/',
                'options':['rw','nosuid','nodev','noexec'],
                'super_options':['rw','user_id=0','group_id=0','default_permissions','allow_other']}
        with mock.patch.object(Path,'stat',return_value=mock.Mock(st_uid=1000,st_mode=0o40700)):
            storage.check_personal(record,pool,cfg,pool['source'])
            for key,value in [('fstype','fuse.foreign'),('source','/unrelated'),
                              ('super_options',['rw','allow_other']),('options',['rw','nodev'])]:
                with self.subTest(key=key),self.assertRaises(storage.ValidationError):
                    storage.check_personal({**record,key:value},pool,cfg,pool['source'])
        with mock.patch.object(Path,'stat',return_value=mock.Mock(st_uid=1000,st_mode=0o40755)):
            with self.assertRaises(storage.ValidationError):
                storage.check_personal(record,pool,cfg,pool['source'])

    def test_missing_array_assembly_is_readonly_and_uuid_limited(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(Path,'glob',return_value=[]), \
                 mock.patch.object(Path,'exists',return_value=False), \
                 mock.patch.object(storage.view,'run') as run:
                storage.ensure_array(Path(directory),config()['pools'][0])
            args=run.call_args.args
            self.assertEqual(args[:5],('mdadm','--assemble','--scan','--readonly','--config'))
            text=Path(args[5]).read_text()
            self.assertIn('AUTO -all',text)
            self.assertIn('UUID=33333333:33333333:33333333:33333333',text)
            self.assertNotIn('--force',args);self.assertNotIn('--run',args)

    def test_already_writable_md_is_not_toggled_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();node=root/'dm';md=root/'md';pool=config()['pools'][0]
            for path in (node/'slaves',node/'holders',node/'dm',md/'md',md/'holders'):
                path.mkdir(parents=True,exist_ok=True)
            (node/'slaves'/'md').symlink_to(md);(md/'holders'/node.name).touch()
            (md/'md/array_state').write_text('clean')
            (md/'md/uuid').write_text(pool['md_uuid']);(node/'dm/name').write_text('owned')
            fd=os.open(root/'device',os.O_RDWR|os.O_CREAT,0o600)
            resolve=Path.resolve
            def resolved(path,**kwargs):
                return node if str(path)=='/sys/dev/block/253:1' else resolve(path,**kwargs)
            def run(*args):
                if args[0]=='lvs':return pool['lv_uuid']
                if args[0]=='dmsetup':return '0 100 linear 9:127 0'
                return ''
            with mock.patch.object(storage.view,'run',side_effect=run) as commands, \
                 mock.patch.object(storage.view,'open_device',return_value=(fd,None)), \
                 mock.patch.object(storage.view,'dev_id',return_value='253:1'), \
                 mock.patch.object(storage.view,'readonly',return_value=False), \
                 mock.patch.object(storage.view,'mounts',return_value=[]), \
                 mock.patch.object(storage.view,'source_size',return_value=pool['size']), \
                 mock.patch.object(Path,'resolve',resolved):
                self.assertEqual(storage.activate_rw(pool,node,md),node)
            self.assertFalse(any(call.args[0]=='mdadm' for call in commands.call_args_list))
            self.assertTrue(any('activation { read_only_volume_list = [] }' in call.args for call in commands.call_args_list))

    def test_rw_reactivation_closes_own_fd_and_revalidates_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);node=root/'dm';md=root/'md'
            (node/'holders').mkdir(parents=True);(md/'holders').mkdir(parents=True)
            (md/'holders'/node.name).touch()
            fd=os.open(root/'device',os.O_RDWR|os.O_CREAT,0o600)
            second=os.open(root/'device',os.O_RDONLY)
            def activate(pool,actual_node,actual_md):
                with self.assertRaises(OSError):os.fstat(fd)
                self.assertEqual((actual_node,actual_md),(node,md))
            with mock.patch.object(storage,'check_source',side_effect=[(fd,node,md,{}),(second,node,md,{})]) as check, \
                 mock.patch.object(storage.view,'mounts',return_value=[]), \
                 mock.patch.object(storage.view,'dev_id',return_value='253:1'), \
                 mock.patch.object(storage,'activate_rw',side_effect=activate):
                storage.prepare_rw(config()['pools'][0])
                self.assertEqual(check.call_count,2)
            with self.assertRaises(OSError):os.fstat(second)

    def test_busy_native_bridge_is_restored_after_owned_unmount_failure(self):
        bridge={'fstype':'trimafs','source':'trimafs','root':'/',
                'super_options':['rw','trimacl','ino_mode=32']}
        calls=[]
        def run(*args):
            calls.append(args)
            if args==('umount','/personal/pool'):
                # First EBUSY permits bridge refresh; the next unrelated error
                # must restore the bridge and propagate, never force unmount.
                if calls.count(args)==1:raise storage.ValidationError('target is busy')
                raise storage.ValidationError('permission denied')
            return ''
        with mock.patch.object(storage.view,'run',side_effect=run), \
             mock.patch.object(storage,'mount_record',side_effect=[bridge,None]):
            with self.assertRaisesRegex(storage.ValidationError,'permission denied'):
                storage.unmount_personal('/personal/pool',True)
        self.assertEqual(calls[-1],('mount','-t','trimafs','-o','trimacl,ino_mode=32','trimafs','/fs'))
        self.assertFalse(any('--force' in args or '-l' in args for args in calls))

    def test_unknown_or_live_bridge_is_never_reconfigured(self):
        with mock.patch.object(storage.view,'run',side_effect=storage.ValidationError('target is busy')) as run, \
             mock.patch.object(storage,'mount_record',return_value={'fstype':'foreign'}):
            with self.assertRaisesRegex(storage.ValidationError,'Unknown'):
                storage.unmount_personal('/personal/pool',True)
            self.assertEqual(run.call_count,1)

    def test_reject_native_vg_wrong_paths_identity_and_mode(self):
        storage.validate_config(config())
        for key, value in [('vg', 'trim_native'), ('id', '../pool1'),
                           ('source', '/dev/sda'), ('mode', 'writable'),
                           ('fsid', 'not-a-uuid'), ('lv_uuid', 'foreign'),
                           ('mount', '/vol1')]:
            data = config(); data['pools'][0][key] = value
            with self.subTest(key=key), self.assertRaises((storage.ValidationError, ValueError)):
                storage.validate_config(data)
        data = config(); data['pools'].append(copy.deepcopy(data['pools'][0]))
        with self.assertRaises(storage.ValidationError): storage.validate_config(data)

    def test_mount_guard_blocks_foreign_fs_device_and_writable_mount(self):
        record = {'identity': '0:55', 'source': '/dev/owned', 'fstype': 'btrfs', 'root': '/', 'options': ['ro']}
        def device_stat(path):
            return mock.Mock(st_rdev=8 if path == '/dev/foreign' else 7)
        with mock.patch.object(storage.os, 'stat', side_effect=device_stat):
            storage.check_mount(record, '/dev/fake', 'ro')
            for key, value in [('source', '/dev/foreign'), ('fstype', 'ext4'),
                               ('root', '/subvolume'), ('options', ['rw'])]:
                altered = {**record, key: value}
                with self.subTest(key=key), self.assertRaises(storage.ValidationError):
                    storage.check_mount(altered, '/dev/fake', 'ro')
            with self.assertRaises(storage.ValidationError):
                storage.check_mount(None, '/dev/fake', 'ro')

    def test_stopped_state_is_idempotent_never_unmounts(self):
        with mock.patch.object(storage, 'pool_state', return_value={'phase': 'stopped'}), \
             mock.patch.object(storage, 'mount_record', return_value=None), \
             mock.patch.object(storage.view, 'run') as run:
            storage.stop_pool(Path('/unused'), config()['pools'][0], config())
            run.assert_not_called()

    def test_missing_ownership_never_unmounts_foreign_mount(self):
        with mock.patch.object(storage, 'pool_state', return_value=None), \
             mock.patch.object(storage, 'mount_record', return_value={'source': 'foreign'}), \
             mock.patch.object(storage.view, 'run') as run:
            with self.assertRaises(storage.ValidationError):
                storage.stop_pool(Path('/unused'), config()['pools'][0], config())
            run.assert_not_called()

    def test_mountinfo_exact_match_not_containing_filesystem(self):
        text = '1 0 253:7 / /mnt/ugreen/pool1 ro - btrfs /dev/dm-7 ro\n'
        with mock.patch.object(Path, 'read_text', return_value=text):
            self.assertIsNone(storage.mount_record('/mnt/ugreen/pool1/missing'))
            self.assertEqual(storage.mount_record('/mnt/ugreen/pool1')['identity'], '253:7')

    def test_stale_boot_state_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root)/'pool1.json').touch()
            with mock.patch.object(storage, 'private_json', return_value={'boot': 'old'}), \
                 mock.patch.object(Path, 'read_text', return_value='current\n'):
                self.assertIsNone(storage.pool_state(Path(root), {'id': 'pool1'}))


if __name__ == '__main__': unittest.main()
