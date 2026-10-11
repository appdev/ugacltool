import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import disk_safety as safety
import fnos_native_adopt as adoption
import fnos_storage as storage
import convert_fnos as conversion
from test_fnos_storage import config
from test_fnos_native_adopt import journal


class ExplicitDiskGuards(unittest.TestCase):
    def policy(self):
        return config()['disk_safety']

    def inventory(self):
        policy = self.policy()
        return [dict(policy['protected_disks'][0], name='/dev/sda', type='disk'),
                dict(policy['pools']['pool1'][0], name='/dev/sdb', type='disk')]

    def test_missing_empty_system_or_target_policy_fails(self):
        values = [None, {}, dict(self.policy(), protected_disks=[]),
                  dict(self.policy(), pools={})]
        without_system = self.policy(); without_system['protected_disks'][0]['role'] = 'other'
        values.append(without_system)
        for value in values:
            with self.subTest(value=value), self.assertRaises(safety.ValidationError):
                safety.validate_policy(value)

    def test_target_policy_is_exact_for_pool_names_and_member_count(self):
        cfg = config()
        safety.policy_for(cfg)
        for change in (lambda c: c['pools'][0].update(members=2),
                       lambda c: c['disk_safety']['pools'].update(pool2=[{'serial': 'SYNTH-OTHER',
                           'model': 'SYNTH-HDD', 'size': 400000000000}])):
            bad = copy.deepcopy(cfg); change(bad)
            with self.assertRaises(safety.ValidationError): safety.policy_for(bad)

    def test_bad_identity_and_placeholders_cannot_authorize_a_disk(self):
        value = self.policy()['pools']['pool1'][0]
        for change in ({'serial': ''}, {'serial': '<serial>'}, {'serial': 'SYNTH\nOTHER'},
                       {'model': '__MODEL__'}, {'size': 0}, {'size': True}, {'size': '400000000000'}):
            with self.subTest(change=change), self.assertRaises(safety.ValidationError):
                safety.identity(dict(value, **change))

    def test_protected_targets_and_duplicate_assignments_are_rejected(self):
        overlap = self.policy(); overlap['pools']['pool1'] = [overlap['protected_disks'][0]]
        duplicates = self.policy(); duplicates['pools']['pool2'] = duplicates['pools']['pool1']
        protected_duplicate = self.policy()
        protected_duplicate['protected_disks'].append(protected_duplicate['protected_disks'][0])
        for value in (overlap, duplicates, protected_duplicate):
            with self.assertRaises(safety.ValidationError): safety.validate_policy(value)

    def test_test_disk_must_match_a_protected_non_target_test_identity(self):
        policy = self.policy()
        disk = {'serial': 'SYNTH-TEST', 'model': 'SYNTH-SSD', 'size': 256 * 1024**3}
        policy['protected_disks'].append(dict(disk, role='test'))
        policy['test_disk'] = disk
        safety.validate_policy(policy)
        for change in ({'size': disk['size']-512}, {'model': 'SYNTH-WRONG'},
                       {'serial': 'SYNTH-SYSTEM'}):
            bad = copy.deepcopy(policy); bad['test_disk'].update(change)
            with self.assertRaises(safety.ValidationError): safety.validate_policy(bad)

    def test_wrong_actual_model_size_type_duplicate_or_missing_fails(self):
        policy = self.policy(); disks = self.inventory()
        safety.check_inventory(policy, disks, {'SYNTH-SYSTEM'})
        for change in ({'size': disks[1]['size']-512}, {'model': 'SYNTH-WRONG'},
                       {'type': 'part'}, {'serial': 'SYNTH-OTHER'}):
            bad = copy.deepcopy(disks); bad[1].update(change)
            with self.subTest(change=change), self.assertRaises(safety.ValidationError):
                safety.check_inventory(policy, bad, {'SYNTH-SYSTEM'})
        for bad in (disks + [disks[1]], disks[:1], disks[1:]):
            with self.assertRaises(safety.ValidationError):
                safety.check_inventory(policy, bad, {'SYNTH-SYSTEM'})

    def test_real_system_roots_must_be_in_the_explicit_system_list(self):
        for critical in ({'SYNTH-ARRAY'}, {'SYNTH-SYSTEM', 'SYNTH-UNLISTED'}, set()):
            with self.assertRaises(safety.ValidationError):
                safety.check_inventory(self.policy(), self.inventory(), critical)

    def test_system_trace_follows_dm_md_partition_to_physical_disk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            physical = root/'sda'; part = physical/'sda1'; part.mkdir(parents=True)
            (part/'partition').write_text('1')
            md = root/'md0'; (md/'slaves').mkdir(parents=True)
            (md/'slaves/sda1').symlink_to(part)
            dm = root/'dm-0'; (dm/'slaves').mkdir(parents=True)
            (dm/'slaves/md0').symlink_to(md)
            sysfs = root/'sys'; sysfs.mkdir(); (sysfs/'253:0').symlink_to(dm)
            mounts = root/'mountinfo'; mounts.write_text('1 0 253:0 / / rw - ext4 /dev/dm-0 rw\n')
            self.assertEqual(safety.system_serials(self.inventory(), sysfs, mounts), {'SYNTH-SYSTEM'})
            mounts.write_text('1 0 0:7 / / rw - overlay overlay rw\n')
            with self.assertRaises(safety.ValidationError):
                safety.system_serials(self.inventory(), sysfs, mounts)

    def test_actual_md_members_must_equal_allowlist_even_when_configured_disks_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            physical = root/'sdb'; part = physical/'sdb2'; part.mkdir(parents=True)
            (part/'partition').write_text('2')
            md = root/'md'; (md/'slaves').mkdir(parents=True)
            link = md/'slaves/member'; link.symlink_to(part)
            with mock.patch.object(safety, 'check_inventory', return_value=self.inventory()):
                members = safety.array_members(md, self.policy(), 'pool1')
                self.assertEqual(members[0]['serial'], 'SYNTH-ARRAY')
                self.assertEqual(members[0]['partition'], 'sdb2')
                wrong = root/'sda'; wrong.mkdir()
                link.unlink(); link.symlink_to(wrong)
                with self.assertRaises(safety.ValidationError):
                    safety.array_members(md, self.policy(), 'pool1')

    def test_anonymous_btrfs_system_mount_protects_all_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sysfs=root/'sys'; sysfs.mkdir()
            btrfs=root/'btrfs'; devices=btrfs/'synthetic-fsid/devices'; devices.mkdir(parents=True)
            for dev, name in (('8:0','sda'),('8:16','sdb')):
                disk=root/name; disk.mkdir(); (disk/'dev').write_text(dev)
                (sysfs/dev).symlink_to(disk); (devices/name).symlink_to(disk)
            mounts=root/'mountinfo'; mounts.write_text('1 0 0:58 / /vol1 rw - btrfs /dev/sda rw\n')
            with mock.patch.object(safety,'block_device_id',return_value='8:0'):
                self.assertEqual(safety.system_serials(self.inventory(),sysfs,mounts,btrfs),
                                 {'SYNTH-SYSTEM','SYNTH-ARRAY'})

    def test_btrfs_system_members_missing_duplicate_or_ambiguous_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); members=root/'a/devices'; members.mkdir(parents=True)
            device=members/'sda'; device.mkdir(); (device/'dev').write_text('8:0')
            with mock.patch.object(safety,'block_device_id',return_value='8:0'):
                self.assertEqual(safety.mounted_btrfs_members('/dev/sda',root),{'8:0'})
                missing=members/'missing'; missing.mkdir()
                with self.assertRaises(safety.ValidationError):safety.mounted_btrfs_members('/dev/sda',root)
                (missing/'dev').write_text('8:0')
                with self.assertRaises(safety.ValidationError):safety.mounted_btrfs_members('/dev/sda',root)
                (missing/'dev').write_text('8:16')
                other=root/'b/devices/sda'; other.mkdir(parents=True); (other/'dev').write_text('8:0')
                with self.assertRaises(safety.ValidationError):safety.mounted_btrfs_members('/dev/sda',root)
                (device/'dev').write_text('8:32'); (other/'dev').write_text('8:48')
                with self.assertRaises(safety.ValidationError):safety.mounted_btrfs_members('/dev/sda',root)

    def test_btrfs_system_source_must_be_a_real_block_device(self):
        with self.assertRaises(safety.ValidationError):
            safety.mounted_btrfs_members('/dev/null',Path('unused'))
        with self.assertRaises(safety.ValidationError):
            safety.mounted_btrfs_members('/tmp/foreign',Path('unused'))

    def test_start_and_conversion_refuse_missing_policy_before_runtime_or_state_changes(self):
        cfg = config(); del cfg['disk_safety']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'never-created'
            with mock.patch.object(storage.view, 'run') as run, \
                 mock.patch.object(storage, 'ensure_array') as assemble:
                with self.assertRaises(safety.ValidationError): storage.start_pool(path, cfg['pools'][0], cfg)
                with mock.patch.object(conversion.view, 'require_host'):
                    with self.assertRaises(safety.ValidationError):
                        conversion.convert(cfg, 'pool1', 'unused', path)
                run.assert_not_called(); assemble.assert_not_called()
            self.assertFalse(path.exists())

    def test_prepare_refuses_missing_policy_before_lvm_backup_or_registration(self):
        cfg = config(); cfg['pools'][0]['mode']='rw'; del cfg['disk_safety']
        with mock.patch.object(adoption, 'check_native_version'), \
             mock.patch.object(storage, 'private_json', return_value=cfg), \
             mock.patch.object(storage.view, 'run') as run, mock.patch.object(adoption, 'sql') as sql:
            with self.assertRaises(safety.ValidationError): adoption.prepare(Path('unused'), Path('unused'))
            run.assert_not_called(); sql.assert_not_called()

    def test_journal_policy_drift_and_legacy_version_are_rejected(self):
        j = journal(); j['config_path']='/private-config'; j['backups_ready']=True
        for changed in (dict(j, version=1), dict(j, version=3)):
            with self.assertRaises(safety.ValidationError): adoption.validate_journal(changed)
        drift = copy.deepcopy(j); drift['pools'][0]['disks'][0]['model']='SYNTH-WRONG'
        with self.assertRaises(safety.ValidationError): adoption.validate_journal(drift)
        changed_cfg = copy.deepcopy(j['config_before'])
        changed_cfg['disk_safety']['protected_disks'][0]['size'] += 512
        for operation in (adoption.apply, adoption.rollback):
            with mock.patch.object(adoption, 'check_native_version'), \
                 mock.patch.object(storage, 'private_json', side_effect=[j, changed_cfg]), \
                 mock.patch.object(safety, 'check_config', return_value=j['config_before']['disk_safety']), \
                 mock.patch.object(storage.view, 'run') as run, mock.patch.object(adoption, 'sql') as sql:
                with self.assertRaises(safety.ValidationError): operation(Path('unused'))
                run.assert_not_called(); sql.assert_not_called()

    def test_three_pool_journal_preserves_the_full_physical_policy(self):
        j = journal(); cfg=j['config_before']; cfg['pools']=[]; j['pools']=[]
        cfg['disk_safety']['pools']={}
        for number, count in ((1,1),(2,1),(3,4)):
            pool=copy.deepcopy(config()['pools'][0]); pool['id']='pool%d' % number
            pool.update(vg='ug_fixture%d' % number, source='/dev/ug_fixture%d/volume1' % number,
                        mount='/mnt/ugreen/pool%d' % number, members=count, mode='rw')
            cfg['pools'].append(pool)
            members=[{'serial':'SYNTH-POOL%d-DISK%d' % (number,i), 'model':'SYNTH-HDD',
                      'size':400000000000} for i in range(count)]
            cfg['disk_safety']['pools'][pool['id']]=members
            vg='trim_%08x_2222_3333_4444_555555555555' % number
            j['pools'].append({'pool':copy.deepcopy(pool), 'vg':vg, 'lv':'0', 'uuid':vg+'-0',
                               'storage_id':number+1, 'disks':copy.deepcopy(members), 'phase':'prepared'})
        adoption.validate_journal(j)
        self.assertEqual(len(j['config_before']['disk_safety']['pools']['pool3']),4)

    def test_placeholder_config_cli_fails_without_device_access(self):
        import subprocess
        base=Path(__file__).resolve().parents[1]
        result=subprocess.run([sys.executable, str(base/'tools/check_config.py'),
                               '--config',str(base/'examples/storage.json.example'), '--schema-only'],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertFalse(json.loads(result.stderr)['valid'])
        self.assertNotIn('serial',result.stderr)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'renameat2 integration requires Linux')
    def test_real_atomic_home_publication_preserves_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); staging=root/'staging'; home=root/'1000'
            staging.mkdir(); home.mkdir(); (home/'keep').write_bytes(b'original')
            with self.assertRaises(safety.ValidationError): adoption.publish_home(staging, home)
            self.assertEqual((home/'keep').read_bytes(), b'original'); self.assertTrue(staging.is_dir())
            newhome=root/'2000'
            adoption.publish_home(staging, newhome)
            self.assertTrue(newhome.is_dir()); self.assertFalse(staging.exists())


if __name__ == '__main__':
    unittest.main()
