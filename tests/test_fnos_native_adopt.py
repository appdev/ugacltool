import copy
import errno
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fnos_native_adopt as adoption
import fnos_storage as storage
from test_fnos_storage import config


def journal():
    original = config(); original['pools'][0]['mode'] = 'rw'
    entry = {'pool': copy.deepcopy(original['pools'][0]),
             'vg': 'trim_11111111_2222_3333_4444_555555555555', 'lv': '0',
             'uuid': 'trim_11111111_2222_3333_4444_555555555555-0',
             'storage_id': 2, 'disks': copy.deepcopy(original['disk_safety']['pools']['pool1']),
             'phase': 'prepared'}
    return {'version': 2, 'config_before': original, 'pools': [entry],
            'database_before': [{'id': 1, 'uuid': 'existing', 'state': 0, 'pool_type': 0}]}


class NativeAdoptionGuards(unittest.TestCase):
    def test_home_publication_never_replaces_an_existing_directory(self):
        native = mock.Mock()
        native.renameat2.return_value = 0
        with mock.patch.object(adoption.ctypes, 'CDLL', return_value=native):
            adoption.publish_home(Path('/vol2/staging'), Path('/vol2/1000'))
        native.renameat2.assert_called_once_with(-100, b'/vol2/staging', -100, b'/vol2/1000', 1)
        native.renameat2.return_value = -1
        with mock.patch.object(adoption.ctypes, 'CDLL', return_value=native):
            with self.assertRaises(storage.ValidationError):
                adoption.publish_home(Path('/vol2/staging'), Path('/vol2/1000'))

    def test_marker_rollback_accepts_only_original_or_journaled_value(self):
        with mock.patch.object(adoption.os, 'getxattr', return_value=b'changed', create=True), \
             mock.patch.object(adoption.os, 'removexattr', create=True) as remove:
            with self.assertRaises(storage.ValidationError):
                adoption.restore_marker('/owned', None)
            remove.assert_not_called()
        with mock.patch.object(adoption.os, 'getxattr', side_effect=OSError(errno.ENODATA, 'absent'), create=True), \
             mock.patch.object(adoption.os, 'removexattr', create=True) as remove:
            adoption.restore_marker('/owned', None)
            remove.assert_not_called()
        with mock.patch.object(adoption.os, 'getxattr', return_value=b'1', create=True), \
             mock.patch.object(adoption.os, 'removexattr', create=True) as remove:
            adoption.restore_marker('/owned', None)
            remove.assert_called_once_with('/owned', 'user.is_trimacl')

    def test_native_config_requires_ugreen_provenance_and_protects_volume_one(self):
        value = journal(); pool = adoption.renamed_pool(value['pools'][0])
        cfg = copy.deepcopy(value['config_before']); cfg['pools'] = [pool]
        storage.validate_config(cfg)
        for field, wrong in [('storage_id', 1), ('original_vg', 'trim_existing'),
                              ('original_lv', 'other'), ('uuid', 'foreign')]:
            bad = copy.deepcopy(cfg); bad['pools'][0]['native_adoption'][field] = wrong
            with self.subTest(field=field), self.assertRaises(storage.ValidationError):
                storage.validate_config(bad)
        del cfg['pools'][0]['native_adoption']
        with self.assertRaises(storage.ValidationError):
            storage.validate_config(cfg)

    def test_journal_rejects_replaced_origin_or_database_collision(self):
        adoption.validate_journal(journal())
        for change in [lambda j: j['pools'][0]['pool'].update(fsid='00000000-0000-0000-0000-000000000000'),
                       lambda j: j['pools'][0].update(storage_id=1),
                       lambda j: j['database_before'].append({'id': 2, 'uuid': 'foreign'}),
                       lambda j: j['pools'][0].update(disks=[])]:
            value = journal(); change(value)
            with self.assertRaises(storage.ValidationError):
                adoption.validate_journal(value)

    def test_native_registration_never_overwrites_an_existing_row(self):
        value = journal(); entry = value['pools'][0]
        for current in [[], [{'id': 2, 'uuid': 'foreign', 'state': 0, 'pool_type': 0}]]:
            with mock.patch.object(adoption, 'rows', return_value=current), \
                 mock.patch.object(adoption, 'sql') as database:
                with self.assertRaises(storage.ValidationError):
                    adoption.register(entry, value['database_before'])
                database.assert_not_called()

    def test_mountinfo_escaped_names_are_matched_without_logging_names(self):
        text = '1 0 253:7 /old\\040folder /vol2/1000/UGREEN/old\\040folder rw - btrfs /dev/dm-7 rw\n'
        with mock.patch.object(Path, 'read_text', return_value=text):
            record = storage.mount_record('/vol2/1000/UGREEN/old folder')
        self.assertEqual(record['root'], '/old folder')

    def test_interrupted_rename_requires_the_exact_lv_uuid_and_capacity(self):
        entry = journal()['pools'][0]
        def run(*args):
            if args[0] == 'lvs':
                import json
                return json.dumps({'report': [{'lv': [{'vg_name': entry['pool']['vg'],
                    'lv_name': '0', 'lv_uuid': entry['pool']['lv_uuid'],
                    'lv_size': str(entry['pool']['size'])}]}]})
            return ''
        with mock.patch.object(storage.view, 'run', side_effect=run) as commands, \
             mock.patch.object(adoption, 'check_pool'):
            adoption.finish_rename(entry, config()['disk_safety'])
        mutations = [c.args for c in commands.call_args_list if c.args[0] != 'lvs']
        self.assertEqual(mutations, [('vgrename', entry['pool']['vg'], entry['vg'])])


if __name__ == '__main__':
    unittest.main()
