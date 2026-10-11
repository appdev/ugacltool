import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fnos_native_lab as lab

TEST_SSD = {'serial': 'SYNTH-TEST-SSD', 'model': 'SYNTH-SSD', 'size': 256 * 1024**3}


class NativeLabGuards(unittest.TestCase):
    def disk(self):
        return dict(TEST_SSD, name='/dev/nvme1n1', type='disk',
                    **{'maj:min': '259:4', 'mountpoints': [None]})

    def test_wrong_serial_size_model_or_duplicate_are_rejected(self):
        original = self.disk()
        for change in [{'serial': 'system-disk'}, {'size': TEST_SSD['size'] - 512},
                       {'model': 'wrong-model'}, {'type': 'part'}]:
            with self.assertRaises(lab.LabError):
                lab.select_disk([dict(original, **change)], TEST_SSD)
        with self.assertRaises(lab.LabError):
            lab.select_disk([original, original], TEST_SSD)

    def test_partitions_mounts_and_holders_are_checked(self):
        with tempfile.TemporaryDirectory() as root:
            sysfs = Path(root)
            for identity in ['259:4', '259:5']:
                (sysfs / identity / 'holders').mkdir(parents=True)
            disk = self.disk()
            disk['children'] = [{'type': 'part', 'maj:min': '259:5', 'mountpoints': [None]}]
            lab.check_unused(disk, sysfs)
            disk['children'][0]['mountpoints'] = ['/vol1']
            with self.assertRaises(lab.LabError):
                lab.check_unused(disk, sysfs)
            disk['children'][0]['mountpoints'] = [None]
            (sysfs / '259:5/holders/md0').touch()
            with self.assertRaises(lab.LabError):
                lab.check_unused(disk, sysfs)

    def test_physical_descriptor_readonly_and_overlay_only_writable(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root) / 'base'; base.write_bytes(b'untouched')
            overlay = Path(root) / 'overlay'; overlay.write_bytes(b'new')
            fd = os.open(base, os.O_RDONLY)
            try:
                nodes = lab.backing_nodes(fd, overlay)
                self.assertTrue(nodes[0]['read-only'])
                self.assertTrue(nodes[1]['read-only'])
                self.assertEqual(nodes[0]['filename'], '/dev/fdset/1')
                self.assertEqual(nodes[-1]['backing'], 'ssd-readonly')
                self.assertNotIn(str(base), str(nodes))
            finally:
                os.close(fd)
            fd = os.open(base, os.O_RDWR)
            try:
                with self.assertRaises(lab.LabError):
                    lab.backing_nodes(fd, overlay)
            finally:
                os.close(fd)
            self.assertEqual(base.read_bytes(), b'untouched')

    def test_changed_device_identity_is_rejected(self):
        pinned = dict(TEST_SSD, identity='259:4')
        disk = self.disk(); disk['maj:min'] = '259:99'
        with mock.patch.object(lab, 'disk_inventory', return_value=[disk]), \
                mock.patch.object(lab, 'check_unused'), \
                mock.patch.object(lab.os, 'fstat', return_value=mock.Mock(st_rdev=os.makedev(259, 4))), \
                mock.patch.object(lab.fcntl, 'ioctl', return_value=lab.struct.pack('Q', TEST_SSD['size'])):
            with self.assertRaises(lab.LabError):
                lab.recheck(12, pinned)


if __name__ == '__main__':
    unittest.main()
