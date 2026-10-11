import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'tools'))
import validate_real_cow as cow


class CowGuards(unittest.TestCase):
    def test_cow_preserves_system_free_space_before_allocation(self):
        for free in (0, 2*1024**3, 3*1024**3-1):
            with mock.patch.object(cow.shutil,'disk_usage',return_value=mock.Mock(free=free)):
                with self.assertRaises(cow.view.ValidationError):cow.require_cow_space('/synthetic-state')
        with mock.patch.object(cow.shutil,'disk_usage',return_value=mock.Mock(free=3*1024**3)):
            cow.require_cow_space('/synthetic-state')
    def test_snapshot_writes_are_routed_to_separate_persistent_cow(self):
        self.assertEqual(cow.snapshot_table(300*1024**3,'253:1','7:2'),
                         '0 629145600 snapshot 253:1 7:2 P 128')
        for size,origin,delta in [(300*1024**3+1,'253:1','7:2'),
                                  (300*1024**3,'253:1\n0 8 linear 8:1 0','7:2')]:
            with self.assertRaises(cow.view.ValidationError):cow.snapshot_table(size,origin,delta)

    def test_foreign_snapshot_uuid_or_table_cannot_be_removed(self):
        state={'name':'ugacltest-owned','uuid':'UGACLTEST-owned','table':'expected'}
        for returns in [('foreign',),('UGACLTEST-owned','foreign')]:
            with mock.patch.object(cow.view,'run',side_effect=returns) as run:
                with self.assertRaises(cow.view.ValidationError):cow.release(state)
                self.assertFalse(any('remove' in c.args for c in run.call_args_list))


if __name__=='__main__':unittest.main()
