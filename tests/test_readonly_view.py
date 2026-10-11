import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import btrfs_readonly_view as view


class MappingTests(unittest.TestCase):
    def test_three_mirrors_cover_entire_12t_device_without_copy(self):
        size = 12 * 1024**4
        rows = [line.split() for line in view.linear_table(size, "253:7", "7:9", view.MIRRORS).splitlines()]
        end = 0
        replaced = []
        for start, length, target, identity, offset in rows:
            start, length, offset = map(int, (start, length, offset))
            self.assertEqual(start, end)
            self.assertEqual(target, "linear")
            if identity == "7:9":
                self.assertEqual(length, 8)
                self.assertEqual(offset, len(replaced)*8)
                replaced.append(start*512)
            else:
                self.assertEqual(identity, "253:7")
                self.assertEqual(start, offset)
            end = start + length
        self.assertEqual(end*512, size)
        self.assertEqual(replaced, list(view.MIRRORS))
        self.assertNotIn(1024**4, replaced)

    def test_missing_extra_unaligned_or_injected_rows_rejected(self):
        cases = [(12*1024**4, "253:7", "7:9", view.MIRRORS[:2]),
                 (12*1024**4, "253:7", "7:9", (*view.MIRRORS, 1024**4)),
                 (300*1024**3+512, "253:7", "7:9", view.MIRRORS),
                 (300*1024**3, "253:7\n0 8 error", "7:9", view.MIRRORS)]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(view.ValidationError):
                view.linear_table(*args)

    def test_small_device_replaces_only_fitting_mirrors(self):
        size = view.MIRRORS[1] + 4096
        rows = view.linear_table(size, "7:1", "7:2", view.MIRRORS[:2])
        self.assertEqual(sum(int(x.split()[1]) for x in rows.splitlines())*512, size)


class GuardTests(unittest.TestCase):
    def test_nonredundant_md_without_degraded_requires_all_members(self):
        with tempfile.TemporaryDirectory() as root:
            node=Path(root)/'md127';md=node/'md';md.mkdir(parents=True)
            (md/'array_state').write_text('readonly')
            (md/'level').write_text('linear');(md/'raid_disks').write_text('1')
            slaves=node/'slaves';slaves.mkdir();(slaves/'sda2').mkdir()
            view.guard_storage_graph(node)
            (md/'raid_disks').write_text('2')
            with self.assertRaisesRegex(view.ValidationError,'member set'):
                view.guard_storage_graph(node)
            (md/'raid_disks').write_text('1');(md/'level').write_text('raid1')
            with self.assertRaisesRegex(view.ValidationError,'member set'):
                view.guard_storage_graph(node)

    def test_md_requires_readonly_healthy_idle_and_rejects_cache(self):
        with tempfile.TemporaryDirectory() as root:
            node=Path(root)/'md9';md=node/'md';md.mkdir(parents=True)
            for state,degraded,action,allowed in [('readonly','0','idle',True),('active','0','idle',False),('readonly','1','idle',False),('readonly','0','resync',False)]:
                for name,value in [('array_state',state),('degraded',degraded),('sync_action',action)]:
                    (md/name).write_text(value)
                if allowed:view.guard_storage_graph(node)
                else:
                    with self.assertRaises(view.ValidationError):view.guard_storage_graph(node)
            cache=Path(root)/'bcache0';cache.mkdir()
            with self.assertRaisesRegex(view.ValidationError,'cache'):view.guard_storage_graph(cache)

    def test_non_linear_dm_backing_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            node=Path(root)/'dm-1';(node/'dm').mkdir(parents=True);(node/'dm/name').write_text('fixture-lv')
            with mock.patch.object(view,'run',return_value='0 128 linear 9:9 0'):
                view.guard_storage_graph(node)
            with mock.patch.object(view,'run',return_value='0 128 thin 9:9 1'):
                with self.assertRaisesRegex(view.ValidationError,'Only linear'):
                    view.guard_storage_graph(node)

    def test_duplicate_loop_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            blocks=Path(root)/'block';blocks.mkdir()
            image=Path(root)/'image';image.write_bytes(b'fixture')
            alias=Path(root)/'alias';os.link(image,alias)
            for name,backing in [('loop1',image),('loop2',alias)]:
                p=blocks/name/'loop';p.mkdir(parents=True)
                (p/'backing_file').write_text(str(backing))
            with self.assertRaisesRegex(view.ValidationError,'another loop alias'):
                view.guard_loop_aliases(blocks/'loop1',blocks)

    def test_removed_state_is_idempotent_and_never_detaches_reused_loop(self):
        with mock.patch.object(view,'require_host'), mock.patch.object(view,'load_state',return_value=(Path('unused'),{'phase':'removed'})), mock.patch.object(view,'run') as run, mock.patch.object(view.subprocess,'run') as subprocess_run:
            self.assertEqual(view.remove('unused')['phase'],'removed')
            run.assert_not_called();subprocess_run.assert_not_called()

    def test_only_confirmed_zombie_without_namespace_can_skip_einval(self):
        with tempfile.TemporaryDirectory() as root:
            process=Path(root)/'123';process.mkdir();(process/'mountinfo').touch()
            original=Path.read_text
            def read(path, *args, **kwargs):
                if path.name=='mountinfo':raise OSError(22,'Invalid argument')
                return original(path,*args,**kwargs)
            for state, allowed in [('Z (zombie)',True),('S (sleeping)',False)]:
                (process/'status').write_text('State:\t'+state+'\n')
                with mock.patch.object(Path,'read_text',read):
                    if allowed:self.assertEqual(view.mounts('253:7',Path(root)),[])
                    else:
                        with self.assertRaisesRegex(view.ValidationError,'Cannot inspect'):
                            view.mounts('253:7',Path(root))

    def test_other_namespace_bind_mount_detected(self):
        with tempfile.TemporaryDirectory() as root:
            process = Path(root) / "123"; process.mkdir()
            (process / "mountinfo").write_text("24 22 253:7 /users /home rw - btrfs /dev/dm-7 rw\n")
            self.assertEqual(view.mounts("253:7", Path(root)), ["/home"])
            original_stat=Path.stat
            def device_stat(path,*args,**kwargs):
                if path.name=='dm-7': return mock.Mock(st_mode=0o60600,st_rdev=7)
                return original_stat(path,*args,**kwargs)
            with mock.patch.object(Path,'stat',device_stat), \
                 mock.patch.object(view.os,'major',return_value=253), \
                 mock.patch.object(view.os,'minor',return_value=7):
                self.assertEqual(view.mounts("253:8", Path(root)), [])

    def test_btrfs_anonymous_device_mount_and_bind_detected_by_source(self):
        with tempfile.TemporaryDirectory() as root:
            process=Path(root)/'123';process.mkdir()
            (process/'mountinfo').write_text('24 22 0:55 / /mnt/pool ro - btrfs /dev/dm-7 ro\n25 22 0:55 / /personal/pool ro - btrfs /dev/dm-7 ro\n')
            original_stat=Path.stat
            def device_stat(path,*args,**kwargs):
                if path.name=='dm-7': return mock.Mock(st_mode=0o60600,st_rdev=7)
                return original_stat(path,*args,**kwargs)
            with mock.patch.object(Path,'stat',device_stat), \
                 mock.patch.object(view.os,'major',return_value=253), \
                 mock.patch.object(view.os,'minor',return_value=7):
                self.assertEqual(view.mounts('253:7',Path(root)),['/mnt/pool','/personal/pool'])
                self.assertEqual(view.mounts('253:8',Path(root)),[])

    def test_unresolved_btrfs_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            process=Path(root)/'123';process.mkdir()
            (process/'mountinfo').write_text('24 22 0:55 / /mnt/pool ro - btrfs /absent-source ro\n')
            with self.assertRaisesRegex(view.ValidationError,'source identity'):
                view.mounts('253:7',Path(root))

    def test_rw_origin_rejected_before_scan_or_state_creation(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)/"new"
            with mock.patch.object(view, "require_host"), mock.patch.object(view, "open_device", return_value=(5, Path("/dev/fake"))), mock.patch.object(view, "dev_id", return_value="253:7"), mock.patch.object(view, "readonly", return_value=False), mock.patch.object(view.os, "close"), mock.patch.object(view, "scan") as scan:
                with self.assertRaisesRegex(view.ValidationError, "ALREADY"):
                    view.create("/dev/fake", output, True)
                self.assertFalse(output.exists())
                scan.assert_not_called()

    def test_mounted_origin_and_unrelated_holders_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            node = Path(root)/"253:7"; node.mkdir(); (node/"holders").mkdir()
            patches = [mock.patch.object(view, "dev_id", return_value="253:7"),
                       mock.patch.object(view, "readonly", return_value=True)]
            with patches[0], patches[1], mock.patch.object(view, "mounts", return_value=["/volume3", "/home"]):
                with self.assertRaisesRegex(view.ValidationError, "mounted"):
                    view.guard_device(5, sysfs=Path(root))
            (node/"holders/dm-9").mkdir()
            with mock.patch.object(view, "dev_id", return_value="253:7"), mock.patch.object(view, "readonly", return_value=True):
                with self.assertRaisesRegex(view.ValidationError, "holders"):
                    view.guard_device(5, sysfs=Path(root))

    def test_no_offline_attestation_rejected_before_host_changes(self):
        with mock.patch.object(view, "require_host") as host:
            with self.assertRaisesRegex(view.ValidationError, "offline-origin"):
                view.create("/dev/fake", "unused")
            host.assert_not_called()

    def test_remove_wrong_uuid_or_table_never_removes(self):
        state = {"name": view.PREFIX+"a"*32, "uuid": "UGACLTOOL-"+"a"*32, "table": "expected"}
        for returned_uuid, table in [("foreign", "expected"), (state["uuid"], "foreign")]:
            result = mock.Mock(returncode=0, stdout=returned_uuid)
            with mock.patch.object(view, "require_host"), mock.patch.object(view, "load_state", return_value=(Path("unused"),state)), mock.patch.object(view.subprocess, "run", return_value=result), mock.patch.object(view, "run", return_value=table) as run:
                with self.assertRaisesRegex(view.ValidationError, "differs"):
                    view.remove("unused")
                self.assertFalse(any("remove" in call.args for call in run.call_args_list))

    def test_state_symlink_and_world_readable_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            link = Path(root)/"link"; link.symlink_to(root)
            with self.assertRaises(view.ValidationError):
                view.load_state(link)
            output = Path(root)/"public"; output.mkdir(mode=0o755)
            with self.assertRaises(view.ValidationError):
                view.load_state(output)


if __name__ == "__main__":
    unittest.main()
