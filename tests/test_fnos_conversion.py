from pathlib import Path
import sys
import os
import struct
import tempfile
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import convert_fnos as convert
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_btrfs_ugos import superblock, SIZE
from test_fnos_storage import config


class ConversionGuards(unittest.TestCase):
    def test_rejected_preflight_closes_device_before_any_state_or_runtime_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);fd=os.open(root/'device.raw',os.O_RDWR|os.O_CREAT,0o600)
            with mock.patch.object(convert.view,'require_host'), \
                 mock.patch.object(convert.storage.disk_safety,'check_config',return_value={}), \
                 mock.patch.object(convert.storage.disk_safety,'array_members'), \
                 mock.patch.object(convert.storage,'check_source',return_value=(fd,None,None,{})), \
                 mock.patch.object(convert.view,'guard_device',side_effect=convert.ValidationError('mounted')), \
                 mock.patch.object(convert.view,'run') as run:
                with self.assertRaisesRegex(convert.ValidationError,'mounted'):
                    convert.convert({'pools':[{'id':'pool1'}]},'pool1','unused',root/'new')
                self.assertFalse((root/'new').exists());run.assert_not_called()
                with self.assertRaises(OSError):os.fstat(fd)
    def test_pending_log_is_rejected_without_replay_or_log_clearing(self):
        block=bytearray(4096)
        convert.reject_pending_log({65536:bytes(block)})
        struct.pack_into('<Q',block,0x60,4096)
        with self.assertRaisesRegex(convert.ValidationError,'Pending'):
            convert.reject_pending_log({65536:bytes(block)})
    def test_evidence_rejects_wrong_origin_kernel_code_failed_integrity(self):
        pool={'id':'pool1','fsid':'fs','device_uuid':'dev','size':4096,'md_uuid':'md','lv_uuid':'lv'}
        blocks={65536:b'original'}
        evidence={'pool':'pool1','kernel':'kernel','origin':{k:pool[k] for k in ('fsid','device_uuid','size','md_uuid','lv_uuid')},
                  'disk_safety':config()['disk_safety'],
                  'patch_core_sha256':'code','original_superblocks_sha256':convert.headers_hash(blocks),
                  'original_writes':False,'offline_check_passed':True,'persistent_reactivation_readback':True,
                  'original_superblocks_unchanged':True,'snapshot_removed':True,'offline_check':{'rc':0},
                  'write_probe':{'write_fsync_read_rename_links_xattr':True}}
        convert.check_evidence(pool,blocks,evidence,'kernel','code',config()['disk_safety'])
        for key,value in [('kernel','other'),('origin',{}),('offline_check_passed',False),
                          ('original_writes',True),('patch_core_sha256','other'),('offline_check',{'rc':1}),
                          ('disk_safety',{})]:
            with self.subTest(key=key),self.assertRaises(convert.ValidationError):
                convert.check_evidence(pool,blocks,{**evidence,key:value},'kernel','code',config()['disk_safety'])
        with self.assertRaises(convert.ValidationError):
            convert.check_evidence(pool,{65536:b'changed'},evidence,'kernel','code',config()['disk_safety'])

    def test_resume_allows_only_exact_original_patched_byte_choices(self):
        original=b'ABC012XYZ';patched=b'ABC987XYZ'
        for current in (original,patched,b'ABC912XYZ'):
            self.assertTrue(convert.acceptable_resume(current,original,patched))
        for current in (b'BBC912XYZ',b'ABC412XYZ',b'ABC912XY'):
            self.assertFalse(convert.acceptable_resume(current,original,patched))

    def test_interrupted_mirror_write_resumes_without_changing_other_sectors(self):
        blocks={x:superblock(x) for x in convert.MIRRORS[:2]}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'offline.raw'
            fd=os.open(source,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                os.ftruncate(fd,SIZE)
                for offset,data in blocks.items():os.pwrite(fd,data,offset)
                os.pwrite(fd,b'KEEP ADJACENT DATA',65536-18)
                state={'written':[]}
                original=convert._pwrite_all
                calls=[]
                def fail_second(fd,data,offset):
                    calls.append(offset)
                    if len(calls)==2:raise OSError('simulated interruption')
                    original(fd,data,offset)
                with mock.patch.object(convert,'_pwrite_all',side_effect=fail_second):
                    with self.assertRaises(OSError):convert.write_mirrors(fd,blocks,root,state)
                self.assertEqual(state['written'],[convert.MIRRORS[1]])
                convert.write_mirrors(fd,blocks,root,state)
                self.assertEqual(set(state['written']),set(blocks))
                self.assertEqual(os.pread(fd,18,65536-18),b'KEEP ADJACENT DATA')
                for offset,data in blocks.items():
                    self.assertEqual(os.pread(fd,4096,offset),convert.patch_superblock(data,offset))
            finally:os.close(fd)


if __name__=='__main__':unittest.main()
