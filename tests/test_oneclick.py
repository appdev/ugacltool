import copy
import fcntl
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import fnos_discover as discover
import fnos_oneclick as oneclick
import fnos_oneclick_server as web
import validate_real_cow as cow
import fnos_app_lifecycle as lifecycle
from patch_btrfs_ugos import ValidationError


def devices():
    return [{'name':'/dev/system','type':'disk','serial':'SYNTH-SYSTEM','model':'SYNTH-SSD','size':64*1024**3},
            {'name':'/dev/data','type':'disk','serial':'SYNTH-DATA','model':'SYNTH-HDD','size':4*1024**3,
             'children':[{'name':'/dev/data2','type':'part','maj:min':'240:2'}]}]


def arrays(disks=None, critical=None, count='1', native=None):
    return discover.discover(devices() if disks is None else disks,
        {'SYNTH-SYSTEM'} if critical is None else critical,
        lambda p:{'MD_UUID':'11111111-2222-3333-4444-555555555555','MD_LEVEL':'linear','MD_DEVICES':count},
        set() if native is None else native)


class DiscoveryGuards(unittest.TestCase):
    def test_discovery_is_readonly_and_does_not_infer_permission(self):
        with mock.patch.object(discover.subprocess,'run') as command:
            candidate=arrays()[0]
        command.assert_not_called()
        self.assertTrue(candidate['eligible'])
        self.assertEqual(candidate['protected'][0]['role'],'system')
        self.assertNotIn('partition',discover.public_candidate(candidate)['members'][0])

    def test_missing_member_or_system_disk_or_native_array_is_blocked(self):
        uuid='11111111-2222-3333-4444-555555555555'
        for candidates in (arrays(count='2'), arrays(critical={'SYNTH-DATA'}), arrays(native={uuid})):
            self.assertFalse(candidates[0]['eligible'])

    def test_duplicate_serial_and_unknown_system_fail(self):
        ds=devices();ds[1]['serial']=ds[0]['serial']
        for ds,critical in ((ds,None),(devices(),{'missing'}),(devices(),set())):
            with self.assertRaises(ValidationError):arrays(ds,critical)

    def test_capacity_model_or_serial_change_invalidates_selection_before_device_access(self):
        selected=arrays()[0]
        for key,value in (('size',5*1024**3),('serial','SYNTH-REPLACED'),('model','SYNTH-NEW')):
            ds=devices();ds[1][key]=value
            with mock.patch.object(discover.os,'stat') as access:
                with self.assertRaises(ValidationError):discover.recheck_selection(selected,arrays(ds))
            access.assert_not_called()

    def test_partition_replacement_and_modified_selection_fail(self):
        selected=arrays()[0]
        with mock.patch.object(discover.os,'stat',return_value=mock.Mock(st_mode=stat.S_IFBLK,st_rdev=0)), \
                mock.patch.object(discover.os,'major',return_value=240), mock.patch.object(discover.os,'minor',return_value=3):
            with self.assertRaises(ValidationError):discover.recheck_selection(selected,[selected])
        selected['members'][0]['size']+=1
        with self.assertRaises(ValidationError):discover.recheck_selection(selected,[selected])

    def test_md_export_rejects_duplicate_or_invalid_uuid(self):
        self.assertEqual(discover.export_fields('MD_UUID=11111111:22223333:44445555:55555555')['MD_UUID'],
                         '11111111-2222-3333-4444-555555555555')
        for text in ('MD_UUID=no','MD_UUID=1\nMD_UUID=2'):
            with self.assertRaises((ValidationError,ValueError)):discover.export_fields(text)


class Adapter(web.DemoAdapter):
    def execute(self,stage,path,record):
        self.calls.append(stage)
        if stage==getattr(self,'fail',None):raise ValidationError('Synthetic refusal')
        if stage=='native_apply':record['storage_id']=2


class WorkflowGuards(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.adapter=Adapter();self.jobs=oneclick.Jobs(Path(self.tmp.name).resolve()/'jobs',self.adapter)

    def create(self):return self.jobs.create(self.adapter.candidates[0],1000)

    def test_failed_cow_never_enters_original_conversion_and_can_resume_same_job(self):
        record=self.create();self.adapter.fail='cow'
        with self.assertRaises(ValidationError):self.jobs.run(record['id'],1000)
        self.assertEqual(self.adapter.calls,['prepare','cow'])
        saved=self.jobs.read(record['id'],1000)
        self.assertEqual(saved['state'],'attention');self.assertEqual(saved['completed'],['prepare'])
        self.adapter.fail=None;result=self.jobs.run(record['id'],1000)
        self.assertEqual(result['state'],'done');self.assertEqual(result['storage_id'],2)
        calls=list(self.adapter.calls);self.jobs.run(record['id'],1000);self.assertEqual(self.adapter.calls,calls)

    def test_any_failed_stage_prevents_all_later_stages(self):
        for stage in oneclick.STAGES:
            record=self.create();self.adapter.calls=[];self.adapter.fail=stage
            with self.assertRaises(ValidationError):self.jobs.run(record['id'],1000)
            self.assertEqual(self.adapter.calls,list(oneclick.STAGES[:oneclick.STAGES.index(stage)+1]))

    def test_wrong_owner_invalid_job_and_symlink_are_rejected(self):
        record=self.create()
        with self.assertRaises(ValidationError):self.jobs.read(record['id'],1001)
        for invalid in ('../other','0'*31,'/etc/passwd'):
            with self.assertRaises(ValidationError):self.jobs.path(invalid)
        link=self.jobs.root/('a'*32);link.symlink_to(self.jobs.path(record['id']),target_is_directory=True)
        with self.assertRaises(ValidationError):self.jobs.read(link.name,1000)

    def test_changed_code_or_skipped_stage_rejected_before_actions(self):
        record=self.create()
        with mock.patch.object(self.adapter,'identity',return_value={'demo':2}):
            with self.assertRaises(ValidationError):self.jobs.run(record['id'],1000)
        self.assertFalse(self.adapter.calls)
        record['completed']=['prepare','convert'];oneclick.adoption.save(self.jobs.path(record['id'])/'job.json',record)
        with self.assertRaises(ValidationError):self.jobs.run(record['id'],1000)
        self.assertFalse(self.adapter.calls)

    def test_process_lock_prevents_device_actions(self):
        record=self.create();fd=os.open(self.jobs.root/'worker.lock',os.O_CREAT|os.O_RDWR,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.jobs.run(record['id'],1000)
            self.assertFalse(self.adapter.calls)
        finally:os.close(fd)

    def test_native_layout_refuses_existing_reserved_directory_file_or_link(self):
        for kind in ('home','team','file','link'):
            with tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)
                if kind=='home':(p/'1000').mkdir()
                if kind=='team':(p/'@team').mkdir()
                if kind=='file':(p/'old.bin').write_bytes(b'old')
                if kind=='link':(p/'old-link').symlink_to('/missing')
                with self.assertRaises(ValidationError):cow.check_native_layout(p,1000)
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'old-directory').mkdir();self.assertEqual(cow.check_native_layout(p,1000),1)


class WebGuards(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.adapter=Adapter()
        self.jobs=oneclick.Jobs(Path(self.tmp.name).resolve()/'jobs',self.adapter)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),web.Handler)
        self.server.app=web.Application(self.jobs,demo=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
        self.addCleanup(self.finish)
        self.token=self.request('/api/state')['csrf']

    def finish(self):self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()

    def request(self,path,body=None,origin=None,token=None,host=None):
        headers={'Referer':self.base+web.PREFIX};data=None
        if body is not None:
            data=json.dumps(body).encode();headers.update({'Content-Type':'application/json','Origin':self.base if origin is None else origin,'X-Oneclick-CSRF':self.token if token is None else token})
        if host is not None:headers['Host']=host
        with urlopen(Request(self.base+path,data=data,headers=headers),timeout=5) as r:return json.load(r)

    def test_cross_origin_wrong_csrf_and_client_paths_refused_before_job_creation(self):
        selection=self.adapter.candidates[0]['selection']
        for body,origin,token in (({'selection':selection},'http://attacker.invalid',None),
                                   ({'selection':selection},None,'bad'),
                                   ({'selection':selection,'config':'/etc/passwd'},None,None),
                                   ({'selection':'/dev/sda'},None,None)):
            for action in ('/api/adopt','/api/check'):
                with self.assertRaises(HTTPError) as exc:self.request(action,body,origin,token)
                self.assertEqual(exc.exception.code,409)
        self.assertEqual(self.jobs.list(1000),[]);self.assertFalse(self.adapter.calls)

    def test_selection_check_validates_without_creating_job_or_disk_actions(self):
        choice=self.adapter.candidates[0]['selection']
        with mock.patch.object(self.adapter,'validate_selection',wraps=self.adapter.validate_selection) as validate:
            self.assertEqual(self.request('/api/check',{'selection':choice}),{'verified':True,'selection':choice})
            validate.assert_called_once_with(self.adapter.candidates[0])
        self.assertFalse(self.adapter.calls);self.assertEqual(self.jobs.list(1000),[])
        with mock.patch.object(self.adapter,'validate_selection',side_effect=ValidationError('identity changed')):
            with self.assertRaises(HTTPError):self.request('/api/check',{'selection':choice})
        self.assertFalse(self.adapter.calls);self.assertEqual(self.jobs.list(1000),[])

    def test_gateway_rewritten_host_still_requires_token_bound_to_browser_origin(self):
        choice=self.adapter.candidates[0]['selection']
        self.assertTrue(self.request('/api/check',{'selection':choice},host='internal-gateway.invalid')['verified'])
        with self.assertRaises(HTTPError):
            self.request('/api/check',{'selection':choice},origin='http://attacker.invalid',host='internal-gateway.invalid')
        self.assertEqual(self.jobs.list(1000),[]);self.assertFalse(self.adapter.calls)

    def test_tokens_are_bound_to_account_and_origin_and_missing_page_context_refused(self):
        app=self.server.app
        self.assertNotEqual(app.token(1000,self.base),app.token(1000,'http://other.invalid'))
        self.assertFalse(app.valid_token(1001,self.base,self.token))
        with self.assertRaises(HTTPError):urlopen(self.base+'/api/state',timeout=5)
        for origin in ('http://user:pass@host.invalid','http://host.invalid/path','http://host.invalid?query'):
            with self.assertRaises(ValidationError):web.origin_of(origin)

    def test_other_user_job_cannot_be_resumed(self):
        job=self.jobs.create(self.adapter.candidates[0],1001)
        with self.assertRaises(HTTPError):self.request('/api/resume',{'job':job['id']})
        self.assertFalse(self.adapter.calls)

    def test_unix_gateway_requires_root_peer_and_unique_admin_headers(self):
        from email.message import Message
        h=object.__new__(web.Handler);h.server=mock.Mock();h.server.app.demo=False
        h.headers=Message();h.headers['X-Trim-Userid']='1000';h.headers['X-Trim-Isadmin']='true'
        h.connection=mock.Mock();h.connection.getsockopt.return_value=struct.pack('3i',10,0,0)
        with mock.patch.object(web.socket,'SO_PEERCRED',17,create=True):
            self.assertEqual(h.principal(),1000)
            h.connection.getsockopt.return_value=struct.pack('3i',10,1000,1000)
            with self.assertRaises(ValidationError):h.principal()
            h.connection.getsockopt.return_value=struct.pack('3i',10,0,0)
            h.headers['X-Trim-Isadmin']='true'
            with self.assertRaises(ValidationError):h.principal()

    def test_demo_execution_has_no_linux_adapter_capability(self):
        with mock.patch.object(oneclick.LinuxAdapter,'execute') as real:
            response=self.request('/api/adopt',{'selection':self.adapter.candidates[0]['selection']})
            for i in range(50):
                import time
                if not self.server.app.worker_lock.locked():break
                time.sleep(.02)
            job=self.jobs.read(response['job']['id'],1000)
            self.assertEqual(job['state'],'done')
            real.assert_not_called()


class LifecycleGuards(unittest.TestCase):
    def test_running_source_change_stops_before_next_action(self):
        with mock.patch.object(oneclick.LinuxAdapter,'source_identity',return_value={'code':'one'}):
            adapter=oneclick.LinuxAdapter()
        with mock.patch.object(oneclick.LinuxAdapter,'source_identity',return_value={'code':'two'}):
            with self.assertRaises(ValidationError):adapter.identity()

    def test_owned_socket_cleanup_refuses_files_symlinks_and_live_servers(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'app.sock';p.write_bytes(b'keep')
            with self.assertRaises(ValidationError):web.remove_stale_socket(p)
            self.assertEqual(p.read_bytes(),b'keep')
            link=Path(tmp)/'link.sock';link.symlink_to(p)
            with self.assertRaises(ValidationError):web.remove_stale_socket(link)
            import socket
            endpoint=Path(tmp)/'live.sock'
            with socket.socket(socket.AF_UNIX) as s:
                s.bind(str(endpoint));s.listen(1)
                with mock.patch.object(web.os,'geteuid',return_value=0), \
                        mock.patch.object(Path,'lstat',return_value=mock.Mock(st_mode=stat.S_IFSOCK,st_uid=0)):
                    with self.assertRaises(ValidationError):web.remove_stale_socket(endpoint)
                self.assertTrue(endpoint.exists())

    def test_app_stop_during_adoption_does_not_stop_any_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp).resolve()/'jobs';oneclick.private_directory(state)
            fd=os.open(state/'worker.lock',os.O_CREAT|os.O_RDWR,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with mock.patch.object(lifecycle,'STATE',state),mock.patch.object(lifecycle.os,'geteuid',return_value=0), \
                        mock.patch.object(lifecycle,'run') as run:
                    with self.assertRaises(ValidationError):lifecycle.main('stop')
                    run.assert_not_called()
            finally:os.close(fd)

    def test_service_does_not_kill_or_depend_on_disappearing_package_state(self):
        unit=lifecycle.service_text()
        self.assertIn('TimeoutStopSec=infinity',unit)
        self.assertIn('--state /var/lib/ugacltool-oneclick/jobs',unit)
        self.assertNotIn('ExecStop=',unit)
        self.assertNotIn('KillSignal=SIGKILL',unit)


if __name__=='__main__':unittest.main()
