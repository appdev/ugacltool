"""Admin-only fnOS gateway UI over a root-private Unix socket.

Demo serves loopback using a separate adapter with no disk-operation methods.
HTTP payloads contain selection/job IDs only; never shell commands or paths.
"""
import argparse
import errno
import fcntl
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
from urllib.parse import urlsplit

import fnos_discover as discovery
from fnos_oneclick import Jobs, LinuxAdapter
from patch_btrfs_ugos import ValidationError


PREFIX = '/app/ugacltool'
ASSETS = {'/': ('text/html; charset=utf-8', 'index.html'),
          '/app.js': ('text/javascript; charset=utf-8', 'app.js'),
          '/style.css': ('text/css; charset=utf-8', 'style.css')}


def origin_of(value, page=False):
    parts = urlsplit(value)
    if (value != value.strip() or parts.scheme not in ('http','https')
            or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.fragment or (not page and (parts.path or parts.query))):
        raise ValidationError('Invalid browser origin')
    parts.port  # Reject malformed ports before normalizing.
    if page and not (parts.path == PREFIX or parts.path.startswith(PREFIX+'/')):
        raise ValidationError('Token must be requested from the application page')
    return parts.scheme+'://'+parts.netloc.lower()


class DemoAdapter:
    def __init__(self):
        self.calls = []
        self.candidates = discovery.discover(
            disks=[{'name':'/dev/demo-system','type':'disk','serial':'DEMO-SYSTEM','model':'演示系统盘','size':64*1024**3},
                   {'name':'/dev/demo-data','type':'disk','serial':'DEMO-ARRAY-01','model':'演示数据盘','size':4*1024**4,
                    'children':[{'name':'/dev/demo-data2','type':'part','maj:min':'240:2'}]}],
            critical={'DEMO-SYSTEM'}, native_md=set(),
            reader=lambda path: {'MD_UUID':'11111111-2222-3333-4444-555555555555','MD_DEVICES':'1','MD_LEVEL':'linear'})

    def identity(self):
        return {'demo': 1}

    def validate_selection(self, selected):
        if selected not in self.candidates or not selected['eligible']:
            raise ValidationError('Invalid demo selection')

    def execute(self, stage, path, record):
        import time
        self.calls.append(stage)
        time.sleep(.25)
        if stage == 'native_apply':
            record['storage_id'] = 2


class Application:
    def __init__(self, jobs, demo=False):
        self.jobs = jobs
        self.demo = demo
        self.csrf = {}
        self.csrf_lock = threading.Lock()
        self.worker_lock = threading.Lock()
        self.stopping = False

    def token(self, uid, origin):
        with self.csrf_lock:
            key = (uid, origin)
            if key not in self.csrf:
                self.csrf[key] = secrets.token_urlsafe(32)
            return self.csrf[key]

    def valid_token(self, uid, origin, token):
        with self.csrf_lock:
            expected = self.csrf.get((uid, origin))
            return expected is not None and hmac.compare_digest(token, expected)

    def start(self, job_id, uid):
        if self.stopping:
            raise ValidationError('应用正在停止，请稍后继续')
        if not self.worker_lock.acquire(blocking=False):
            raise ValidationError('已有任务运行，请等待完成')
        def work():
            try:
                self.jobs.run(job_id, uid)
            except Exception as exc:
                from fnos_native_adopt import save
                record = self.jobs.read(job_id, uid)
                if record['state'] != 'done':
                    record.update(state='attention', error_type=type(exc).__name__,
                                  message='任务已停止并保留记录，请核对阵列与代码版本后继续')
                    save(self.jobs.path(job_id)/'job.json', record)
            finally:
                self.worker_lock.release()
        thread = threading.Thread(target=work, daemon=False)
        thread.start()

    def candidates(self):
        return self.jobs.adapter.candidates if self.demo else discovery.discover()


class Handler(BaseHTTPRequestHandler):
    server_version = 'ugacltool'
    def log_message(self, *args):
        pass

    def principal(self):
        if self.server.app.demo:
            if self.client_address[0] != '127.0.0.1':
                raise ValidationError('Demo is loopback only')
            return 1000
        if not hasattr(socket, 'SO_PEERCRED'):
            raise ValidationError('Unix peer credentials unavailable')
        _, peer_uid, _ = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer_uid != 0:
            raise ValidationError('Only the root gateway peer is trusted')
        users = self.headers.get_all('X-Trim-Userid', [])
        admins = self.headers.get_all('X-Trim-Isadmin', [])
        if len(users) != 1 or len(admins) != 1 or admins[0] != 'true' or not re.fullmatch('[1-9][0-9]{0,9}', users[0]):
            raise ValidationError('需要飞牛管理员登录')
        return int(users[0])

    def route(self):
        if '?' in self.path or '#' in self.path or '%' in self.path:
            raise ValidationError('Invalid route')
        path = self.path
        if path == PREFIX:
            return '/'
        if path.startswith(PREFIX+'/'):
            path = path[len(PREFIX):]
        return path

    def send(self, status, content, content_type='application/json; charset=utf-8'):
        data = json.dumps(content, ensure_ascii=False).encode() if isinstance(content, dict) else content
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            uid = self.principal(); path = self.route(); app = self.server.app
            if path in ASSETS:
                kind, name = ASSETS[path]
                self.send(200, (Path(__file__).resolve().parents[1]/'web'/name).read_bytes(), kind)
            elif path == '/api/state':
                referers = self.headers.get_all('Referer', [])
                if len(referers) != 1:
                    raise ValidationError('Application page context required')
                origin = origin_of(referers[0], page=True)
                self.send(200, {'csrf':app.token(uid,origin),'demo':app.demo, 'running':app.worker_lock.locked(), 'jobs':app.jobs.list(uid)})
            elif path == '/api/arrays':
                self.send(200, {'arrays':[discovery.public_candidate(c) for c in app.candidates()]})
            else:
                self.send(404, {'error':'页面不存在'})
        except (ValidationError, ValueError, OSError, KeyError):
            self.send(403, {'error':'无法通过管理员身份或存储安全检查'})

    def do_POST(self):
        gate = 'administrator'
        try:
            uid = self.principal(); app = self.server.app; path = self.route()
            gate = 'origin-csrf'
            origins = self.headers.get_all('Origin', [])
            hosts = self.headers.get_all('Host', [])
            tokens = self.headers.get_all('X-Oneclick-CSRF', [])
            # The fnOS gateway rewrites Host for its Unix backend. Bind the
            # secret to the browser page origin at issuance instead. The app
            # emits no CORS permission: another origin cannot read this token.
            if (len(origins)!=1 or len(hosts)!=1 or len(tokens)!=1
                    or not app.valid_token(uid, origin_of(origins[0]), tokens[0])):
                raise ValidationError('写请求未通过同源检查')
            gate = 'request-body'
            if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
                raise ValidationError('Unsupported request body')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=4096:
                raise ValidationError('Request body size refused')
            body = json.loads(self.rfile.read(int(lengths[0])))
            if not isinstance(body, dict):
                raise ValidationError('Invalid request')
            if app.worker_lock.locked():
                raise ValidationError('已有任务运行，请等待完成')
            gate = 'array-selection'
            if path in ('/api/adopt', '/api/check') and set(body)=={'selection'}:
                if not isinstance(body['selection'],str) or not re.fullmatch('[0-9a-f]{64}',body['selection']):
                    raise ValidationError('Invalid selection')
                candidates = [c for c in app.candidates() if c['selection']==body['selection'] and c['eligible']]
                if len(candidates)!=1:
                    raise ValidationError('阵列已变化，请重新扫描选择')
                if path == '/api/check':
                    # Selection checks are read-only: no job, assembly, LV
                    # activation, mount, or original-array write is performed.
                    gate = 'readonly-identity'
                    app.jobs.adapter.validate_selection(candidates[0])
                    self.send(200, {'verified':True, 'selection':body['selection']})
                    return
                gate = 'create-job'
                record = app.jobs.create(candidates[0], uid)
            elif path == '/api/resume' and set(body)=={'job'}:
                gate = 'resume-owner'
                record = app.jobs.read(body['job'],uid)
            else:
                raise ValidationError('Unknown action')
            gate = 'start-worker'
            app.start(record['id'],uid)
            self.send(202, {'job':app.jobs.public(record)})
        except (ValidationError, ValueError, OSError, KeyError, TypeError):
            if not self.server.app.demo:
                # Fixed diagnostic code only. Never log headers, CSRF tokens,
                # credentials, selected identities, private paths, or stderr.
                print('ugacltool: request refused at '+gate, file=sys.stderr, flush=True)
            self.send(409, {'error':'操作已停止：身份、阵列选择或任务状态未通过检查，请重新扫描核对'})


class UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def remove_stale_socket(path):
    """Remove only a root-owned dead socket, never a file or active service."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0:
        raise ValidationError('Existing path is not an owned socket')
    with socket.socket(socket.AF_UNIX) as probe:
        probe.settimeout(1)
        try:
            probe.connect(str(path))
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise ValidationError('Socket state cannot be established') from exc
        else:
            raise ValidationError('Gateway socket is already serving')
    if path.lstat() != before:
        raise ValidationError('Socket changed during inspection')
    path.unlink()


def serve(root, demo=False, port=18742, socket_path=None):
    lock_fd = None
    socket_identity = None
    path = None
    if demo:
        app = Application(Jobs(root, DemoAdapter()), demo=True)
        server = ThreadingHTTPServer(('127.0.0.1',port), Handler)
    else:
        if os.geteuid()!=0 or socket_path is None:
            raise ValidationError('Production requires a root-private fnOS gateway socket')
        jobs = Jobs(root, LinuxAdapter())
        lock_fd = os.open(jobs.root/'server.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        path = Path(socket_path).absolute()
        # fnOS exposes a root-owned target symlink. Resolve the parent only;
        # the socket itself must still be inspected with lstat, never followed.
        parent = path.parent.resolve(strict=True)
        if parent.stat().st_uid or parent.stat().st_mode & 0o022:
            raise ValidationError('Unsafe gateway socket directory')
        for ancestor in (path.parent, *path.parent.parents):
            info = ancestor.lstat()
            if info.st_uid or (not stat.S_ISLNK(info.st_mode)
                    and (info.st_mode & 0o002 or (info.st_mode & 0o020 and info.st_gid != 0))):
                raise ValidationError('Untrusted gateway path ancestor')
        path = parent/path.name
        remove_stale_socket(path)
        app = Application(jobs)
        server = UnixHTTPServer(str(path), Handler)
        os.chmod(path,0o600)
        socket_identity = path.stat()
    server.app = app
    def stop(signum, frame):
        app.stopping = True
        # shutdown must run outside the serving thread. Active storage workers
        # remain alive and finish; no KILL or forced unmount is used.
        threading.Thread(target=server.shutdown, daemon=True).start()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if path is not None and path.exists():
            current = path.lstat()
            if current.st_ino == socket_identity.st_ino and current.st_dev == socket_identity.st_dev:
                path.unlink()
        if lock_fd is not None:
            os.close(lock_fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo',action='store_true')
    parser.add_argument('--port',type=int,default=18742)
    parser.add_argument('--state',type=Path,default=Path('/var/lib/ugacltool-oneclick/jobs'))
    parser.add_argument('--socket',type=Path)
    args=parser.parse_args()
    if not args.demo and args.port!=18742:
        parser.error('Production has no TCP port option')
    serve(args.state,args.demo,args.port,args.socket)
