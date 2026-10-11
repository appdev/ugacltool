"""fnOS package lifecycle. Preserve adoption jobs and native boot services."""
import fcntl
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from fnos_oneclick import private_directory
from patch_btrfs_ugos import ValidationError

STATE = Path('/var/lib/ugacltool-oneclick/jobs')
UNIT = Path('/etc/systemd/system/ugacltool-web.service')
APP = Path('/var/apps/ugacltool/target')


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode:
        raise ValidationError('Application service operation failed')
    return result


def validate_installation(harden=False):
    actual = Path(os.environ.get('TRIM_APPDEST', str(APP))).resolve(strict=True)
    if actual != APP.resolve(strict=True):
        raise ValidationError('Package destination differs')
    if not re.fullmatch(r'/[A-Za-z0-9_./@+-]+', str(actual)):
        raise ValidationError('Unsupported package destination')
    info = actual.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid or (not harden and info.st_mode & 0o022):
        raise ValidationError('Application directory must be root-owned and not writable by other users')
    # fnpack extracts new package directories as 0775. Harden only this app's
    # newly installed code; no user files, arrays, or adoption state are visited.
    paths = [actual]
    for folder in ('scripts', 'tools', 'web'):
        directory = actual/folder
        if directory.is_symlink() or directory.stat().st_uid or (not harden and directory.stat().st_mode & 0o022):
            raise ValidationError('Application source directory is unsafe')
        paths.append(directory)
        for path in directory.rglob('*'):
            info = path.lstat()
            cache_dir = path.name == '__pycache__' and path.parent == directory
            if (not (stat.S_ISREG(info.st_mode) or (cache_dir and stat.S_ISDIR(info.st_mode)))
                    or info.st_uid or (not harden and info.st_mode & 0o022)):
                raise ValidationError('Application source file is unsafe')
            paths.append(path)
    if harden:
        for path in paths:
            path.chmod(stat.S_IMODE(path.stat().st_mode) & ~0o022)
        return validate_installation()
    return actual


def service_text():
    return ('[Unit]\nDescription=UGACLTOOL native adoption interface\nAfter=network.target\n'
            '[Service]\nType=simple\nUMask=0077\n'
            'ExecStart=/usr/bin/python3 -B /var/apps/ugacltool/target/scripts/fnos_oneclick_server.py '
            '--state /var/lib/ugacltool-oneclick/jobs --socket /var/apps/ugacltool/target/app.sock\n'
            'Restart=on-failure\nRestartSec=3\nTimeoutStopSec=infinity\n'
            '[Install]\nWantedBy=multi-user.target\n')


def install_unit():
    text = service_text()
    if UNIT.exists() or UNIT.is_symlink():
        info = UNIT.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022 or UNIT.read_text() != text:
            raise ValidationError('Existing web service is not owned by this application')
        return
    fd = os.open(UNIT, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text); stream.flush(); os.fsync(stream.fileno())
    run('systemctl', 'daemon-reload')


def main(action):
    if os.geteuid() != 0 or action not in ('start', 'stop', 'status', 'secure-install'):
        raise ValidationError('Root package lifecycle action required')
    if action == 'secure-install':
        validate_installation(harden=True)
        return 0
    if action == 'status':
        return 0 if run('systemctl', 'is-active', UNIT.name, check=False).returncode == 0 else 3
    if action == 'start':
        validate_installation()
        private_directory(STATE)
        install_unit()
        run('systemctl', 'enable', '--now', UNIT.name)
        if run('systemctl', 'is-active', UNIT.name).stdout.strip() != 'active':
            raise ValidationError('Application did not start')
        return 0
    # Upgrades/uninstall refuse while any worker owns the durable lock.
    # Keep original-array maintenance units and state forever; no data cleanup.
    private_directory(STATE)
    fd = os.open(STATE/'worker.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValidationError('Adoption is running; stop or upgrade after completion')
        if UNIT.exists():
            install_unit()
            run('systemctl', 'disable', '--now', UNIT.name)
    finally:
        os.close(fd)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1] if len(sys.argv) == 2 else ''))
    except (ValidationError, OSError):
        print('应用操作已停止，请确认接管任务已完成、安装路径和服务归属正确。', file=sys.stderr)
        sys.exit(1)
