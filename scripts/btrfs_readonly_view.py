#!/usr/bin/env python3
"""Metadata-only, read-only Linux device-mapper view of an OFFLINE UGOS device.

Never assembles arrays, changes source RO flags, unmounts users' filesystems,
repairs Btrfs, or writes an origin. Requires root, dmsetup and losetup.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import uuid

from patch_btrfs_ugos import (ValidationError, MIRRORS, SUPER_SIZE, scan,
                             patch_superblock, source_size, validate_patch_scope)

BLKROGET = 0x125E
BLKSSZGET = 0x1268
PREFIX = "ugacltool-ro-"


def run(*args, input=None):
    p = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30)
    if p.returncode:
        raise ValidationError("%s failed: %s" % (args[0], p.stderr.strip()))
    return p.stdout.strip()


def dev_id(fd):
    value = os.fstat(fd)
    if not stat.S_ISBLK(value.st_mode):
        raise ValidationError("Expected the final Btrfs block device, not a file/member disk")
    return "%d:%d" % (os.major(value.st_rdev), os.minor(value.st_rdev))


def readonly(fd):
    return struct.unpack("=I", fcntl.ioctl(fd, BLKROGET, bytes(4)))[0] == 1


def mounts(identity, proc=Path("/proc")):
    """Look in all visible processes' namespaces, including bind mounts.

    A disappearing process is harmless. Inaccessible mountinfo fails closed.
    Linux root must have visibility of the host's process/mount namespaces.
    """
    result = set()
    for path in proc.glob("[0-9]*/mountinfo"):
        try:
            content = path.read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as exc:
            # A zombie has no fs/mount namespace and procfs returns EINVAL.
            # Do not confuse that with an inaccessible live namespace.
            if exc.errno == errno.EINVAL:
                try:
                    status = (path.parent / "status").read_text()
                except FileNotFoundError:
                    continue
                try:
                    os.readlink(path.parent / "ns/mnt")
                except FileNotFoundError:
                    if re.search(r"^State:\s+Z\b", status, re.M):
                        continue
            raise ValidationError("Cannot inspect mount namespaces: %s" % exc) from exc
        for line in content.splitlines():
            fields = line.split()
            if len(fields) > 5 and fields[2] == identity:
                result.add(fields[4])
                continue
            # Btrfs mountinfo uses an anonymous filesystem device (0:N), not
            # the block device's rdev. Resolve its reported source in that
            # process's root as well as the host; never equate 0:N to an LV.
            if '-' in fields:
                separator = fields.index('-')
                if fields[separator+1] != 'btrfs':
                    continue
                source = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[separator+2])
                matched = False
                resolved = False
                for candidate in (path.parent/'root'/source.lstrip('/'), Path(source)):
                    try:
                        value = candidate.stat()
                    except (FileNotFoundError, NotADirectoryError, ProcessLookupError):
                        continue
                    except OSError as exc:
                        raise ValidationError('Cannot resolve Btrfs mount source') from exc
                    if stat.S_ISBLK(value.st_mode):
                        resolved = True
                        matched |= '%d:%d' % (os.major(value.st_rdev), os.minor(value.st_rdev)) == identity
                if not resolved:
                    raise ValidationError('Cannot establish Btrfs mount source identity')
                if matched:
                    result.add(fields[4])
    return sorted(result)


def guard_device(fd, allowed_holders=(), sysfs=Path("/sys/dev/block")):
    identity = dev_id(fd)
    if not readonly(fd):
        raise ValidationError("Origin must ALREADY be kernel read-only; no flags changed")
    node = (sysfs / identity).resolve(strict=True)
    guard_loop_aliases(node)
    guard_storage_graph(node)
    if any((node / "holders").iterdir()):
        unexpected = {p.name for p in (node / "holders").iterdir()} - set(allowed_holders)
        if unexpected:
            raise ValidationError("Device has holders: " + ",".join(sorted(unexpected)))
    if any(p.is_dir() and (p / "partition").exists() for p in node.iterdir()):
        raise ValidationError("Whole disks with partitions are not final Btrfs devices")
    used = mounts(identity)
    if used:
        raise ValidationError("Device is mounted (including other namespaces): " + ",".join(used))
    sector = struct.unpack("=I", fcntl.ioctl(fd, BLKSSZGET, bytes(4)))[0]
    if sector not in (512, 4096) or source_size(fd) % sector:
        raise ValidationError("Only sector-aligned 512/4096-byte devices are supported")
    return identity


def guard_loop_aliases(node, blocks=Path('/sys/block')):
    backing = node / 'loop/backing_file'
    if not backing.exists():
        return
    try:
        value = os.stat(backing.read_text().strip())
        if not stat.S_ISREG(value.st_mode):
            raise ValidationError('Loop origin must use a stable regular fixture/metadata file')
        for other in blocks.glob('loop*/loop/backing_file'):
            if other.parent.parent.name == node.name:
                continue
            try:
                duplicate = os.stat(other.read_text().strip())
            except FileNotFoundError:
                continue  # Another loop was detached.
            if (duplicate.st_dev, duplicate.st_ino) == (value.st_dev, value.st_ino):
                raise ValidationError('Backing file has another loop alias: '+other.parent.parent.name)
    except OSError as exc:
        raise ValidationError('Cannot establish loop backing identity: '+str(exc)) from exc


def guard_storage_graph(node, seen=None):
    """Only verified linear LVM/DM -> healthy readonly MD -> disk layouts.

    No cache/thin/snapshot/crypt or native Btrfs RAID interpretation is guessed.
    Loop-backed fixtures are checked separately and do not traverse their host FS.
    """
    seen = set() if seen is None else seen
    node = node.resolve(strict=True)
    if node in seen:
        return
    seen.add(node)
    if node.name.startswith('bcache'):
        raise ValidationError('Bcache origin requires a separately verified offline cache procedure')
    if (node/'dm').is_dir():
        name = (node/'dm/name').read_text().strip()
        rows = run('dmsetup','table',name).splitlines()
        if not rows or any(len(row.split())<3 or row.split()[2]!='linear' for row in rows):
            raise ValidationError('Only linear device-mapper backing is supported')
    if (node/'md').is_dir():
        md = node/'md'
        if (md/'array_state').read_text().strip()!='readonly':
            raise ValidationError('Underlying MD must be healthy and already readonly')
        degraded = md/'degraded'
        if degraded.exists():
            if degraded.read_text().strip()!='0':
                raise ValidationError('Underlying MD is degraded')
        else:
            # Nonredundant MD linear/raid0 does not expose degraded. Require
            # every expected member instead of guessing health or failing on
            # an attribute the kernel does not provide for this personality.
            level = (md/'level').read_text().strip()
            expected = int((md/'raid_disks').read_text().strip())
            members = list((node/'slaves').iterdir())
            if level not in ('linear','raid0') or expected<=0 or len(members)!=expected:
                raise ValidationError('Cannot establish complete nonredundant MD member set')
        action = md/'sync_action'
        if action.exists() and action.read_text().strip()!='idle':
            raise ValidationError('Underlying MD recovery/resync must be idle')
    slaves = node/'slaves'
    if slaves.exists():
        for slave in slaves.iterdir():
            guard_storage_graph(slave,seen)


def linear_table(size, origin, metadata, offsets):
    """DM uses 512-byte sectors even when the backing device uses 4K sectors."""
    if size % 4096 or not re.fullmatch(r"\d+:\d+", origin) or not re.fullmatch(r"\d+:\d+", metadata):
        raise ValidationError("Invalid mapping geometry or device identity")
    expected = [x for x in MIRRORS if x + SUPER_SIZE <= size]
    if list(offsets) != expected or not expected:
        raise ValidationError("Mapping must replace exactly all fitting mirrors")
    rows, position = [], 0
    for index, offset in enumerate(expected):
        start = offset // 512
        if start > position:
            rows.append("%d %d linear %s %d" % (position, start-position, origin, position))
        rows.append("%d 8 linear %s %d" % (start, metadata, index*8))
        position = start + 8
    if position < size // 512:
        rows.append("%d %d linear %s %d" % (position, size//512-position, origin, position))
    return "\n".join(rows)


def open_device(source):
    # Permit by-id/mapper aliases but open the resolved inode without following
    # another symlink. The FD, not the supplied pathname, defines the origin.
    resolved = Path(source).resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        dev_id(fd)
        return fd, resolved
    except BaseException:
        os.close(fd)
        raise


def inspect(source):
    fd, resolved = open_device(source)
    try:
        identity = dev_id(fd)
        infos, _ = scan(fd)
        for info in infos:
            validate_patch_scope(info)
        reasons = []
        try:
            guard_device(fd)
        except (ValidationError, OSError) as exc:
            reasons.append(str(exc))
        return {"source": str(resolved), "identity": identity, "mirrors": infos,
                "ready": not reasons, "blocking_reasons": reasons,
                "origin_writes": False, "offline_origin_attestation_required": True}
    finally:
        os.close(fd)


def save_state(root, state):
    # State is our private, newly-created directory. Keep partial state so an
    # interrupted operation can be inspected/removed; never delete evidence.
    temporary = root / ("state-" + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream, indent=2)
        stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, root / "state.json")
    fd = os.open(root, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_host():
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise ValidationError("Run as root in the Linux HOST namespace, not a container")
    if os.readlink("/proc/self/ns/mnt") != os.readlink("/proc/1/ns/mnt"):
        raise ValidationError("Use the host mount namespace")
    if Path('/.dockerenv').exists() or Path('/run/.containerenv').exists():
        raise ValidationError('Use the actual host; containers cannot inspect host mount ownership')
    if "linear" not in run("dmsetup", "targets").split():
        raise ValidationError("Kernel device-mapper linear target is unavailable")


def create(source, directory, offline_origin=False):
    if not offline_origin:
        raise ValidationError("--offline-origin requires an offline, stable origin under sole ownership")
    require_host()
    fd, resolved = open_device(source)
    root = Path(directory).absolute()
    state = None
    try:
        identity = guard_device(fd)  # Before ANY durable side effect.
        infos, blocks = scan(fd)
        for info in infos:
            validate_patch_scope(info)
        size = source_size(fd)
        patched = b"".join(patch_superblock(blocks[x], x) for x in sorted(blocks))
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        token = uuid.uuid4().hex
        state = {"version": 1, "name": PREFIX+token, "uuid": "UGACLTOOL-"+token,
                 "source": str(resolved), "origin_identity": identity, "size": size,
                 "fsid": infos[0]["fsid"], "metadata": str(root / "superblocks.bin"),
                 "metadata_sha256": hashlib.sha256(patched).hexdigest(),
                 "metadata_bytes": len(patched), "loop": None, "table": None,
                 "phase": "prepared", "origin_writes": False}
        save_state(root, state)
        meta_fd = os.open(root / "superblocks.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(meta_fd, "wb") as stream:
            stream.write(patched); stream.flush(); os.fsync(stream.fileno())
        state["loop"] = run("losetup", "--find", "--show", "--read-only", state["metadata"])
        save_state(root, state)
        loop_fd, _ = open_device(state["loop"])
        try:
            meta_identity = guard_device(loop_fd)
            if source_size(loop_fd) != len(patched):
                raise ValidationError("Metadata loop size mismatch")
        finally:
            os.close(loop_fd)
        state["metadata_identity"] = meta_identity
        state["table"] = linear_table(size, identity, meta_identity, sorted(blocks))
        state["phase"] = "mapping_requested"
        save_state(root, state)
        guard_device(fd)
        if scan(fd)[1] != blocks:
            raise ValidationError("Origin changed before activation")
        run("dmsetup", "create", state["name"], "--uuid", state["uuid"],
            "--readonly", "--noudevsync", "--table", state["table"])
        run("dmsetup", "mknodes", state["name"])
        view_fd, view = open_device("/dev/mapper/"+state["name"])
        try:
            if not readonly(view_fd) or source_size(view_fd) != size:
                raise ValidationError("View is not read-only or size differs")
            viewed, readback = scan(view_fd)
            if b"".join(readback[x] for x in sorted(readback)) != patched:
                raise ValidationError("Compatibility view readback differs")
            if any(x["ugacl"] for x in viewed):
                raise ValidationError("View still has UGACL bit")
            holder = (Path('/sys/dev/block') / dev_id(view_fd)).resolve(strict=True).name
        finally:
            os.close(view_fd)
        guard_device(fd, allowed_holders=(holder,))
        if scan(fd)[1] != blocks:
            raise ValidationError("Origin changed during activation")
        state.update(phase="active", device="/dev/mapper/"+state["name"])
        save_state(root, state)
        return state
    except BaseException:
        if state is not None:
            state["phase"] = "incomplete"
            save_state(root, state)
        # Retain partial state. An explicit guarded remove performs teardown.
        raise
    finally:
        os.close(fd)


def load_state(directory):
    root = Path(directory).absolute()
    value = root.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o077:
        raise ValidationError("State directory must be a private root-owned real directory")
    fd = os.open(root / "state.json", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o077:
            raise ValidationError("Unsafe state file")
        with os.fdopen(fd, "r", closefd=False) as stream:
            state = json.load(stream)
    finally:
        os.close(fd)
    if (state.get("version") != 1 or not re.fullmatch(PREFIX+r"[a-f0-9]{32}", state.get("name", ""))
            or state.get("uuid") != "UGACLTOOL-"+state["name"][len(PREFIX):]
            or state.get("metadata") != str(root / "superblocks.bin")):
        raise ValidationError("Unknown or inconsistent view state")
    return root, state


def remove(directory):
    require_host()
    root, state = load_state(directory)
    if state.get('phase') == 'removed':
        return state  # Never detach a loop number reused after our teardown.
    info = subprocess.run(["dmsetup", "info", "-c", "--noheadings", "-o", "uuid", state["name"]],
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if info.returncode == 0:
        if info.stdout.strip() != state["uuid"]:
            raise ValidationError("Refuse removal: mapping UUID differs")
        if run("dmsetup", "table", state["name"]) != state["table"]:
            raise ValidationError("Refuse removal: mapping table differs")
        fd, _ = open_device("/dev/mapper/"+state["name"])
        try:
            guard_device(fd)
        finally:
            os.close(fd)
        # No --force, --deferred or lazy unmount; an in-use view stays intact.
        run("dmsetup", "remove", "--noudevsync", state["name"])
    else:
        # A generic dmsetup error must not be treated as 'already removed'.
        if any(p.read_text().strip() == state["name"] for p in Path("/sys/block").glob("dm-*/dm/name")):
            raise ValidationError("Cannot inspect existing mapping; leave it intact")
    if state.get("loop"):
        loop = Path(state["loop"])
        if not re.fullmatch(r"/dev/loop\d+", str(loop)):
            raise ValidationError("Invalid metadata loop identity")
        data = json.loads(run("losetup", "--json", "--list", "--output", "NAME,BACK-FILE,RO", str(loop)))
        records = data.get("loopdevices", [])
        if records:
            record = records[0]
            if (len(records) != 1 or record["name"] != str(loop) or not record["ro"]
                    or Path(record["back-file"]).resolve() != Path(state["metadata"]).resolve()
                    or hashlib.sha256(Path(state["metadata"]).read_bytes()).hexdigest() != state["metadata_sha256"]):
                raise ValidationError("Refuse detach: metadata loop identity differs")
            fd, _ = open_device(loop)
            try:
                guard_device(fd)
            finally:
                os.close(fd)
            run("losetup", "--detach", str(loop))
    state["phase"] = "removed"
    save_state(root, state)
    return state  # Files deliberately retained, not deleted.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("inspect"); p.add_argument("source")
    p = sub.add_parser("create"); p.add_argument("source"); p.add_argument("--state-directory", required=True)
    p.add_argument("--offline-origin", action="store_true")
    p = sub.add_parser("remove"); p.add_argument("state_directory")
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect(args.source)
        elif args.command == "create":
            result = create(args.source, args.state_directory, args.offline_origin)
        else:
            result = remove(args.state_directory)
        print(json.dumps(result, indent=2))
        return 3 if args.command == "inspect" and not result["ready"] else 0
    except (ValidationError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": str(exc), "origin_writes": False,
                          "recovery": "Inspect private state and use guarded remove if creation was interrupted"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
