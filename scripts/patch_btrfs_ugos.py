#!/usr/bin/env python3
"""Inspect UGOS Btrfs and patch a NEW offline raw image; never write a device.

This is an experimental reader-compatibility tool, not a filesystem repair or
permission/quota converter. Python 3.9+, standard library only.
"""

import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import struct
import sys
import uuid

SUPER_SIZE = 4096
MIRRORS = (65536, 67108864, 274877906944)
UGACL = 1 << 62
INCOMPAT_OFFSET = 0xBC
# Conservative first-version scope: basic single-device features through NO_HOLES.
# Native Btrfs RAID, METADATA_UUID, zoned and newer layouts are deliberately excluded.
SUPPORTED_INCOMPAT = 0x37F
SUPPORTED_COMPAT_RO = 0x3


class ValidationError(ValueError):
    pass


def _crc_table():
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        table.append(value)
    return tuple(table)


CRC_TABLE = _crc_table()


def crc32c(data):
    """Standard reflected Castagnoli CRC32C, including initial/final XOR."""
    value = 0xFFFFFFFF
    for byte in data:
        value = CRC_TABLE[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value ^ 0xFFFFFFFF


def parse_superblock(data, offset):
    if offset not in MIRRORS:
        raise ValidationError("Not a Btrfs superblock mirror offset")
    if len(data) != SUPER_SIZE:
        raise ValidationError("Truncated superblock")
    if data[0x40:0x48] != b"_BHRfS_M":
        raise ValidationError("Btrfs magic does not match")
    u64 = lambda pos: struct.unpack_from("<Q", data, pos)[0]
    u32 = lambda pos: struct.unpack_from("<I", data, pos)[0]
    if u64(0x30) != offset:
        raise ValidationError("Superblock bytenr does not match mirror position")
    csum_type = struct.unpack_from("<H", data, 0xC4)[0]
    if csum_type != 0:
        raise ValidationError("Only CRC32C superblocks are supported (csum_type=0)")
    if data[4:32] != bytes(28):
        raise ValidationError("Unexpected nonzero CRC32C checksum padding")
    if u32(0) != crc32c(data[32:]):
        raise ValidationError("Superblock CRC32C mismatch")
    sectorsize, nodesize = u32(0x90), u32(0x94)
    if (sectorsize < 4096 or sectorsize > 65536 or
            sectorsize & (sectorsize - 1) or nodesize < sectorsize or
            nodesize > 65536 or nodesize & (nodesize - 1)):
        raise ValidationError("Invalid sector/node size")
    if u64(0x70) < SUPER_SIZE + MIRRORS[0] or u64(0x78) > u64(0x70):
        raise ValidationError("Invalid filesystem byte counts")
    if u64(0xD1) < offset + SUPER_SIZE or u64(0xD9) > u64(0xD1):
        raise ValidationError("Invalid device byte counts")
    fsid = str(uuid.UUID(bytes=data[0x20:0x30]))
    if str(uuid.UUID(bytes=data[0x11B:0x12B])) != fsid:
        raise ValidationError("Device FSID differs (METADATA_UUID layout unsupported)")
    flags = u64(INCOMPAT_OFFSET)
    return {
        "offset": offset, "fsid": fsid,
        "device_uuid": str(uuid.UUID(bytes=data[0x10B:0x11B])),
        "device_id": u64(0xC9), "generation": u64(0x48),
        "total_bytes": u64(0x70), "device_total_bytes": u64(0xD1),
        "num_devices": u64(0x88), "sectorsize": sectorsize,
        "nodesize": nodesize, "super_flags": u64(0x38),
        "compat_flags": u64(0xAC), "compat_ro_flags": u64(0xB4),
        "incompat_flags": hex(flags), "ugacl": bool(flags & UGACL),
        "unsupported_incompat_flags": hex(flags & ~(SUPPORTED_INCOMPAT | UGACL)),
        "checksum_type": "crc32c", "checksum_valid": True,
    }


def validate_patch_scope(info):
    if info["num_devices"] != 1:
        raise ValidationError("Multi-device Btrfs is outside this version's scope")
    if int(info["unsupported_incompat_flags"], 16):
        raise ValidationError("Unsupported incompat flags: " + info["unsupported_incompat_flags"])
    if info["compat_flags"] or info["compat_ro_flags"] & ~SUPPORTED_COMPAT_RO:
        raise ValidationError("Unsupported compat/compat_ro flags")
    if info["super_flags"] & ~1:
        raise ValidationError("Unsupported superblock flags (error/seeding/etc.)")
    if info["total_bytes"] != info["device_total_bytes"]:
        raise ValidationError("Single-device filesystem/device sizes differ")
    if not info["ugacl"]:
        raise ValidationError("UGACL bit is absent; no conversion needed")


def patch_superblock(data, offset):
    info = parse_superblock(data, offset)
    validate_patch_scope(info)
    result = bytearray(data)
    struct.pack_into("<Q", result, INCOMPAT_OFFSET,
                     int(info["incompat_flags"], 16) & ~UGACL)
    struct.pack_into("<I", result, 0, crc32c(result[32:]))
    result = bytes(result)
    checked = parse_superblock(result, offset)
    if checked["ugacl"]:
        raise ValidationError("Patched superblock still contains UGACL")
    return result


def source_size(fd):
    mode = os.fstat(fd).st_mode
    if stat.S_ISREG(mode):
        return os.fstat(fd).st_size
    if stat.S_ISBLK(mode) and sys.platform.startswith("linux"):
        return struct.unpack("=Q", fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]
    raise ValidationError("Expected a regular raw image or Linux block device")


def scan(fd):
    size = source_size(fd)
    infos, blocks = [], {}
    for offset in MIRRORS:
        if offset + SUPER_SIZE > size:
            continue
        data = os.pread(fd, SUPER_SIZE, offset)
        try:
            info = parse_superblock(data, offset)
        except ValidationError as exc:
            raise ValidationError("Mirror at %d: %s" % (offset, exc)) from exc
        if info["device_total_bytes"] > size:
            raise ValidationError("Device/image is smaller than declared device size")
        infos.append(info)
        blocks[offset] = data
    if not infos:
        raise ValidationError("No complete Btrfs superblock fits in the input")
    # Refuse old/mixed copies rather than choosing a recovery strategy silently.
    fields = ("fsid", "device_uuid", "device_id", "generation", "total_bytes",
              "device_total_bytes", "num_devices", "incompat_flags",
              "compat_flags", "compat_ro_flags", "super_flags", "sectorsize", "nodesize")
    for info in infos[1:]:
        if any(info[key] != infos[0][key] for key in fields):
            raise ValidationError("Superblock mirrors disagree; recovery is outside scope")
    return infos, blocks


def _signature(fd):
    value = os.fstat(fd)
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def reject_attached_loop(fd):
    """Reject images attached to a Linux loop device, even if not mounted."""
    identity = os.fstat(fd)
    for entry in Path("/sys/block").glob("loop*/loop/backing_file"):
        try:
            name = entry.read_text().strip()
            value = os.stat(name)
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            raise ValidationError("Cannot establish loop-device safety: %s" % exc) from exc
        if (value.st_dev, value.st_ino) == (identity.st_dev, identity.st_ino):
            raise ValidationError("Image is attached to a loop device; detach it first")


def _copy_range(src, dst, start, end):
    position = start
    while position < end:
        data = os.pread(src, min(1024 * 1024, end - position), position)
        if not data:
            raise ValidationError("Image was truncated during copy")
        # Preserve holes, including on platforms without SEEK_DATA/SEEK_HOLE.
        if any(data):
            _pwrite_all(dst, data, position)
        position += len(data)


def _pwrite_all(fd, data, offset):
    view = memoryview(data)
    while view:
        count = os.pwrite(fd, view, offset)
        if count <= 0:
            raise OSError("Short write")
        view = view[count:]
        offset += count


def copy_sparse(src, dst, size):
    os.ftruncate(dst, size)
    if not hasattr(os, "SEEK_DATA"):
        _copy_range(src, dst, 0, size)
        return
    position = 0
    while position < size:
        try:
            start = os.lseek(src, position, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                return
            if exc.errno in (errno.EINVAL, errno.ENOTSUP):
                _copy_range(src, dst, position, size)
                return
            raise
        try:
            end = min(os.lseek(src, start, os.SEEK_HOLE), size)
        except OSError as exc:
            if exc.errno in (errno.EINVAL, errno.ENOTSUP):
                _copy_range(src, dst, start, size)
                return
            # ENXIO here is not 'no more data': silently returning would drop
            # the remaining file data after already-copied valid superblocks.
            raise ValidationError("Cannot determine sparse extent end") from exc
        if end <= start:
            raise ValidationError("Invalid sparse extent reported by filesystem")
        _copy_range(src, dst, start, end)
        position = end


def patch_image(source, output, offline_image=False):
    if not offline_image:
        raise ValidationError("Use --offline-image only for an unmounted image not used by QEMU")
    src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    dst = None
    complete = False
    try:
        if not stat.S_ISREG(os.fstat(src).st_mode):
            raise ValidationError("Patching block devices is disabled; input must be a raw image file")
        fcntl.flock(src, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Also conflict with POSIX/OFD writer locks used by QEMU. This remains
        # advisory: --offline-image is still required to exclude unlocked writers.
        if sys.platform.startswith("linux"):
            fcntl.lockf(src, fcntl.LOCK_SH | fcntl.LOCK_NB)
        reject_attached_loop(src)
        before = _signature(src)
        infos, blocks = scan(src)
        for info in infos:
            validate_patch_scope(info)
        patched = {offset: patch_superblock(data, offset) for offset, data in blocks.items()}
        # O_EXCL rejects every existing output, including symlinks and hardlinks.
        dst = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        copy_sparse(src, dst, before[2])
        for offset, data in patched.items():
            _pwrite_all(dst, data, offset)
        os.fsync(dst)
        if _signature(src) != before or any(
                os.pread(src, SUPER_SIZE, offset) != data for offset, data in blocks.items()):
            raise ValidationError("Source changed during copy; discard output and use a stable image")
        after_infos, after_blocks = scan(dst)
        if after_blocks != patched:
            raise ValidationError("Output superblock readback differs from patch")
        complete = True
        return {"output": str(output), "mirrors": after_infos,
                "original_modified": False, "filesystem_compatibility_verified": False,
                "ugacl_policy_translated": False, "vendor_quota_translated": False,
                "requires_isolated_access": True,
                "warning": "Experimental image only: clearing UGACL can expose denied files and bypass vendor quotas. Use access-restricted read-only recovery or isolated tests; production conversion is unsupported."}
    finally:
        if dst is not None:
            identity = os.fstat(dst)
            os.close(dst)
            if not complete:
                try:
                    current = os.lstat(output)
                    if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                        os.unlink(output)
                except FileNotFoundError:
                    pass
        os.close(src)


def assess_policy(native, guest):
    """Compare recorded synthetic policy probes; never certify production data."""
    profile = native.get("profile")
    if profile not in ("acl-qgroup", "usrquota") or guest.get("profile") != profile:
        raise ValidationError("Policy report profiles disagree or are unsupported")
    if guest.get("production_volume_tested") is not False:
        raise ValidationError("Expected an isolated synthetic test report")
    checks, differences = {}, []
    source_access = native.get("access", {})
    for phase in ("readonly", "write_overlay"):
        evidence = guest.get(phase, {})
        hashes = evidence.get("file_hashes", {})
        checks[phase + "_file_hashes"] = (
            "passed" if hashes and all(v is True for v in hashes.values()) else "not_verified")
        if profile == "usrquota":
            continue  # this fixture does not exercise file permissions
        for operation in ("read", "write_open"):
            if phase == "readonly" and operation == "write_open":
                continue  # EROFS is a mount restriction, not ACL equivalence
            status = "passed" if source_access else "not_verified"
            target_access = evidence.get("access", {})
            for name, expected in source_access.items():
                a = expected.get(operation, {}).get("allowed")
                b = target_access.get(name, {}).get(operation, {}).get("allowed")
                if not isinstance(a, bool) or not isinstance(b, bool):
                    if status != "failed":
                        status = "not_verified"
                elif a != b:
                    status = "failed"
                    differences.append({"phase": phase, "file": name,
                                        "operation": operation, "native_allowed": a,
                                        "target_allowed": b})
            checks[phase + "_" + operation + "_policy"] = status
    source_quota = native.get("quota", {}).get("host_probe", {})
    key = "quota_probe" if profile == "acl-qgroup" else "user_quota_probe"
    target_quota = guest.get("write_overlay", {}).get(key, {})
    if (source_quota.get("errno") != errno.EDQUOT or
            not isinstance(source_quota.get("written"), int) or
            not isinstance(source_quota.get("maximum"), int) or
            not 0 < source_quota["written"] < source_quota["maximum"] or
            target_quota.get("maximum") != source_quota["maximum"] or
            not isinstance(target_quota.get("written"), int)):
        checks["quota_policy"] = "not_verified"
    else:
        same = (target_quota.get("errno") == errno.EDQUOT and
                target_quota["written"] == source_quota["written"])
        checks["quota_policy"] = "passed" if same else "failed"
        if not same:
            differences.append({"operation": key, "native": source_quota, "target": target_quota})
    values = set(checks.values())
    status = ("incompatible" if "failed" in values else
              "not_verified" if "not_verified" in values else "sample_checks_passed")
    return {"profile": profile, "status": status, "checks": checks,
            "differences": differences, "production_conversion_supported": False,
            "scope": "Recorded synthetic probes only; not full ACL/quota or filesystem certification"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Read only; inspect a raw image or Linux block device")
    check.add_argument("source")
    single = commands.add_parser("check-superblock", help="Inspect one captured 4096-byte superblock")
    single.add_argument("source")
    single.add_argument("--offset", type=lambda value: int(value, 0), required=True)
    patch = commands.add_parser("patch-image", help="Copy and patch a NEW offline raw image; never in place")
    patch.add_argument("source")
    patch.add_argument("--output", required=True)
    patch.add_argument("--offline-image", action="store_true")
    policy = commands.add_parser("assess-policy", help="Compare native/guest synthetic policy reports; exit 3 when incompatible or unverified")
    policy.add_argument("native_report")
    policy.add_argument("guest_report")
    args = parser.parse_args(argv)
    try:
        exit_code = 0
        if args.command == "assess-policy":
            result = assess_policy(json.loads(Path(args.native_report).read_text()),
                                   json.loads(Path(args.guest_report).read_text()))
            exit_code = 0 if result["status"] == "sample_checks_passed" else 3
        elif args.command == "patch-image":
            result = patch_image(args.source, args.output, args.offline_image)
        else:
            fd = os.open(args.source, os.O_RDONLY | os.O_NONBLOCK)
            try:
                if args.command == "check-superblock":
                    if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_size != SUPER_SIZE:
                        raise ValidationError("A captured superblock must be a 4096-byte regular file")
                    result = parse_superblock(os.pread(fd, SUPER_SIZE, 0), args.offset)
                else:
                    infos, _ = scan(fd)
                    result = {"mirrors": infos, "read_only": True,
                              "filesystem_compatibility_verified": False}
            finally:
                os.close(fd)
        print(json.dumps(result, indent=2))
        return exit_code
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
