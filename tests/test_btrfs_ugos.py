import importlib.util
import errno
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "patch_btrfs_ugos.py"
spec = importlib.util.spec_from_file_location("btrfs_ugos", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
SIZE = tool.MIRRORS[1] + tool.SUPER_SIZE
FSID = bytes(range(16))
DEVICE_UUID = bytes(range(16, 32))


def reference_crc(data):
    # Slow, independent bit-by-bit implementation used only for test fixtures.
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def superblock(offset, size=SIZE, generation=42, flags=tool.UGACL | 0x361):
    data = bytearray(tool.SUPER_SIZE)
    data[0x20:0x30] = FSID
    struct.pack_into("<Q", data, 0x30, offset)
    struct.pack_into("<Q", data, 0x38, 1)
    data[0x40:0x48] = b"_BHRfS_M"
    for pos, value in ((0x48, generation), (0x70, size), (0x78, 4096),
                       (0x88, 1), (0xB4, 3), (0xBC, flags), (0xC9, 1),
                       (0xD1, size), (0xD9, 4096)):
        struct.pack_into("<Q", data, pos, value)
    struct.pack_into("<I", data, 0x90, 4096)
    struct.pack_into("<I", data, 0x94, 16384)
    data[0x10B:0x11B] = DEVICE_UUID
    data[0x11B:0x12B] = FSID
    # Nonzero vendor/reserved bytes must survive a patch exactly.
    data[0x300:0x320] = bytes(range(32))
    struct.pack_into("<I", data, 0, reference_crc(data[32:]))
    return bytes(data)


def mutated(data, pos, fmt, value):
    result = bytearray(data)
    struct.pack_into(fmt, result, pos, value)
    struct.pack_into("<I", result, 0, reference_crc(result[32:]))
    return bytes(result)


class SuperblockTests(unittest.TestCase):
    def setUp(self):
        self.data = superblock(tool.MIRRORS[0])

    def test_crc_known_vectors(self):
        self.assertEqual(tool.crc32c(b"123456789"), 0xE3069283)
        self.assertEqual(tool.crc32c(bytes(32)), 0x8A9136AA)
        self.assertEqual(tool.crc32c(bytes([255]) * 32), 0x62A8AB43)
        self.assertEqual(tool.crc32c(b""), 0)

    def test_crc_full_superblock_against_reference(self):
        self.assertEqual(tool.crc32c(self.data[32:]), reference_crc(self.data[32:]))

    def test_patch_changes_only_bit_and_crc(self):
        patched = tool.patch_superblock(self.data, tool.MIRRORS[0])
        self.assertEqual(struct.unpack_from("<Q", patched, 0xBC)[0], 0x361)
        self.assertEqual(patched[0x128:0x130], self.data[0x128:0x130])
        changed = {index for index, (a, b) in enumerate(zip(self.data, patched)) if a != b}
        self.assertLessEqual(changed, {0, 1, 2, 3, 0xC3})
        self.assertIn(0xC3, changed)
        self.assertFalse(tool.parse_superblock(patched, tool.MIRRORS[0])["ugacl"])

    def test_reject_checksum_corruption(self):
        data = bytearray(self.data)
        data[1000] ^= 1
        with self.assertRaisesRegex(tool.ValidationError, "CRC32C mismatch"):
            tool.patch_superblock(data, tool.MIRRORS[0])

    def test_reject_bad_magic_and_position(self):
        for data, offset in ((mutated(self.data, 0x40, "<Q", 0), tool.MIRRORS[0]),
                             (self.data, tool.MIRRORS[1]), (self.data, 1 << 40)):
            with self.subTest(offset=offset), self.assertRaises(tool.ValidationError):
                tool.parse_superblock(data, offset)

    def test_reject_truncated(self):
        with self.assertRaisesRegex(tool.ValidationError, "Truncated"):
            tool.parse_superblock(self.data[:-1], tool.MIRRORS[0])

    def test_reject_unsupported_layouts_before_patch(self):
        cases = [(0xC4, "<H", 1), (0x88, "<Q", 2), (0x38, "<Q", 3),
                 (0xBC, "<Q", tool.UGACL | (1 << 63)),
                 (0xBC, "<Q", tool.UGACL | (1 << 7)),
                 (0xAC, "<Q", 1), (0xB4, "<Q", 8),
                 (0x90, "<I", 8193), (0x94, "<I", 2048),
                 (0xD1, "<Q", SIZE - 4096), (4, "<I", 1),
                 (0x11B, "<Q", 0)]
        for pos, fmt, value in cases:
            with self.subTest(pos=pos, value=value), self.assertRaises(tool.ValidationError):
                tool.patch_superblock(mutated(self.data, pos, fmt, value), tool.MIRRORS[0])

    def test_reject_no_flag(self):
        patched = tool.patch_superblock(self.data, tool.MIRRORS[0])
        with self.assertRaisesRegex(tool.ValidationError, "absent"):
            tool.patch_superblock(patched, tool.MIRRORS[0])


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "source.raw"
        self.output = Path(self.directory.name) / "patched.raw"
        self.make_image(SIZE)

    def make_image(self, size, generation=42):
        with self.source.open("wb") as stream:
            stream.truncate(size)
            for offset in tool.MIRRORS:
                if offset + tool.SUPER_SIZE <= size:
                    stream.seek(offset)
                    stream.write(superblock(offset, size, generation))
            stream.seek(1024 * 1024)
            stream.write(bytes(range(256)) * 100)

    def patch(self):
        return tool.patch_image(str(self.source), str(self.output), True)

    def test_copy_source_unchanged_and_only_expected_bytes_changed(self):
        before = self.source.stat()
        self.patch()
        self.assertEqual(before.st_mtime_ns, self.source.stat().st_mtime_ns)
        changed = []
        with self.source.open("rb") as src, self.output.open("rb") as dst:
            position = 0
            while True:
                a, b = src.read(1024 * 1024), dst.read(1024 * 1024)
                if not a:
                    self.assertFalse(b)
                    break
                if a != b:
                    changed.extend(position + i for i, (x, y) in enumerate(zip(a, b)) if x != y)
                position += len(a)
        allowed = {offset + byte for offset in tool.MIRRORS[:2] for byte in (0, 1, 2, 3, 0xC3)}
        self.assertLessEqual(set(changed), allowed)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_third_mirror_and_sparse_copy(self):
        size = tool.MIRRORS[2] + tool.SUPER_SIZE
        self.make_image(size)
        result = self.patch()
        self.assertEqual(len(result["mirrors"]), 3)
        self.assertEqual(self.output.stat().st_size, size)
        # APFS may allocate a full extent around each short pwrite.
        self.assertLess(self.output.stat().st_blocks * 512, 8 * 1024 * 1024)
        self.assertNotIn(1 << 40, tool.MIRRORS)

    def test_output_must_be_new(self):
        self.output.write_bytes(b"keep me")
        with self.assertRaises(FileExistsError):
            self.patch()
        self.assertEqual(self.output.read_bytes(), b"keep me")

    def test_same_file_is_never_modified(self):
        before = self.source.stat()
        with self.assertRaises(FileExistsError):
            tool.patch_image(str(self.source), str(self.source), True)
        self.assertEqual(before.st_mtime_ns, self.source.stat().st_mtime_ns)

    def test_symlink_input_and_output_rejected(self):
        link = Path(self.directory.name) / "link.raw"
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            tool.patch_image(str(link), str(self.output), True)
        self.output.symlink_to(self.source)
        with self.assertRaises(FileExistsError):
            self.patch()

    def test_hardlink_output_rejected(self):
        os.link(self.source, self.output)
        with self.assertRaises(FileExistsError):
            self.patch()

    def test_requires_offline_declaration(self):
        with self.assertRaisesRegex(tool.ValidationError, "offline-image"):
            tool.patch_image(str(self.source), str(self.output))
        self.assertFalse(self.output.exists())

    def test_reject_non_regular_input_before_output(self):
        fifo = Path(self.directory.name) / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(tool.ValidationError, "raw image"):
            tool.patch_image(str(fifo), str(self.output), True)
        self.assertFalse(self.output.exists())

    def test_reject_loop_attachment_before_output(self):
        with mock.patch.object(tool, "reject_attached_loop", side_effect=tool.ValidationError("loop device")):
            with self.assertRaisesRegex(tool.ValidationError, "loop device"):
                self.patch()
        self.assertFalse(self.output.exists())

    def test_bad_mirror_prevents_output(self):
        with self.source.open("r+b") as stream:
            stream.seek(tool.MIRRORS[1])
            stream.write(bytes(tool.SUPER_SIZE))
        with self.assertRaisesRegex(tool.ValidationError, "magic"):
            self.patch()
        self.assertFalse(self.output.exists())

    def test_stale_mirror_prevents_output(self):
        with self.source.open("r+b") as stream:
            stream.seek(tool.MIRRORS[1])
            stream.write(superblock(tool.MIRRORS[1], generation=41))
        with self.assertRaisesRegex(tool.ValidationError, "disagree"):
            self.patch()
        self.assertFalse(self.output.exists())

    def test_declared_device_larger_than_image_rejected(self):
        with self.source.open("r+b") as stream:
            stream.truncate(SIZE - 4096)
        with self.assertRaisesRegex(tool.ValidationError, "smaller"):
            self.patch()
        self.assertFalse(self.output.exists())

    def test_source_change_and_copy_failure_remove_only_created_output(self):
        for failure in (OSError("out of space"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(tool, "copy_sparse", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        self.patch()
                self.assertFalse(self.output.exists())
        original = tool._signature
        count = 0

        def changed_signature(fd):
            nonlocal count
            count += 1
            result = original(fd)
            return result if count == 1 else result[:-1] + (result[-1] + 1,)

        with mock.patch.object(tool, "_signature", side_effect=changed_signature):
            with self.assertRaisesRegex(tool.ValidationError, "changed"):
                self.patch()
        self.assertFalse(self.output.exists())

    def test_check_never_modifies_source(self):
        before = self.source.stat()
        with mock.patch("builtins.print"):
            self.assertEqual(tool.main(["check", str(self.source)]), 0)
        self.assertEqual(before.st_mtime_ns, self.source.stat().st_mtime_ns)

    @unittest.skipUnless(hasattr(os, "SEEK_DATA"), "SEEK_DATA is not available")
    def test_seek_hole_error_cannot_silently_drop_data(self):
        with mock.patch.object(os, "lseek", side_effect=[0, OSError(errno.ENXIO, "no hole")]):
            with self.assertRaisesRegex(tool.ValidationError, "extent end"):
                self.patch()
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(hasattr(os, "SEEK_DATA"), "SEEK_DATA is not available")
    def test_sparse_seek_unsupported_falls_back_without_losing_payload(self):
        with mock.patch.object(os, "lseek", side_effect=OSError(errno.EINVAL, "unsupported")):
            self.patch()
        with self.source.open("rb") as src, self.output.open("rb") as dst:
            src.seek(1024 * 1024)
            dst.seek(1024 * 1024)
            self.assertEqual(src.read(25600), dst.read(25600))

    def test_cli_failure_is_nonzero_and_does_not_create_output(self):
        with mock.patch("builtins.print"):
            self.assertEqual(tool.main(["patch-image", str(self.source), "--output", str(self.output)]), 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
