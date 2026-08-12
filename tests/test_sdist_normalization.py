from __future__ import annotations

from contextlib import contextmanager
import gzip
from io import BytesIO
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts.normalize_sdist import (
    SdistNormalizationError,
    normalize_sdist,
    source_date_epoch,
)


@contextmanager
def _gzip_tar(path: Path, *, gzip_mtime: int):
    with path.open("wb") as destination:
        with gzip.GzipFile(
            filename=path.name,
            mode="wb",
            fileobj=destination,
            mtime=gzip_mtime,
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                yield archive


def _add_directory(
    archive: tarfile.TarFile,
    name: str,
    *,
    uid: int,
    mtime: int,
    mode: int = 0o700,
) -> None:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = mode
    member.uid = uid
    member.gid = uid + 1
    member.uname = f"private-user-{uid}"
    member.gname = f"private-group-{uid}"
    member.mtime = mtime
    archive.addfile(member)


def _add_file(
    archive: tarfile.TarFile,
    name: str,
    content: bytes,
    *,
    uid: int,
    mtime: int,
    mode: int = 0o600,
) -> None:
    member = tarfile.TarInfo(name)
    member.type = tarfile.REGTYPE
    member.mode = mode
    member.uid = uid
    member.gid = uid + 1
    member.uname = f"private-user-{uid}"
    member.gname = f"private-group-{uid}"
    member.mtime = mtime
    member.size = len(content)
    member.pax_headers = {"atime": str(mtime + 1), "comment": f"host-{uid}"}
    archive.addfile(member, BytesIO(content))


def _build_safe_archive(path: Path, *, variant: int) -> None:
    entries = [
        ("file", "wirescope-1.2.3/README.md", b"public readme\n"),
        ("dir", "wirescope-1.2.3/bin", b""),
        ("file", "wirescope-1.2.3/bin/wirescope", b"#!/bin/sh\nexit 0\n"),
        ("dir", "wirescope-1.2.3", b""),
    ]
    if variant % 2:
        entries.reverse()
    with _gzip_tar(path, gzip_mtime=100 + variant) as archive:
        for kind, name, content in entries:
            if kind == "dir":
                _add_directory(archive, name, uid=500 + variant, mtime=1_000 + variant)
            else:
                _add_file(
                    archive,
                    name,
                    content,
                    uid=500 + variant,
                    mtime=1_000 + variant,
                    mode=0o777 if variant else 0o600,
                )


class SdistNormalizationTests(unittest.TestCase):
    def test_different_host_metadata_and_order_produce_identical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.tar.gz"
            second = Path(temporary) / "second.tar.gz"
            _build_safe_archive(first, variant=0)
            _build_safe_archive(second, variant=1)

            normalize_sdist(first, epoch=1_234)
            normalize_sdist(second, epoch=1_234)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            normalized = first.read_bytes()
            normalize_sdist(first, epoch=1_234)
            self.assertEqual(first.read_bytes(), normalized)
            raw_tar = gzip.decompress(first.read_bytes())
            self.assertNotIn(b"private-user", raw_tar)
            self.assertNotIn(b"private-group", raw_tar)
            self.assertNotIn(b"host-", raw_tar)
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual(
                    [member.name for member in members],
                    [
                        "wirescope-1.2.3",
                        "wirescope-1.2.3/README.md",
                        "wirescope-1.2.3/bin",
                        "wirescope-1.2.3/bin/wirescope",
                    ],
                )
                for member in members:
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.uname, "")
                    self.assertEqual(member.gname, "")
                    self.assertEqual(member.mtime, 1_234)
                    self.assertEqual(member.pax_headers, {})
                    self.assertTrue(member.isfile() or member.isdir())
                by_name = {member.name: member for member in members}
                self.assertEqual(by_name["wirescope-1.2.3"].mode, 0o755)
                self.assertEqual(by_name["wirescope-1.2.3/bin"].mode, 0o755)
                self.assertEqual(by_name["wirescope-1.2.3/README.md"].mode, 0o644)
                self.assertEqual(by_name["wirescope-1.2.3/bin/wirescope"].mode, 0o755)
                self.assertEqual(
                    archive.extractfile("wirescope-1.2.3/README.md").read(),
                    b"public readme\n",
                )

    def test_rejects_traversal_without_replacing_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsafe.tar.gz"
            with _gzip_tar(path, gzip_mtime=1) as archive:
                _add_directory(archive, "wirescope-1", uid=1, mtime=1)
                _add_file(archive, "wirescope-1/../escape", b"bad", uid=1, mtime=1)
            original = path.read_bytes()

            with self.assertRaisesRegex(SdistNormalizationError, "non-canonical"):
                normalize_sdist(path, epoch=0)

            self.assertEqual(path.read_bytes(), original)

    def test_rejects_symlink_member_without_replacing_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "unsafe.tar.gz"
            with _gzip_tar(path, gzip_mtime=1) as archive:
                _add_directory(archive, "wirescope-1", uid=1, mtime=1)
                member = tarfile.TarInfo("wirescope-1/link")
                member.type = tarfile.SYMTYPE
                member.linkname = "../../private"
                archive.addfile(member)
            original = path.read_bytes()

            with self.assertRaisesRegex(SdistNormalizationError, "not a regular file or directory"):
                normalize_sdist(path, epoch=0)

            self.assertEqual(path.read_bytes(), original)

    def test_source_date_epoch_defaults_to_zero_and_is_strict(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(source_date_epoch(), 0)
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "42"}, clear=True):
            self.assertEqual(source_date_epoch(), 42)
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "-1"}, clear=True):
            with self.assertRaisesRegex(SdistNormalizationError, "invalid SOURCE_DATE_EPOCH"):
                source_date_epoch()


if __name__ == "__main__":
    unittest.main()
