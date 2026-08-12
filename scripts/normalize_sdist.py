#!/usr/bin/env python3
"""Rewrite one source distribution with deterministic, public-safe metadata.

The normalizer never extracts archive members.  It accepts only a gzip-compressed
tar archive containing regular files and directories beneath one explicit root,
then atomically replaces it with a sorted USTAR archive.  Ownership, timestamps,
permissions, gzip filename fields, and PAX metadata from the build host are not
copied to the result.
"""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Optional, Sequence


MAX_MEMBERS = 100_000
MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE_DATE_EPOCH = (1 << 32) - 1
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class SdistNormalizationError(ValueError):
    """The input is not a safe, canonical source distribution."""


@dataclass(frozen=True)
class _ArchiveMember:
    name: str
    source: tarfile.TarInfo


def _parse_epoch(value: str) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("epoch must be a non-negative integer")
    epoch = int(value, 10)
    if epoch > MAX_SOURCE_DATE_EPOCH:
        raise argparse.ArgumentTypeError(
            f"epoch must be no greater than {MAX_SOURCE_DATE_EPOCH} for portable gzip output"
        )
    return epoch


def source_date_epoch(explicit: Optional[int] = None) -> int:
    """Resolve an explicit epoch, SOURCE_DATE_EPOCH, or the deterministic default 0."""

    if explicit is not None:
        if not 0 <= explicit <= MAX_SOURCE_DATE_EPOCH:
            raise SdistNormalizationError("epoch is outside the portable gzip range")
        return explicit
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured is None:
        return 0
    try:
        return _parse_epoch(configured)
    except argparse.ArgumentTypeError as exc:
        raise SdistNormalizationError(f"invalid SOURCE_DATE_EPOCH: {exc}") from exc


def _canonical_member_name(member: tarfile.TarInfo) -> tuple[str, tuple[str, ...]]:
    name = member.name
    if (
        not name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise SdistNormalizationError(f"unsafe archive member name: {name!r}")
    if name.startswith("/"):
        raise SdistNormalizationError(f"absolute archive member path: {name!r}")
    if member.isdir() and name.endswith("/"):
        name = name[:-1]
    elif name.endswith("/"):
        raise SdistNormalizationError(f"regular file path ends with '/': {name!r}")
    parts = tuple(name.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SdistNormalizationError(f"non-canonical archive member path: {member.name!r}")
    if _DRIVE_PREFIX.match(parts[0]):
        raise SdistNormalizationError(f"drive-qualified archive member path: {member.name!r}")
    return name, parts


def _validated_members(archive: tarfile.TarFile) -> list[_ArchiveMember]:
    records: list[_ArchiveMember] = []
    kinds: dict[str, bool] = {}
    root: Optional[str] = None
    root_is_directory = False
    total_size = 0

    for index, member in enumerate(archive):
        if index >= MAX_MEMBERS:
            raise SdistNormalizationError(f"archive contains more than {MAX_MEMBERS} members")
        if not (member.isfile() or member.isdir()):
            raise SdistNormalizationError(
                f"archive member is not a regular file or directory: {member.name!r}"
            )
        if getattr(member, "sparse", None):
            raise SdistNormalizationError(f"sparse archive member is not allowed: {member.name!r}")
        if member.size < 0 or (member.isdir() and member.size != 0):
            raise SdistNormalizationError(f"invalid archive member size: {member.name!r}")

        name, parts = _canonical_member_name(member)
        if name in kinds:
            raise SdistNormalizationError(f"duplicate archive member path: {name!r}")
        if root is None:
            root = parts[0]
        elif parts[0] != root:
            raise SdistNormalizationError(
                f"archive has multiple top-level roots: {root!r} and {parts[0]!r}"
            )
        if len(parts) == 1:
            if member.isfile():
                raise SdistNormalizationError("the top-level root must be a directory")
            root_is_directory = True

        total_size += member.size
        if total_size > MAX_UNCOMPRESSED_BYTES:
            raise SdistNormalizationError(
                f"archive expands beyond the {MAX_UNCOMPRESSED_BYTES}-byte safety limit"
            )
        kinds[name] = member.isdir()
        records.append(_ArchiveMember(name=name, source=member))

    if not records or root is None:
        raise SdistNormalizationError("archive is empty")
    if not root_is_directory:
        raise SdistNormalizationError("archive is missing its explicit top-level directory")

    for name in kinds:
        path_parts = name.split("/")
        for index in range(1, len(path_parts)):
            ancestor = "/".join(path_parts[:index])
            if ancestor in kinds and not kinds[ancestor]:
                raise SdistNormalizationError(
                    f"archive path descends through regular file {ancestor!r}"
                )
    return sorted(records, key=lambda record: record.name)


def _normalized_tarinfo(record: _ArchiveMember, root: str, epoch: int) -> tarfile.TarInfo:
    source = record.source
    result = tarfile.TarInfo(record.name)
    result.type = tarfile.DIRTYPE if source.isdir() else tarfile.REGTYPE
    result.size = 0 if source.isdir() else source.size
    relative_name = record.name[len(root) + 1 :] if record.name != root else ""
    result.mode = 0o755 if source.isdir() or relative_name == "bin/wirescope" else 0o644
    result.uid = 0
    result.gid = 0
    result.uname = ""
    result.gname = ""
    result.mtime = epoch
    result.linkname = ""
    result.devmajor = 0
    result.devminor = 0
    result.pax_headers = {}
    return result


def _write_normalized(
    source_archive: tarfile.TarFile,
    records: Iterable[_ArchiveMember],
    root: str,
    epoch: int,
    destination: BinaryIO,
) -> None:
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=destination,
        mtime=epoch,
    ) as compressed:
        with tarfile.open(
            fileobj=compressed,
            mode="w|",
            format=tarfile.USTAR_FORMAT,
            encoding="utf-8",
            errors="strict",
        ) as output:
            for record in records:
                info = _normalized_tarinfo(record, root, epoch)
                if record.source.isdir():
                    output.addfile(info)
                    continue
                payload = source_archive.extractfile(record.source)
                if payload is None:
                    raise SdistNormalizationError(
                        f"regular archive member has no payload: {record.name!r}"
                    )
                with payload:
                    output.addfile(info, payload)


def _open_source(path: Path) -> tuple[BinaryIO, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SdistNormalizationError(f"cannot open source distribution safely: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SdistNormalizationError("source distribution is not a regular file")
        return os.fdopen(descriptor, "rb"), metadata
    except Exception:
        os.close(descriptor)
        raise


def _same_source(path: Path, opened: os.stat_result, handle: BinaryIO) -> bool:
    try:
        current_path = os.lstat(path)
        current_file = os.fstat(handle.fileno())
    except OSError:
        return False
    identity = (opened.st_dev, opened.st_ino)
    return (
        stat.S_ISREG(current_path.st_mode)
        and (current_path.st_dev, current_path.st_ino) == identity
        and (current_file.st_dev, current_file.st_ino) == identity
        and current_file.st_size == opened.st_size
        and current_file.st_mtime_ns == opened.st_mtime_ns
    )


def _sync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def normalize_sdist(path: Path, *, epoch: Optional[int] = None) -> None:
    """Validate and atomically rewrite ``path`` as a deterministic sdist."""

    archive_path = Path(path).absolute()
    if archive_path.suffixes[-2:] != [".tar", ".gz"]:
        raise SdistNormalizationError("source distribution must have a .tar.gz suffix")
    fixed_epoch = source_date_epoch(epoch)
    source, opened_metadata = _open_source(archive_path)
    temporary_path: Optional[Path] = None
    try:
        try:
            input_archive = tarfile.open(
                fileobj=source,
                mode="r:gz",
                encoding="utf-8",
                errors="strict",
            )
        except (OSError, tarfile.TarError) as exc:
            raise SdistNormalizationError(f"invalid gzip tar source distribution: {exc}") from exc
        with input_archive:
            records = _validated_members(input_archive)
            root = records[0].name.split("/", 1)[0]
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{archive_path.name}.normalize-",
                dir=archive_path.parent,
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as destination:
                    _write_normalized(input_archive, records, root, fixed_epoch, destination)
                    destination.flush()
                    os.fsync(destination.fileno())
            except Exception:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise

        if not _same_source(archive_path, opened_metadata, source):
            raise SdistNormalizationError("source distribution changed during normalization")
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, archive_path)
        temporary_path = None
        _sync_directory(archive_path.parent)
    except SdistNormalizationError:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        raise SdistNormalizationError(f"could not normalize source distribution: {exc}") from exc
    finally:
        source.close()
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="atomically normalize one .tar.gz source distribution",
    )
    parser.add_argument("archive", type=Path, help="concrete .tar.gz archive to rewrite")
    parser.add_argument(
        "--epoch",
        type=_parse_epoch,
        help="fixed Unix timestamp (default: SOURCE_DATE_EPOCH or 0)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        normalize_sdist(arguments.archive, epoch=arguments.epoch)
    except SdistNormalizationError as exc:
        print(f"normalize_sdist: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
