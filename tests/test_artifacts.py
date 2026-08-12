from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from wirescope.analyzer import export_har, export_requests_csv
from wirescope.artifacts import (
    ArtifactSecurityError,
    atomic_text_writer,
    atomic_write_bytes,
    atomic_write_text,
    external_artifact,
    private_text_stream,
)
from wirescope.capture import capture_packets, watch_dns
from wirescope.cdp import CDPRecorder
from wirescope.proxy import EventWriter
from wirescope.record import record_connections
from wirescope.report import generate_comparison_html, generate_html_report
from wirescope.tui import LiveState


@contextmanager
def permissive_umask():
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class SecureArtifactTests(unittest.TestCase):
    def test_owner_only_from_creation_with_umask_zero(self):
        with tempfile.TemporaryDirectory() as directory, permissive_umask():
            root = Path(directory)
            text = root / "nested" / "report.json"
            binary = root / "capture.bin"
            observed = []
            with private_text_stream(text) as stream:
                observed.append(file_mode(text))
                stream.write("first")
            atomic_write_bytes(binary, b"wire")
            self.assertEqual(observed, [0o600])
            self.assertEqual(file_mode(text), 0o600)
            self.assertEqual(file_mode(binary), 0o600)

    def test_final_component_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("keep", encoding="utf-8")
            link = root / "artifact.txt"
            link.symlink_to(target)

            with self.assertRaises(ArtifactSecurityError):
                with private_text_stream(link) as stream:
                    stream.write("bad")
            with self.assertRaises(ArtifactSecurityError):
                atomic_write_text(link, "bad")
            with self.assertRaises(ArtifactSecurityError):
                with external_artifact(link):
                    pass

            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_external_writer_symlink_substitution_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "capture.pcap"
            target = root / "unrelated"
            target.write_bytes(b"keep")
            with self.assertRaises(ArtifactSecurityError):
                with external_artifact(output):
                    output.unlink()
                    output.symlink_to(target)
            self.assertEqual(target.read_bytes(), b"keep")

    def test_overwrite_and_append_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            atomic_write_text(output, "old\n")
            atomic_write_text(output, "new\n")
            with private_text_stream(output, append=True) as stream:
                stream.write("next\n")
            output.chmod(0o644)
            with private_text_stream(output, append=True) as stream:
                self.assertEqual(file_mode(output), 0o600)
                stream.write("last\n")

            self.assertEqual(output.read_text(encoding="utf-8"), "new\nnext\nlast\n")
            self.assertEqual(file_mode(output), 0o600)

    def test_atomic_writer_exception_preserves_destination_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report.json"
            atomic_write_text(output, "stable")

            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                with atomic_text_writer(output) as stream:
                    stream.write("partial")
                    raise RuntimeError("interrupted")

            self.assertEqual(output.read_text(encoding="utf-8"), "stable")
            self.assertEqual(list(root.glob(".report.json.*.tmp")), [])


class MigratedWriterTests(unittest.TestCase):
    def assert_private(self, *paths: Path) -> None:
        for path in paths:
            self.assertTrue(path.is_file(), str(path))
            self.assertEqual(file_mode(path), 0o600, str(path))

    def test_one_shot_report_and_analyzer_exports_are_private(self):
        report = {
            "generated_at": "2026-01-01T00:00:00Z",
            "source_type": "test",
            "summary": {"requests": 0, "domains": 0},
            "requests": [],
            "aggregates": {},
            "scores": {},
            "findings": [],
        }
        comparison = {"before": "a", "after": "b", "deltas": {}, "score_deltas": {}}
        with tempfile.TemporaryDirectory() as directory, permissive_umask():
            root = Path(directory)
            html = root / "report.html"
            compare = root / "compare.html"
            csv = root / "requests.csv"
            har = root / "requests.har"
            generate_html_report(report, str(html))
            generate_comparison_html(comparison, str(compare))
            export_requests_csv(report, str(csv))
            export_har(report, str(har))
            self.assert_private(html, compare, csv, har)
            self.assertIn("WireScope Network Report", html.read_text(encoding="utf-8"))
            self.assertEqual(json.loads(har.read_text(encoding="utf-8"))["log"]["entries"], [])

    def test_streaming_record_proxy_cdp_and_tui_outputs_are_private(self):
        class EmptyAdapter:
            def connections(self):
                return []

        class FakeWebSocket:
            def __init__(self, _url):
                self.returned_metrics = False

            def send_json(self, _value):
                pass

            def recv_json(self):
                if not self.returned_metrics:
                    self.returned_metrics = True
                    return {"id": 6, "result": {"metrics": []}}
                raise socket.timeout()

            def close(self):
                pass

        class FakeTcpdump:
            def __init__(self):
                self.stdout = StringIO()
                self.stderr = StringIO()
                self.returncode = None

            def poll(self):
                return self.returncode

            def send_signal(self, signal_number):
                self.returncode = -signal_number

            def wait(self, timeout=None):
                return self.returncode

            def terminate(self):
                self.returncode = -15

        with tempfile.TemporaryDirectory() as directory, permissive_umask():
            root = Path(directory)
            recording = root / "connections.jsonl"
            proxy = root / "proxy.jsonl"
            cdp = root / "browser.jsonl"
            dns = root / "dns.jsonl"
            record_connections(EmptyAdapter(), str(recording), duration=0, interval=0.01)
            with redirect_stdout(StringIO()):
                with EventWriter(str(proxy)) as writer:
                    writer.emit({"type": "test"})
            with mock.patch("wirescope.cdp.WebSocket", FakeWebSocket):
                CDPRecorder("ws://127.0.0.1/devtools/page/test", str(cdp)).record(duration=0)
            with mock.patch("wirescope.capture.subprocess.Popen", return_value=FakeTcpdump()):
                watch_dns("en0", duration=0, output=str(dns))

            previous = Path.cwd()
            try:
                os.chdir(root)
                exported = Path(LiveState(adapter=EmptyAdapter()).export()).resolve()
            finally:
                os.chdir(previous)
            self.assert_private(recording, proxy, cdp, dns, exported)
            self.assertEqual(json.loads(proxy.read_text(encoding="utf-8"))["type"], "test")

    def test_external_capture_is_prepared_and_post_verified(self):
        observed = []

        def fake_run(command, check):
            self.assertFalse(check)
            output = Path(command[command.index("-w") + 1])
            observed.append(file_mode(output))
            output.write_bytes(b"pcap")
            output.chmod(0o666)
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory, permissive_umask():
            output = Path(directory) / "capture.pcap"
            with mock.patch("wirescope.capture.subprocess.run", side_effect=fake_run):
                result = capture_packets("en0", str(output), duration=1)
            self.assertEqual(result, 0)
            self.assertEqual(observed, [0o600])
            self.assertEqual(output.read_bytes(), b"pcap")
            self.assertEqual(file_mode(output), 0o600)


if __name__ == "__main__":
    unittest.main()
