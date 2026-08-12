import unittest

from wirescope.models import Connection, Endpoint
from wirescope.tui import (
    LiveState,
    capability_rows,
    diagnostic_health,
    draw_timeline,
    network_state_summary,
    stable_fingerprint,
)


def connection():
    return Connection(
        process="Browser",
        pid=42,
        user="tester",
        fd="9u",
        family="IPv4",
        protocol="TCP",
        local=Endpoint("127.0.0.1", "50000"),
        remote=Endpoint("203.0.113.10", "443"),
        state="ESTABLISHED",
        path="vpn-default",
    )


class LegacyAdapter:
    pass


class DynamicAdapter:
    def __init__(self):
        self.round = 0

    def connections(self):
        self.round += 1
        return [] if self.round == 1 else [connection()]

    def interface_counters(self):
        return {"en0": {"rx_bytes": self.round * 100, "tx_bytes": self.round * 50}}

    def interfaces(self):
        return []

    def routes(self):
        interface = "en0" if self.round == 1 else "utun4"
        return [{"destination": "default", "gateway": "192.0.2.1", "interface": interface}]

    def dns_resolvers(self):
        server = "1.1.1.1" if self.round == 1 else "9.9.9.9"
        return [{"id": 1, "nameservers": [server]}]

    def vpn_status(self):
        return {"active": self.round > 1, "interfaces": []}

    def proxy_config(self):
        return {"HTTPEnable": 0}

    def capabilities(self):
        return {
            "schema_version": 1,
            "capabilities": {
                "connections": {"available": True, "requires_root": False},
                "packet_capture": {"available": False, "requires_root": True},
            },
        }

    def command_diagnostics(self):
        return [{"name": "routes", "ok": True, "warning_kind": None}]

    def parser_diagnostics(self):
        return [{"parser": "routes", "confidence": "high", "warnings": []}]


class SmallScreen:
    def __init__(self, height=12, width=60):
        self.height = height
        self.width = width
        self.lines = []

    def getmaxyx(self):
        return self.height, self.width

    def addnstr(self, y, x, value, count, attr=0):
        self.lines.append((y, x, value[:count], attr))


class TimelineStateTests(unittest.TestCase):
    def test_fingerprints_are_order_independent(self):
        self.assertEqual(stable_fingerprint({"b": 2, "a": 1}), stable_fingerprint({"a": 1, "b": 2}))
        self.assertNotEqual(stable_fingerprint({"a": 1}), stable_fingerprint({"a": 2}))

    def test_network_snapshots_and_changes_are_typed(self):
        state = LiveState(adapter=LegacyAdapter())
        first = [{"destination": "default", "gateway": "192.0.2.1", "interface": "en0"}]
        second = [{"destination": "default", "gateway": "192.0.2.1", "interface": "utun4"}]
        self.assertTrue(state.observe_network_state("routes", first, "2026-01-01T00:00:00.000+00:00"))
        self.assertFalse(state.observe_network_state("routes", first, "2026-01-01T00:00:01.000+00:00"))
        self.assertTrue(state.observe_network_state("routes", second, "2026-01-01T00:00:02.000+00:00"))
        self.assertEqual(len(state.events), 2)
        self.assertEqual(state.events[0].event_type, "network.routes.changed")
        self.assertEqual(state.events[1].event_type, "network.routes.snapshot")
        self.assertEqual(state.events[0].details["previous"], first)
        self.assertIn("utun4", state.events[0].summary)

    def test_marker_filter_and_selection(self):
        state = LiveState(adapter=LegacyAdapter())
        marker = state.add_marker("Deployment started")
        state.add_marker("Cache cleared")
        state.query = "deployment"
        self.assertEqual(state.filtered_events(), [marker])
        self.assertIs(state.selected_event(), marker)
        self.assertEqual(marker.event_type, "user.marker")
        self.assertEqual(marker.details["marker_number"], 1)

    def test_health_normalization_and_legacy_fallback(self):
        state = LiveState(adapter=LegacyAdapter())
        state.refresh_health()
        self.assertEqual(state.capabilities, {})
        report = DynamicAdapter().capabilities()
        rows = capability_rows(report)
        self.assertEqual([item["name"] for item in rows], ["connections", "packet_capture"])
        health = diagnostic_health(
            report,
            [{"ok": False, "warning_kind": "permission-denied"}],
            [{"confidence": "low", "warnings": [{"code": "skipped"}]}],
        )
        self.assertEqual(health["capabilities_available"], 1)
        self.assertEqual(health["command_failures"], 1)
        self.assertEqual(health["parser_low_confidence"], 1)

    def test_refresh_correlates_lifecycle_and_network_changes(self):
        state = LiveState(adapter=DynamicAdapter())
        state.refresh(force_static=True)
        self.assertEqual(len(state.events), 4)
        state.refresh(force_static=True)
        event_types = {event.event_type for event in state.events}
        self.assertIn("connection.opened", event_types)
        self.assertIn("network.routes.changed", event_types)
        self.assertIn("network.dns.changed", event_types)
        self.assertIn("network.vpn.changed", event_types)
        self.assertEqual(state.capabilities["schema_version"], 1)
        self.assertEqual(network_state_summary("proxy", {"HTTPEnable": 0}), "proxy not enabled")

    def test_small_timeline_detail_does_not_overlap_or_raise(self):
        state = LiveState(adapter=LegacyAdapter(), show_detail=True)
        state.add_marker("small terminal")
        screen = SmallScreen()
        draw_timeline(screen, state, 4)
        self.assertTrue(any("need at least 18" in line[2] for line in screen.lines))


if __name__ == "__main__":
    unittest.main()
