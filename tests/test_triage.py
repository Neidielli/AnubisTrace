"""Unit tests for AnubisTrace Live Triage and Collector modules."""

import json
import tempfile
from pathlib import Path

from anubistrace.triage.collector import LiveCollector, calculate_sha256


def test_calculate_sha256():
    with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
        f.write("AnubisTrace Forensic Integrity Test")
        tmp_path = Path(f.name)

    try:
        h = calculate_sha256(tmp_path)
        assert len(h) == 64  # SHA-256 hexadecimal length
        assert h != "ERROR_HASHING_FILE"
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_live_collector_manifest_structure():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "triage_test"
        collector = LiveCollector(out_path)

        # Run triage (mocked/safe in temp dir)
        collector.run_triage()

        assert out_path.exists()
        assert collector.manifest_file.exists()

        data = json.loads(collector.manifest_file.read_text(encoding="utf-8"))
        assert "case_info" in data
        assert "system_profile" in data
        assert "evidence_manifest" in data
        assert data["case_info"]["tool"] == "AnubisTrace Live Collector"
        assert "hostname" in data["system_profile"]
