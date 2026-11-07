"""
Self-contained test runner for AnubisTrace.
Allows running the full test suite without external dependencies.
"""

import sys
import traceback
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).parent.resolve()
sys.path.insert(0, str(root_dir))

from tests.test_event import test_severity_ordering, test_forensic_event_creation
from tests.test_mitre import (
    test_mitre_event_id_enrichment,
    test_mitre_lolbin_and_command_pattern,
    test_encoded_powershell_detection,
)
from tests.test_timeline import test_timeline_sorting_and_filtering
from tests.test_parsers import (
    test_evtx_xml_parser,
    test_linux_auth_parser,
    test_linux_bash_history_parser,
)

TEST_FUNCTIONS = [
    test_severity_ordering,
    test_forensic_event_creation,
    test_mitre_event_id_enrichment,
    test_mitre_lolbin_and_command_pattern,
    test_encoded_powershell_detection,
    test_timeline_sorting_and_filtering,
    test_evtx_xml_parser,
    test_linux_auth_parser,
    test_linux_bash_history_parser,
]

def run_all() -> int:
    print("=" * 60)
    print("  AnubisTrace - Full Forensic Test Suite")
    print("=" * 60)

    passed = 0
    failed = 0

    for test_fn in TEST_FUNCTIONS:
        test_name = test_fn.__name__
        try:
            test_fn()
            print(f"  [PASS] {test_name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {test_name}")
            traceback.print_exc()
            failed += 1

    print("-" * 60)
    print(f"Summary: {passed} passed, {failed} failed.")
    print("=" * 60)

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(run_all())
