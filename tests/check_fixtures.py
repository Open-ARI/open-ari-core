# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ncdents, LLC.
"""Check fixture integrity and CLI outcomes without external Python packages."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "tests/fixtures/manifest.json").read_text())
assert manifest["schema_version"] == 1
binary = root / "target/debug" / ("openari.exe" if os.name == "nt" else "openari")
seen = set()
for case in manifest["cases"]:
    assert case["id"] not in seen
    seen.add(case["id"])
    data = bytes.fromhex(case["hex"])
    assert hashlib.sha256(data).hexdigest() == case["sha256"]
    assert case["provenance"] == "synthetic-prefix-not-an-image"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.bin"
        path.write_bytes(data)
        result = subprocess.run([str(binary), "verify", str(path)], capture_output=True, check=False)
    assert result.returncode == 3, result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["policy_id"] == case["policy_id"]
    assert report["inspection"]["container_hint"] == case["expected"]["container_hint"]
    for key in ("decision", "reason"):
        assert report[key] == case["expected"][key]
    for key in ("structure", "image_integrity", "signature", "trust", "revocation"):
        assert report[key] == "not_checked"
    assert report["inspection"]["ari_version"] is None
print(f"Validated {len(seen)} synthetic prefix cases; none authenticated.")
