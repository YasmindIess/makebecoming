#!/usr/bin/env python3
"""End-to-end checks for native kernel and PHP local blockstore."""
import json, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
fixture = root / "examples/v2_1_verified.jsonl"
records = [json.loads(line) for line in fixture.read_text().splitlines() if line.strip()]
assert len(records) == 3
def run(*cmd, succeeds=True):
    p = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    assert (p.returncode == 0) == succeeds, p.stderr
    return p.stdout
result = json.loads(run(root / "forge-kernel", "replay", fixture))
assert result["verified"] and result["boundary_squared_zero"]
assert (result["vertices"], result["edges"], result["faces"], result["tetrahedra"]) == (27, 65, 57, 18)
assert result["head"] == records[-1]["digest"]
with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    bad = td / "bad.jsonl"
    manipulated = json.loads(json.dumps(records))
    manipulated[0]["body"]["boundary_x_milli"] += 1
    bad.write_text("\n".join(json.dumps(row, separators=(",", ":")) for row in manipulated) + "\n")
    run(root / "forge-kernel", "replay", bad, succeeds=False)
    store = td / "journal"
    cli = root / "runtime/forge-store.php"
    first = json.loads(run("php", cli, "append", fixture, store))
    assert first["new_blocks"] == 3
    second = json.loads(run("php", cli, "append", fixture, store))
    assert second["new_blocks"] == 0
    replay = json.loads(run("php", cli, "replay", store))
    assert replay["result"]["verified"] and replay["result"]["head"] == records[-1]["digest"]
print("MAKEBECOMING SMOKE PASS: C topology, hash chain, rejection, PHP append, cold replay")
