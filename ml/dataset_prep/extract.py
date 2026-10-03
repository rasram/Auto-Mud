"""Run the exact same Zeek policy on public or testbed PCAPs."""
import shutil
import subprocess
from pathlib import Path

from ml.schema import file_hash, write_json, read_jsonl, write_jsonl, validate_telemetry, require


def extract(pcaps, out, zeek="zeek", mergecap="mergecap"):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    require(not (out / "automud-window.log").exists(), "Output already contains telemetry; choose a fresh directory")
    paths = [Path(p).resolve() for p in pcaps]
    require(paths and all(p.is_file() for p in paths), "Missing PCAP input")
    policy = Path(__file__).resolve().parents[2] / "network" / "zeek" / "automud-window.zeek"
    binary = shutil.which(zeek)
    require(binary, "Zeek executable unavailable; run extraction in the Linux testbed environment")
    source = paths[0]
    if len(paths) > 1:
        require(shutil.which(mergecap), "Multiple capture parts require mergecap to preserve connection state")
        source = out / "merged.pcapng"
        subprocess.run([mergecap, "-w", str(source), *map(str, paths)], check=True)
    # Deliberately do not use -C: a blanket checksum bypass hides broken capture/offload setup.
    subprocess.run([binary, "-r", str(source), str(policy)], cwd=out, check=True)
    reporter = out / "reporter.log"
    require(not reporter.exists() or "AutoMUD out-of-order" not in reporter.read_text(),
            "Out-of-order packets crossed emitted windows; repair capture ordering and re-extract")
    version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    write_json(out / "extraction.json", {"zeek_version": version, "policy_sha256": file_hash(policy),
               "inputs": [{"path": str(p), "sha256": file_hash(p)} for p in paths]})
    # Zeek emits all rows for one minute together; order within a window is immaterial.
    write_jsonl(out / "telemetry.jsonl", (validate_telemetry(r) for r in read_jsonl(out / "automud-window.log")))
    return str(out / "telemetry.jsonl")
