# Implementation validation record

Checked on 2026-10-03. This records software validation, not model effectiveness.

- Python 3.12 on Windows: 23 tests passed across `ml/tests`,
  `profiling/features`, and `profiling/profile_engine`. Coverage includes flow
  direction, interval deltas, outages, labels, schema validity, train-only scaling,
  queried-edge removal, frozen/history-independent Head C, both training stages,
  checkpoint reloads, split leakage, calibration source selection, and TCP transport.
- The newly downloaded UNSW workbook and 17 daily attack/benign captures were
  inventoried without reading entire multi-gigabyte files. The audit found ten
  listed IoT targets, 114 experiment rows, three external attacker IPs, and three
  malformed annotation rows. A test checks that actor IPs are not silently mapped
  to compromised target identities.
- The smallest new UNSW capture (`18-10-21.pcap`, about 147 MB) passed the same
  Zeek extraction contract: 3,427 flow-window rows across 413 active minute
  windows and 574 UIDs, without a reporter warning. A review manifest resolved
  one Hue device and remains deliberately marked incomplete. This checks the
  capture format and identity path; it does not certify the dataset or its labels.
- The synthetic `python -m ml smoke` pipeline trained both stages, calibrated,
  saved/reloaded models, and produced evaluation/prediction artifacts. Synthetic
  checkpoints are marked and cannot be used to claim measured detection accuracy.
- Zeek 7.0.1 in Ubuntu 24.04/WSL parsed the policy and processed a packet fixture.
  `scripts/validate_gnn_sensor.py` verified exact IPv4/IPv6 IP-byte and packet totals,
  a TCP connection spanning two windows, handshake state and a failed SYN.
- The supplied CIC `Backdoor_Malware.pcap` was extracted using this policy and
  passed telemetry validation: 3,916 flow-window rows, 18 active windows, 2,553
  connection UIDs. This proves extraction compatibility, not actor labels or accuracy.
- All 240 default attack/control plans were generated, and the matrix launcher's
  dry-run path was exercised. No live attacks or long collections were run.

The environment did not have Mininet and Open vSwitch installed. Full topology
startup, mirror capture health, responder load, and seven-day stability must pass
the Linux pilot in [COLLECTION.md](COLLECTION.md) before the long collection.
The supplied public attack files are not a completed actor-labeled training corpus.
UNSW now has the raw PCAPs, but its victim annotations do not establish compromised
IoT actors. The CIC victims document and shared AI summary do not establish them
either.

The tested training environment used PyTorch 2.14.1+cpu and PyG 2.8.0.post1.
The dependency ranges in `requirements-ml.txt` permit other supported versions;
run the acceptance tests in the actual collection/training environment. Checkpoints
record the installed training dependency versions.
