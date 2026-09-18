# data/processed/testbed/

**Owner:** Shared (produced by `network/testbed/` and the traffic helpers in
`scripts/UNSW-IoTraffic/`)

Reproducible traffic inputs and outputs for the Mininet household testbed.
These files are local derived data and are excluded from Git.

| Subdirectory | Contents |
|---|---|
| `generated/` | Original per-device JSON event logs emitted by the offline traffic generators |
| `replay_safe/` | Replay-ready copies normalized for packet construction with Scapy; this is the default input to `run_full_topology.py` |
| `runs/<run-name>/` | Outputs from a Mininet run, including its PCAP and `logs/` from the individual device agents and packet capture process |

`generated/` is called “generated,” rather than “raw,” to distinguish it from
the original external datasets in `data/raw/`. Do not hand-edit either traffic
set; regenerate or transform it so that a run remains reproducible.

The default full-topology run writes to `runs/full_topology/`. Pass
`--traffic-dir` or `--output-dir` to `network/testbed/run_full_topology.py` when
using another prepared input set or preserving multiple named runs.
