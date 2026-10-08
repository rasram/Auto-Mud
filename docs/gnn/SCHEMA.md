# AutoMUD graph v2: schemas and upstream requirements

For the dedicated local WSL environment and revised collection design, see [LOCAL_WSL.md](LOCAL_WSL.md). V1 interval telemetry remains accepted; v1 graphs/checkpoints must be rebuilt/retrained.

The authoritative ordered contract is `configs/gnn/schemas/features.json`.
JSON Schemas in that directory describe manifests, telemetry, labels, and graphs.
Regenerate them with `python -m ml schemas`. Runtime validation also checks identity,
finite values, roles, chronology, and partition leakage that JSON Schema cannot.

## Required upstream artifacts

| Artifact | Producer | Purpose |
|---|---|---|
| `manifest.json` | Collection runner or reviewed public adapter | Run/session/source, UTC bounds, inventory, capture quality, seed, hashes |
| `capture.pcap` or PCAPNG parts | Dedicated OVS mirror/public release | Re-extractable ground evidence |
| `telemetry.jsonl` | Canonical Zeek policy and `ml extract` | Per-connection directional interval observations |
| `labels.jsonl` | Scenario runner or verified public metadata | Device roles, binary labels, intervals, onset and evidence |
| `sources.json` | Experiment author/`ml make-config` | Explicit nonoverlapping dataset partitions |

All time values are UTC Unix seconds. Study bounds align to multiples of 60.
Intervals are half-open `[start,end)`. Capture before/after those study bounds is
retained in source files but excluded from prepared graphs. First/last partial
public capture windows are excluded by the manifest bootstrap helper.

Inventory entries contain a stable `device_id`, one of eleven device functional types (plus the external-service context type),
optional MAC, and time-valid IP leases. IDs/IPs/MACs do **not** become numerical model
features. IP leases take precedence; a gateway MAC must not identify remote cloud
hosts as the gateway/device. Ambiguous identity within a window is rejected.

## Telemetry row

```json
{
  "schema_version": "automud.graph.v1",
  "window_start": 1800000000,
  "uid": "connection-17",
  "orig_h": "10.0.0.11", "resp_h": "10.0.0.13",
  "orig_p": 45678, "resp_p": 80, "proto": "tcp",
  "flow_start": 1800000002.0,
  "orig_ip_bytes": 840, "resp_ip_bytes": 640,
  "orig_pkts": 6, "resp_pkts": 5,
  "observed_duration": 0.4,
  "established": true, "failed": false, "new_flow": true
}
```

There is one row per connection UID per observed minute. Counters are IP-level
bytes/packets **inside that minute**, not cumulative totals. `observed_duration` is
time from connection start to the latest observed packet through that cutoff; it
does not use the eventual future flow duration. `new_flow` is true only in the start
minute. Optional `orig_mac`/`resp_mac` support identity resolution.

The Zeek policy uses packet observations for exact interval attribution, with
handshake evidence recorded causally. A TCP attempt is failed if rejected or still
not established after three observed seconds at the cutoff. Resetting an already
established connection is not failed establishment. Unknown outcomes are masked.
Counters are for Zeek-accepted IP packets; pure ARP attacks are outside v1.

Ordinary `conn.log` is useful for diagnostics and enrichment but is **not** accepted
as equivalent interval telemetry. Its totals cannot tell how a long flow's bytes
were distributed in time. Neither the profiling engine's existing ten-field
summary nor traffic-generator intent logs contain all required observed features.

## Ordered node features

The first 18 values are traffic statistics. All counters include both directions
relative to the device, including when it is the connection responder.

| Index | Name | Definition before transformation |
|---:|---|---|
| 0–1 | `tx_ip_bytes`, `rx_ip_bytes` | Sum IP bytes sent/received |
| 2–3 | `tx_packets`, `rx_packets` | Sum packets sent/received |
| 4 | `active_flows` | Distinct observed connection intervals involving device |
| 5–6 | `initiated_flows`, `inbound_flows` | Newly started flows originated/received this minute |
| 7 | `unique_destinations` | Distinct responder IPs in device-originated active flows |
| 8 | `new_destination_fraction` | Fraction of originated active flows whose responder IP was absent from all prior observed windows |
| 9 | `unique_destination_ports` | Distinct `(TCP/UDP, responder port)` pairs on originated flows |
| 10 | `destination_port_entropy` | Shannon entropy in bits over those pairs, weighted by active flow count |
| 11–13 | `tcp_fraction`, `udp_fraction`, `icmp_fraction` | Fractions of all active flows involving the device; unsupported transports can leave their sum below one |
| 14 | `tcp_failed_fraction` | Failed / known-outcome outgoing active TCP flows |
| 15–16 | `mean_observed_flow_duration`, `median_observed_flow_duration` | Observed durations through cutoff, seconds |
| 17 | `log_tx_rx_ratio` | `log1p(tx_ip_bytes) - log1p(rx_ip_bytes)` |

Indices 18–21 are local/external directional bytes; 22–26 are external/service
fractions; 27 is bytes per initiated flow; 28–31 describe flow gaps and 10-second
bursts; 32–37 describe preceding 5/15-minute means, log changes, and gap variability.
See LOCAL_WSL.md for definitions and masks. The ordered JSON contract names every
column and every `log1p` transform. Scale all 38 measured statistics using training
means/standard deviations, per functional type; constant features use unit scale.
Types with fewer than 100 active training observations use the global normal
training scaler. Unknown types use the same fallback. Fit statistics only on
available, active, valid Stage-1 training observations.

The remaining encoder columns are:

- 38–39: sine/cosine of UTC seconds through the day.
- 40: device activity flag.
- 41–52: one-hot `hub, speaker, light, plug, camera, doorbell, motion_sensor,
  printer, environmental_sensor, scale, unknown, external_service`.
- 53–60: external service category one-hot; all zeros for device nodes.
- 61–98: validity masks for the 38 measured features.

Thus `x` has **99 columns**; Head A reconstructs the first **38**, with invalid
targets masked out. Missing/undefined normalized values are zero with mask=false.
Observed silence has valid zero counters but undefined duration/protocol fractions.
Sensor/device unavailability has all traffic masks false. Inactive/unavailable
devices receive status output, not a falsely confident Head C probability.

History updates only after completing a window. Head C zeroes destination-history and rolling-context columns and
their masks before a separate shared-encoder pass. Its output therefore does not
depend on whether the device had prior destination history.

## Graph semantics and PyG interface

One graph represents one simultaneous household/network window. Preserve all
inventoried devices, including observed idle devices. External peers affect device
features and observed service-category context nodes. These context nodes are
not treated as IoT devices for reconstruction or classification. Never merge unrelated public captures
into a fictitious household. Do not inject intended topology edges.

Each directed observed pair stores source/target node indices, exchanged bytes,
packets, flow count, protocol histogram, transport-port set, historical novelty,
and whether any exchange was confirmed. TCP attempts also supply relational
evidence, but the metadata distinguishes them from confirmed communication.

`to_pyg` returns `x[N,99]`, `target[N,38]`, `feature_mask[N,38]`,
`edge_index[2,E]`, `positive_pairs[2,P]`, `y[N]`, `active[N]`, and `available[N]`.
Message passing uses the deduplicated bidirectional adjacency. Positive scoring
pairs retain direction. Labels use -1 for unknown. IDs and provenance stay in the
raw graph record alongside tensors.

Head B uses embeddings, not edge byte counts or novelty flags: these would make a
trivial real-edge/zero-filled-negative shortcut. For every query, its relationship
is removed in **both** directions before embedding. The same procedure is used in
training, calibration, and inference. Negatives never cross graph boundaries.

## Labels and output

```json
{"device_id":"camera-1","start":1800000000,"end":1800001200,
 "label":1,"role":"actor","attack_family":"port_scan",
 "onset":"from_start","evidence":"scenario-run-17"}
```

Only a verified malicious actor gets the Head C actor `label` 1.
A/B use separate `behavior_label` and `relationship_label` annotations, including
behavior intervals for affected victims. See LOCAL_WSL.md for exact semantics. Being a victim, reflector, or merely
present in an attack capture does not prove compromise. Unknown actors/background
devices remain unlabeled unless there is evidence for a normal label. Positive
intervals require family/onset/provenance. Mixed boundary windows are excluded from
the classifier loss. Fully controlled clean manifests can provide label 0.

Predictions contain run/window/model/schema identifiers, per-device status,
reconstruction error, maximum initiated link anomaly (robust revision) (`1 - minimum expectedness`),
Head C probability, three individual threshold flags, and per-edge expectedness.
No initiated relationship means unavailable robust link evidence (`null`), not zero risk. The
profiling deviation score bypasses this model and is fused downstream.

## Limitations of the current contract

TCP/UDP counts capture activity, not payload semantics. No ARP feature, DNS meaning,
TLS fingerprint, exploit success, persistent temporal hidden state, or proof of
infection is implied. The packet-level Zeek handler favors correct attribution at
household scale; measure sensor drops/CPU before scaling or high-rate experiments.
