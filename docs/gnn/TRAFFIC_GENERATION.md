# Existing traffic generation versus training-quality collection

The existing scripts remain useful for inspecting calibrated events and diagnostic
replay. They must not be treated as equivalent to captured live training traffic.
The new collection path is separate so older profiling/replay workflows retain
their interfaces. The legacy launcher now defaults to 1x and prints this distinction.

## Findings from the actual repository

| Existing behavior | Why it matters for GNN data | Implemented collection path |
|---|---|---|
| `run_full_topology.py` defaulted to 3600x replay | Zeek sees wall-clock compression; seven virtual days are not seven days of sixty-second windows | Real Mininet runner stays 1x; the separate virtual packet renderer supplies full logical timestamps and synthetic provenance |
| `send_flow_via_scapy` sends repeated TCP packets without a connection lifecycle | "Normal" learns failed/rejected handshakes | Socket clients and responders complete TCP exchanges |
| Response packet/byte counts and duration are ignored | Inbound volume, ratio, and duration features do not match intent | Bidirectional bounded transfers paced over event duration |
| Each replay begins at its own first event | Device-to-device timing and graph context are shifted | One UTC start and common monotonic schedule |
| Cloud and household-edge streams use individual gap sleeps; edge generator emits one edge stream at a time | Combined stream timing can be wrong | One deterministic sorted household plan |
| Calibration feeds packet inter-arrival statistics into flow scheduling | Wrong event rate and burstiness | Derive gaps from new-connection start timestamps |
| Time units are assumed without conversion; CSV readme and observed values disagree | Orders-of-magnitude timing errors | Re-extract canonical telemetry in seconds |
| Protocol, application label, and port are sampled independently | Inconsistent combinations, e.g. ICMP with a DNS service port | Joint transport/port service samples |
| Real public/placeholder destinations need ad hoc replay normalization | Success and destination diversity become uncontrolled | Sixteen isolated cloud IP aliases and explicit local responders |
| `tcpdump -i any` records several network interfaces | Duplicate observations can inflate counts; some formats lose Ethernet identity | Dedicated OVS mirror interface with full snap length |
| No automatic actor/time labels or held-out scenario seeds | Cannot reliably train/test Head C | Scenario matrix, ground-truth labels, matched controls, whole-session splits |
| No collection completeness gate | Partial runs may appear normal | Capture health, agent exit status, timing lag, seed and file hashes |

The checked-in sample `conn.log` contained 2,693 flows over about 108 seconds:
1,710 `REJ`, 622 `S0`, 156 `SHR`, 191 `OTH`, 10 `RSTO`, and only 4 `SF` records.
That is useful evidence that capture works, but is not a representative successful
household baseline. It should not train the production encoder.

## What is already reusable

- The finalized twelve device names and static IP assignments.
- The six authored household automation relationships, their ports and rates.
- The UNSW normal PCAPs and existing calibration insights.
- The profiling engine and its independent policy/deviation interface.
- Existing generated JSON logs for debugging and comparisons.

The six household relationships are simulation assumptions, not measured UNSW
device-to-device ground truth. Keep that distinction in experiments and reports.

## What changes when using the new path

Generate v1 profiles with `ml calibrate-traffic`, plans with `ml plan-normal` /
`ml plan-attacks`, and execute them with `network.testbed.collect`. Do not feed the
new plan format to the legacy `device_agent.py`: they intentionally have different
contracts. Do not label legacy generated events as observed Zeek flow records.

The new socket service is a small controlled request/response protocol. TCP/UDP
transport, volume, timing, and service-port features are meaningful; HTTP/TLS/DNS
application semantics are not reproduced simply by choosing those port numbers.
This is why application-protocol fingerprints are absent from the v1 feature set.

The collection transport currently supports TCP and UDP. Real ICMP observations
remain supported by the feature extractor, but the normal generator does not
reproduce an ICMP distribution. Pure ARP attacks remain unsupported. Record these
coverage limits rather than treating missing protocol traffic as calibration success.

Normal profile sampling retains bounded marginal volume/duration distributions and
joint transport/port distributions, not every original dependency. Individual events
are capped at 64 KiB each way and ten seconds, with inter-flow gaps capped at an hour
in calibration. These defaults keep collection reproducible at household scale but
must be checked for distortion, particularly for cameras and long-lived streams.
Change the generator and retrain if a pilot does not cover the desired operating
regime. The GNN sensor itself supports long-running flows and does not share these
generator bounds.

## Pilot acceptance and tuning

Require working responses and established TCP, zero unexpected failures/drops, and
no agent deadline misses. Verify that every expected household relationship occurs
over a sufficiently long pilot; a two-per-hour edge can legitimately be absent
from a short test. Check quiet devices separately from busy cameras.

Compare measured per-device minute volume, flow count, service mix, duration and
active hours with calibration inputs. Large differences need explanation or
generator adjustments. Do not fix them by rescaling timestamps after capture or by
pretending packet gaps are flow gaps. Increase pilot duration before concluding
that a low-rate edge or rare event is absent.

If collection overloads, reduce concurrent planned volume or provision a stronger
sensor; preserve 1x time. For throughput experiments use separately identified
datasets rather than mixing drop-heavy captures into the clean baseline.

## Scenario interpretation

- Port scan: bounded TCP connection attempts across unserved lab ports.
- Lateral connections: connections to devices beyond the normal authored edges.
- Exfiltration: sustained outbound transfers to a controlled local cloud endpoint.
- Beaconing: repeated small transfers to a controlled endpoint.

No exploit success or actual command execution is assumed. They are network-behavior
tests. In particular, normal bulk uploads and polling can resemble the last two;
the matched controls intentionally expose false positives. Device-specific public
malware examples can broaden Head C only when actors, timing and feature semantics
are reconciled correctly.
