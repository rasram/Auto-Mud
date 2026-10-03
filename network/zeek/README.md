# network/zeek/

**Owner:** Anand Mahadev

Zeek sensor setup. All OVS traffic is mirrored to Zeek, which writes structured flow logs roughly every 60 seconds. The same Zeek flow format is used for the offline UNSW PCAP replay in Stage 0, so live features stay consistent with training features.

Methodology: Stage 0, step 2 (offline replay) and Stage 1, step 8 (live sensor).

## Canonical GNN telemetry

Load `automud-window.zeek` to emit `automud-window.log` in JSON. It accounts for
IP packets in UTC minute windows and preserves long-flow timing. Run the same
policy on public PCAPs using `python -m ml extract`. Ordinary conn.log totals are
not interchangeable with interval telemetry. See [the schema](../../docs/gnn/SCHEMA.md)
and [collection commands](../../docs/gnn/COLLECTION.md).
