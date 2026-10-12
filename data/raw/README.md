# data/raw/

**Owner:** Shared

Original, unmodified datasets. Never edit these in place.

| Subdirectory | Dataset | Purpose |
|---|---|---|
| `unsw_iot/` | UNSW IoT dataset: real `.pcap` traffic from 28 IoT devices | Profile engine training and ground truth |

The GNN-only research dataset directories were moved to the ignored private
archive. They are not needed for frozen inference or live integration. The
selected small models and reference test are in `models/gnn/` and `fixtures/gnn/`.

The MUDgee reference set is committed once at `data/references/mudgee_muds/` and should
not be copied into `raw/`.
