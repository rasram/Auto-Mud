# AutoMUD operations dashboard

**Owner:** Rashwanth Ram

The dashboard is a dependency-free Python and browser application backed by the
live pipeline's append-only events. It provides:

- current service, sensor, join, model and policy health;
- an interactive recent-relationship map with independent MUD outcomes;
- per-device Head A/Head B raw-logit history, frozen thresholds and explicit
  null, warm-up and unscored states;
- explainable security and operations findings;
- controller-confirmed action lifecycle and expiry;
- complete per-observation stage timing and evidence drill-down; and
- token-guarded, expiring human suppression controls with an audit record.

The UI never presents logits as probabilities. Engineering observations and
observe-mode decisions are clearly labelled and cannot install automatic rules.

The systemd service binds to `127.0.0.1:8090`. Use the documented SSH tunnel for
operator access. To enable suppression controls, copy
`configs/live/dashboard.env.example` to `/etc/automud/dashboard.env`, set a long
random token, make the file root-readable only, and restart
`automud-dashboard`. The runtime override record is stored outside Git at
`/mnt/data/automud/live/control/human-overrides.json`.
