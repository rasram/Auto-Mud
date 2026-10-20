# dashboard/backend/

**Owner:** Rashwanth Ram

The active standard-library HTTP backend is `integration/live/dashboard.py`.
It aggregates the JSONL event stream, finalizer state and loopback controller
API into cached dashboard views. Keeping it with the integration contracts
prevents a second service from reinterpreting GNN or MUD evidence.
