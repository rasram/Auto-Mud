# Dashboard UI refresh and anomaly audit

Recorded 20 October 2026, following commit `754d7b4`. These changes are deployed
on Saturn and are available in the attached review checkout.

## Interface

- Larger, higher-contrast text, consistent spacing and a system font that is
  available on the workstation; no remote font requests.
- Monitoring-mode and observation-status banners appear only on Overview,
  as requested by Jayan. Connection errors remain visible across views.
- Connection summaries wrap whole fields and give the expandable details a
  separate full-width row. Health/settings values wrap instead of truncating;
  drawer grids adapt to available width. Ordinary words stay intact, while
  technical identifiers/hashes can wrap when needed. All seven views plus device
  and observation drawers were checked at 1189, 900, 390 and 320 pixel viewports.
  Expanded connection details were checked at desktop and both phone widths.
  Evidence: `text-wrapping-checks.json`, `text-wrapping-network.jpg` and
  `text-wrapping-mobile.jpg`; no document overflow in the final checks.
- A locally served subset of 31 official Lucide SVG icons, including device
  types, monitoring, findings, network actions and navigation. The upstream
  revision and ISC/Feather notices are retained in `dashboard/frontend/vendor/`.
- Operator views use **GNN**, Behavior and Connections. Model releases,
  fingerprints, policy versions, source IDs and deployment identifiers are in
  About's technical disclosure. Numeric logits, cutoffs and binding details are
  available in an optional device disclosure.
- Device cards distinguish Flag raised, No flag and Unavailable. No GNN flags
  does not imply that a device satisfies its network policy. Flags are not
  presented as confirmed compromise or probabilities.
- Repeated policy connections are grouped by device, route, observation and
  severity. Original evidence remains intact. In the audited minute, the old
  count of 72 finding records becomes 12 policy-violation groups.
- An About view explains the independent GNN, MUD and response checks, the lab
  traffic, warm-up requirements and interface credits.

## Validation result

**The recorded flags are computationally consistent. Their true/false-positive
accuracy is not established by this audit.** No attack-labelled representative
capture was supplied, and no new labels were invented.

The final immutable audit covers 53 retained windows from
`saturn-20261020T113959Z`. Its replay window is **18:01–18:02 IST** on 20 October.

| Check | Observed result |
|---|---|
| Frozen score/threshold flags across retained windows | No mismatches; strict `score > threshold` rule checked |
| Same stored graph replay through deployed frozen GNN | All 24 scores reproduced exactly, maximum absolute error 0 |
| Re-evaluation of recorded MUD results | No mismatches |
| Independent exact-rule lookup for the planned local TCP routes | No mismatches |
| Latest TCP traffic versus existing probe plan | All planned; no unplanned TCP flow IDs |
| Latest allowed / denied connections | 36 allowed, 72 denied |
| Latest denied routes | 12 distinct routes, all deliberate TCP port-18080 probes |
| Latest GNN flags | 7 behavioral flags, 0 connection flags |
| Latest history state | 15 prior windows, 3000 observed seconds, `fully_warmed=false` |
| Model accuracy / confirmed attacks | Not validated; `accuracy_validated=false` in the report |

The seven behavioral flags were August Doorbell, Belkin WeMo Motion Sensor,
Belkin WeMo Switch, LIFX Bulb, Philips Hue, Samsung Camera and Samsung SmartThings.
These are **unconfirmed signals on controlled lab traffic**. They may reflect a
difference from the model's learned normal baseline; this audit does not isolate
the cause or prove that they are true or false positives. Warm-up was still
incomplete. A policy denial does not require a GNN flag, because the two checks
answer different questions.

The policy violations match the intentionally disallowed ring probes. They are
correct rule outcomes for those connections and are not evidence of compromise.
The latest 36 allowed connections also match the six existing local permission
rules. Startup ICMP/IPv6 records remain in the audit; they are not silently
relabelled as application probe traffic.

Replaying the stored graph verifies score consistency, not independent correctness
of feature extraction or attack ground truth. Representative labelled validation
remains separate and requires explicit permission for any proposed dataset change.

## Evidence and checks

On Saturn:

`/mnt/data/automud/live/acceptance/ui-validation-20261020/`

- `validated-observation-audit/audit.json`: final report with exact per-device
  scores, thresholds, flags, window identities and limitations.
- The same directory contains immutable copies of events, runtime metadata and
  model state used for the read-only audit, bound by SHA-256 in the report.
- `tests.xml`: **105 passed**, no failures or skips; existing PyTorch warning.
- `focused-tests.xml`: **28 passed**.
- Frontend checks: **8 passed**, covering filtering, unavailable evidence,
  warm-up, grouping and bundled icons.
- Browser verification: all seven views on desktop and 390 x 844 mobile,
  including About, device disclosures and grouped findings. No horizontal
  document overflow or browser errors. Release names remain hidden outside About.
- `ui-browser-verification.json`, `ui-refresh-desktop.jpg` and
  `ui-refresh-mobile.jpg`: browser checks and deployed overview screenshots.
- `ui-source.sha256`: source manifest shared by the review checkout and Saturn.

Dataset, model, threshold, profile, normalization, feature contract, inventory and
MUD policy remain unchanged. The audit reads copies and scores the same retained
graph; it does not train, collect new samples, submit windows to the live API or
write to live model state. Administrative controls remain locked and the live
override ledger hash is unchanged. Observation remains `engineering / observe`.

To audit a later retained state, select a new output directory:

```bash
cd /opt/automud/Auto-Mud
.venv-ml/bin/python -m integration.live.audit_observation \
  --output /mnt/data/automud/live/acceptance/UNIQUE-AUDIT-ID
```

The audit exits nonzero on computational mismatches. A passed audit still does
not establish model accuracy; consult `accuracy_validated` and the limitations.
