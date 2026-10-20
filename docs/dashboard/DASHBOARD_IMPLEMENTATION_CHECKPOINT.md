# AutoMUD dashboard implementation checkpoint

Updated 20 October 2026. This file is the compact, repository-scoped handoff
between dashboard implementation parts. It does not replace pipeline acceptance
evidence or owner approval.

## Completed: Part 1 — backend aggregation and guarded APIs

- `integration/live/dashboard.py` now builds one cached operational snapshot
  from the append-only event log, finalizer status and controller API.
- It exposes overview, device, topology, alert, action, trace-summary and
  trace-detail views while retaining the original status/events endpoints.
- Head A/B values remain raw logits with flags, thresholds and null/unscored
  reasons. MUD permissions remain a separate evidence branch.
- Deterministic plain-English explanations describe recorded evidence without
  claiming compromise probability or predictive certainty.
- Human suppression create/remove endpoints require
  `AUTOMUD_DASHBOARD_ADMIN_TOKEN`, validate actor/reason/expiry/device scope and
  persist an atomic mode-0600 audit record. With no token, controls stay locked.
- Static and API responses now include CSP, frame, MIME, referrer and browser
  permission security headers.

Validation on Saturn:

- focused integration suite: 15 passed;
- full regression: 92 passed in 16.54 seconds;
- one existing PyTorch `torch.jit.script` future-deprecation warning.

## Completed: Part 2 — application shell and visual system

- Replaced the trace-only page with a responsive security-console shell.
- Added desktop/sidebar and mobile/drawer navigation for overview, network,
  devices, alerts, enforcement and pipeline views.
- Added a prominent safety/degraded/enforcement banner and an overview with
  protected inventory, findings, active response, observation health, pipeline
  stages, attention queue, recent activity and active policy/model identity.
- Added explicit loading, empty and error states, keyboard focus styles,
  reduced-motion support, a 10-second request timeout and bounded 30-second
  refresh.

Validation on Saturn:

- all HTML, CSS and JavaScript assets served successfully;
- desktop browser rendered real live data with no console warnings/errors;
- 390 x 844 responsive browser check passed with usable navigation and layout.

## Completed: Part 3 — topology and device evidence

- Added an interactive SVG relationship map built from recent MUD exchanges.
- Relationships retain allowed, denied and unknown authorization states and can
  be filtered and inspected for direction, count, bytes and protocol.
- Added searchable/filterable inventory cards with active binding, risk state,
  MUD counts, score history and model warm-up state.
- Added device evidence drawers with stable identity, IP/MAC/switch binding,
  profile support, Head A/B raw logits, frozen thresholds, history and explicit
  null/unscored reasons. The interface states that logits are not probabilities.

Validation on Saturn:

- rendered 12 devices and 36 aggregated recent relationships from live records;
- connection selection and all/permission filtering worked;
- device search for `camera` returned the three camera entries;
- device evidence drawer open/close and empty-history state worked;
- browser console contained no warnings or errors.

## Completed: Part 4 — alerts, actions, traces and guarded controls

- Added security and operations alert filtering with deterministic evidence
  explanations and direct trace inspection.
- Added the controller action lifecycle table, including target scope, action,
  state, installation time and expiry/removal time. Observation-mode runs keep
  the table explicitly empty instead of implying enforcement.
- Added active suppression display/create/remove flows. Controls are disabled
  when `AUTOMUD_DASHBOARD_ADMIN_TOKEN` is unset; the token stays in browser
  memory only and API mutations remain authenticated and audited.
- Added end-to-end trace filtering, aggregate stage-latency cards and trace
  detail drawers containing stage timestamps, raw trace/run identity, health,
  versions, proposals, withheld reasons and controller outcome.
- Moved the override ledger into the configured data disk and tightened its
  directory/file permissions. The systemd service now reads an optional
  root-owned environment file and receives write access only to that control
  directory.

Validation on Saturn:

- `automud-dashboard` and `automud-finalizer` were active after deployment;
- full regression: 92 passed in 16.11 seconds;
- alerts, enforcement and pipeline pages rendered live records with no browser
  console warnings/errors;
- selecting `Partial / unavailable` returned four pipeline rows and selecting
  `Operations` returned four alert rows;
- a trace drawer displayed all recorded stages, identifiers, model/policy
  versions, measured latency and the no-action controller outcome;
- suppression controls stayed locked and no live override was mutated.

## Next: Part 5 — final acceptance and handoff evidence

Run the final API, security-header, service, observe-mode, desktop/mobile and
cross-page interaction checks. Record exact evidence in the project docs,
perform the final secret/diff review, and commit and push the acceptance record.
