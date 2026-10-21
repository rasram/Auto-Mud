# Shared evaluation tools

These tools recount existing labelled records. They use the Python standard
library, take explicit file paths, and do not submit traffic, change services,
train models, fit cutoffs or modify datasets. Run commands from the repository root.

```bash
python scripts/integrated_evaluation/report.py --help
python scripts/integrated_evaluation/report.py \
  --detection /path/to/detection-records.json \
  --mud /path/to/mud-records.json \
  --response /path/to/response-records.json \
  --output /path/to/new-recount.json
python -m unittest discover -s scripts/integrated_evaluation -p "test_*.py"
```

Any combination of the three inputs is accepted. Each file is a JSON array or
JSONL file. The output records input hashes and counts; an existing output file
is never overwritten. Files are operator-supplied evidence, not bundled datasets.

| Input | Required fields | Meaning |
| --- | --- | --- |
| Detection | `head` (`A`/`B`), `label` (`0`/`1`), `flag` (`true`/`false`/`null`); optional `eligible` | One observation per head/device/window. Ineligible rows are excluded. Null predictions remain unscored. |
| MUD | `expected`, `actual` | `allowed`/`denied` are binary outcomes. Other expected values are unsupported; other actual values are unavailable. Denied is the positive class. |
| Response | `required` (boolean), `proposed` (boolean/null); optional `eligible` | Presence of a required response proposal at the declared observation level. Null is unavailable. |

Detector precision uses scored positives. Population recall and F1 retain unscored
positive labels as misses; coverage and unscored negatives remain explicit. MUD
binary coverage includes unsupported records in the denominator. Response counts
describe proposal presence, not action installation, successful blocking or attack
detection accuracy. Keep the record unit and independent truth definition with
each study; do not pool unrelated recordings, flow rows and device-windows.

For the running pipeline, use the shared native tools already in
[`integration/live`](../../integration/live/README.md):

- `integration.live.verify_observation` checks retained joined engineering
  observations and frozen flags against the configured running deployment.
- `integration.live.audit_observation` copies retained evidence, reproduces a
  stored graph's scores and audits local MUD decisions. It does not establish
  anomaly accuracy without independent ground truth.
- `integration.live.acceptance` collects existing runtime, test and action
  receipts into an evidence-linked report; unperformed scenarios remain blocked.

Those native commands require the deployment environment and configured services;
consult their `--help` and the linked guide. The recount above needs only Python.
Software regression checks can be run independently in the configured Linux
environment (the live finalizer uses Linux file locking):

```bash
python -m pytest integration/tests ml/tests network/tests profiling/features profiling/profile_engine
node --test dashboard/frontend/app.test.cjs
```

The [presentation results](../../docs/presentation/AutoMUD_Presentation_Results.md)
summarize the completed study and its limits. Dated workstation preparation,
Saturn replay/actuation, personal progress monitoring and document-generation
scripts are private. Their raw research inputs are not distributed here. A new
labelled live packet-to-action study still requires its own declared protocol and
truth; these recount/acceptance tools do not constitute that study.
