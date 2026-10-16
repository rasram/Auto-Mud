# Supervised C/E2 results and deployment limits

The active release is **original C, seed 42, selected epoch 13**, of the C/E2
family. E2 independently reproduced C's binary benchmark decisions; this
package uses C's own weights and frozen cutoffs. It replaces self-supervised
New 2. These are previously completed benchmark results, not new live accuracy
measurements from the deployment checks.

| Metric | Earlier A | Earlier B | Later A | Later B |
|---|---:|---:|---:|---:|
| Precision | 99.6199% | 100% | 99.1362% | 99.9044% |
| Population recall | 99.7066% | 99.9524% | 99.4316% | 99.5714% |
| Population F1 | 99.6632% | 99.9762% | 99.2837% | 99.7377% |
| False-positive rate | 0.097160% | 0% | 0.220864% | 0.001924% |
| Coverage | 100% | 98.9892% | 100% | 98.7541% |
| True positives | 21,751 | 2,099 | 21,691 | 2,091 |
| False positives | 83 | 0 | 189 | 2 |
| False negatives | 64 | 1 | 124 | 9 |

Earlier primary population: 107,241 active device observations; later: 107,388.
Each has 21,815 A positives and 2,100 B positives. B support is respectively
106,157 and 106,050; no initiated relationship means unscored. Population
recall retains all positives in the denominator rather than silently dropping
unscored ones. Numeric details/check outcomes are in
[`models/gnn/results.json`](../../models/gnn/results.json).

C passes the earlier saved qualification. On the later corpus it **fails three
supported B subgroup checks**: Philips Hue recall 98.8571%, and one lateral
native-period group's recall 97.1429% / F1 98.5507%. Aggregate high scores do
not erase these failures. The temporal-only comparator T was stronger in the
completed study; there is no demonstrated learned-message advantage for C.

Both corpora are consumed evaluations of one authored household with known
devices and synthetic attack overlays. They do not establish generalization
to unseen households, physical devices or fresh live traffic. Earlier New 2
results used a different population/protocol and are not a controlled
before/after improvement estimate.

C is supervised direct detection: an own-device encoder plus causal GRU
history with two heads, using graph-derived descriptors but no learned
neighbor messages. A covers behavioral/affected devices, including victims;
B concerns initiating relationships. Neither is a compromise probability or
MUD permission. Head C remains untrained.

Frozen strict raw-logit cutoffs are A `1.1537269353866577` and
B `-0.2367836833000183`. The release includes matching clean profiles,
normalizer, feature contract and cutoffs; it does not fit them during operation.
The consumed fixture reproduces C's scores and decisions. Engineering
qualification in [DEPLOYMENT_VALIDATION.json](DEPLOYMENT_VALIDATION.json)
establishes software/capture/API compatibility and capacity, not predictive
qualification or Ryu enforcement. Follow the handoff's observation-mode and
full-pipeline acceptance steps before enabling automated responses.
