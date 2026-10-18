# Original E1+Q results and deployment limits

The current repository release is original E1, seed 42, selected epoch 5,
`supervised-E1Q-20261018`, with its already-frozen lower-quartile cutoffs.
These are previously completed consumed-benchmark results. The release upgrade
does not retrain, refit cutoffs or change the dataset.

| Metric | Earlier A | Earlier B | Later A | Later B |
|---|---:|---:|---:|---:|
| Precision | 99.647371% | 100.000000% | 99.668981% | 100.000000% |
| Population recall | 99.743296% | 100.000000% | 99.376576% | 100.000000% |
| Population F1 | 99.695311% | 100.000000% | 99.522563% | 100.000000% |
| False-positive rate | 0.090136% | 0.000000% | 0.084139% | 0.000000% |
| Coverage | 100.000000% | 98.989193% | 100.000000% | 98.754051% |
| True positives | 21,759 | 2,100 | 21,679 | 2,100 |
| False positives | 77 | 0 | 72 | 0 |
| False negatives | 56 | 0 | 136 | 0 |

Earlier primary population: 107,241 active observations; later: 107,388.
Each has 21,815 A positives and 2,100 B positives. B support is respectively
106,157 and 106,050. Population recall retains unscored positives in its
denominator. Detailed primary metrics and every saved gate check are in
[`results.json`](../../models/gnn/results.json). E1+Q passes all original gates
on both corpora.

| Mean A/B population F1 | Earlier | Later |
|---|---:|---:|
| Retained C | 99.8197% | 99.5107% |
| Original E1+Q | 99.8477% | 99.7613% |
| T reference | 99.8948% | 99.8971% |

Later A false alarms decrease from C's 189 to 72, while misses increase from
124 to 136. Later B improves from 2 false alarms / 9 misses to 0 / 0 on scored
opportunities. This aggregate gain has an A recall tradeoff. The earlier paired
improvement interval includes zero; later E1 seeds transfer less well. T remains
stronger. No replicated learned-message superiority is established.

Both corpora are consumed, from one authored household with known devices and
synthetic attack overlays. These results do not establish accuracy on unseen
households, physical devices or fresh live traffic.

E1 directly scores behavioral/affected devices with A and initiating relationships
with B, using directed learned messages and own-device causal GRU history.
Strict raw-logit cutoffs are A `0.7624336779117584`, B `4.921021908521652`.
These are not probabilities or MUD permissions. Head C remains untrained.

[Deployment validation](DEPLOYMENT_VALIDATION.json) records installation parity,
unchanged-pipeline regression, replay of an existing engineering packet capture
and CPU capacity. These checks do not activate a native teammate host, establish
live accuracy or qualify Ryu enforcement. Original C's validation is preserved
separately in [DEPLOYMENT_VALIDATION_C_20261016.json](DEPLOYMENT_VALIDATION_C_20261016.json).
