# Processed UNSW profiling data

`behavioral_profiles/` contains 27 frozen Zeek window baselines used by
`profiling/profile_engine/score_window.py`. They are observation and deviation
profiles, not MUD ACL documents. `reports/zeek_reference_fact_recall.json`
scores their observed domains, ports, and networks against the MUDgee
references in `data/references/mudgee_muds/`.

`features/`, `zeek/`, and `scores/` hold regenerable intermediate outputs when
the full source captures and Zeek pipeline are available.
