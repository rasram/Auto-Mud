# profiling/validation/

**Owner:** Sarveshwar Balu

`compare_mud.py` compares observed domains, transport ports, and networks in
the frozen Zeek behavioral profiles with the MUDgee reference ACLs. The
references are held under `data/references/mudgee_muds/` and are read only
after profiles have been generated.

Run the full UNSW pipeline with:

```sh
bash scripts/UNSW-IoTraffic/build_all_profiles.sh
```

The report is written to
`data/processed/unsw/reports/zeek_reference_fact_recall.json`.
`injected_anomaly_check.py` exercises four synthetic attack-shaped windows
against a frozen profile. It is a sanity check, not a measurement of detection
performance on real attacks.
