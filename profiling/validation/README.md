# profiling/validation/

**Owner:** Sarveshwar Balu

Compares automatically generated profiles with the MUDgee-generated ground-truth MUD profiles for the UNSW devices.

Metric: **Profile Fidelity**, the % of endpoints in the ground-truth MUD profiles that also appear in the generated profile.

Methodology: Stage 0, step 4. Feeds **Objective 1**.

`scorer.py` normalizes RFC 8520 ACEs and reports Profile Fidelity (reference
endpoint recall), endpoint precision/F1, service F1, protocol F1, exact ACE F1,
and a weighted structural similarity score.

The MUDgee files in `data/raw/mudgee_profiles/` are held-out evaluation data.
They are never imported by the generator. Only devices with an available PCAP
and a matching reference profile are scored; absent PCAPs are not failures or
zero-valued rows. Reports are written as JSON and CSV under `results/` by:

    .\.venv\Scripts\python.exe -m profiling.run_unsw_profiling
